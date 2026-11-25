package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

const workloadRuntimeDirectory = "/run/ocean-workload-network"

var taskIdentityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validContainerTask(task workload.Task) bool {
	for _, value := range []string{task.ID, task.Generation, task.Revision, task.TenantID, task.SubscriptionID} {
		if !taskIdentityPattern.MatchString(value) {
			return false
		}
	}
	return (task.VolumeID == "" || storage.ValidID(task.VolumeID)) && task.Address.Is4() && task.Port >= 1 && task.Port <= 65535 &&
		(task.State == workload.Running || task.State == workload.Stopped || task.State == workload.Removed)
}

func containerName(id workload.AssignmentID) string {
	hash := sha256.Sum256([]byte(id.TenantID + "/" + id.SubscriptionID + "/" + id.ID + "/" + id.Generation))
	return fmt.Sprintf("ocean-%x", hash[:16])
}

func (j *joinClient) containerTasks(ctx context.Context, networkOnly bool) ([]workload.Task, error) {
	path := "/container-tasks"
	if networkOnly {
		path = "/container-network"
	}
	var tasks []workload.Task
	for cursor := ""; ; {
		end := j.url() + path
		if cursor != "" {
			end += "?continuation=" + url.QueryEscape(cursor)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, end, nil)
		if err != nil {
			return nil, err
		}
		response, err := j.client.Do(request)
		if err != nil {
			return nil, err
		}
		var page workload.Page
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("workload tasks returned HTTP %d", response.StatusCode)
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&page)
		_ = response.Body.Close()
		if err != nil || len(page.Tasks) > 16 || page.Next != "" && (page.Next <= cursor || len(page.Tasks) == 0) || len(tasks) > 4096 {
			return nil, errors.New("invalid workload task page")
		}
		for _, task := range page.Tasks {
			if !validContainerTask(task) || networkOnly && task.Container != nil {
				return nil, errors.New("invalid workload task")
			}
		}
		tasks = append(tasks, page.Tasks...)
		if page.Next == "" {
			return tasks, nil
		}
		cursor = page.Next
	}
}

func (j *joinClient) reportContainer(ctx context.Context, report workload.Report) error {
	payload, _ := json.Marshal(report)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/container-tasks/status", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusConflict {
		return fmt.Errorf("workload report returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (j *joinClient) reconcileContainers(ctx context.Context, logger *slog.Logger) {
	// Pulling an image can block for a while. Other assigned groups keep
	// reconciling, with a bounded number of runtime calls in flight.
	ticker := time.NewTicker(650 * time.Millisecond)
	defer ticker.Stop()
	inFlight := make(map[string]bool)
	completed := make(chan string, 8)
	for {
		for waiting := true; waiting; {
			select {
			case name := <-completed:
				delete(inFlight, name)
			default:
				waiting = false
			}
		}
		read, cancel := context.WithTimeout(ctx, 3*time.Second)
		tasks, err := j.containerTasks(read, false)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("workload assignment reconciliation will retry", "error", err)
		}
		if err == nil && j.config.TelemetryBufferBytes > 0 {
			j.setTelemetryTargets(tasks)
		}
		for _, task := range tasks {
			name := containerName(task.AssignmentID)
			if inFlight[name] || len(inFlight) >= cap(completed) {
				continue
			}
			inFlight[name] = true
			go func() {
				defer func() { completed <- name }()
				work, cancel := context.WithTimeout(ctx, time.Minute)
				defer cancel()
				report, err := j.applyContainer(work, name, task)
				if report.State != "" {
					err = errors.Join(err, j.reportContainer(work, report))
				}
				if err != nil && ctx.Err() == nil {
					logger.Warn("workload reconciliation stage failed", "placement", task.ID, "error", err)
				}
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type containerProcess struct {
	Pid       int
	Running   bool
	StartedAt string
	ExitCode  int
}

func inspectContainer(ctx context.Context, name string, podman func(context.Context, ...string) *exec.Cmd) (containerProcess, bool, error) {
	present := podman(ctx, "container", "exists", name).Run()
	var missing *exec.ExitError
	if errors.As(present, &missing) && missing.ExitCode() == 1 {
		return containerProcess{}, false, nil
	}
	if present != nil {
		return containerProcess{}, false, errors.New("could not query the local container runtime")
	}
	data, err := podman(ctx, "inspect", "--type", "container", "--format", "{{json .State}}", name).Output()
	var status containerProcess
	if err != nil || json.Unmarshal(data, &status) != nil || status.Running && status.Pid < 2 {
		return containerProcess{}, false, errors.New("could not inspect the local container process")
	}
	return status, true, nil
}

func localPodman(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "/usr/bin/podman", args...)
}

func podmanAction(ctx context.Context, args ...string) error {
	command := localPodman(ctx, args...)
	if err := command.Run(); err != nil {
		// Podman and the container may include tenant data in diagnostics.
		return fmt.Errorf("podman %s failed: %w", args[0], err)
	}
	return nil
}

func networkReady(name string, pid int) bool {
	path := filepath.Join(workloadRuntimeDirectory, name+".ready")
	status, err := os.Stat(path)
	if err != nil || time.Since(status.ModTime()) > policyLease {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == strconv.Itoa(pid)
}

func (j *joinClient) applyContainer(ctx context.Context, name string, task workload.Task) (workload.Report, error) {
	report := workload.Report{AssignmentID: task.AssignmentID}
	status, present, err := inspectContainer(ctx, name, localPodman)
	if err != nil {
		return report, err
	}
	if task.State == workload.Removed {
		functionConfig := j.functionContainerConfig(name)
		if _, err := os.Stat(functionConfig); err == nil {
			if err := j.removeFunctionSidecars(ctx, name); err != nil {
				return report, err
			}
			_ = os.Remove(functionConfig)
		}
		if present {
			if err := podmanAction(ctx, "rm", "--force", "--ignore", "--time", "1", name); err != nil {
				return report, err
			}
		}
		if _, err := os.Stat(filepath.Join(workloadRuntimeDirectory, name+".network")); errors.Is(err, os.ErrNotExist) &&
			(task.VolumeID == "" || !writerMounted(task.VolumeID)) {
			report.State = workload.Removed
			_ = os.Remove(filepath.Join(j.config.StateDirectory, name+".restart"))
		}
		return report, nil
	}
	if task.Container == nil {
		return report, errors.New("workload configuration is missing")
	}
	if task.VolumeID != "" && task.State == workload.Running && !mountReady(task.VolumeID, task.Generation) {
		return report, nil
	}
	if task.Function != nil && task.State == workload.Running && task.Start {
		if err := prepareFunctionStorage(task); err != nil {
			report.State = workload.Failed
			return report, err
		}
		path := j.functionContainerConfig(name)
		saved, _ := os.ReadFile(path)
		configuration := task.Function.Configuration
		if j.config.TelemetryBufferBytes > 0 {
			configuration += ".otlp"
		}
		if string(saved) != configuration {
			if err := j.removeFunctionSidecars(ctx, name); err != nil {
				return report, err
			}
			if present {
				if err := podmanAction(ctx, "rm", "--force", "--ignore", "--time", "1", name); err != nil {
					return report, err
				}
				present = false
			}
			if err := replaceRuntimeFile(path, []byte(configuration)); err != nil {
				return report, err
			}
		}
	}
	if task.State == workload.Stopped {
		if task.Function != nil {
			if err := j.removeFunctionSidecars(ctx, name); err != nil {
				return report, err
			}
		}
		if present && status.Running {
			if err := podmanAction(ctx, "stop", "--time", "1", name); err != nil {
				return report, err
			}
		}
		report.State = workload.Stopped
	} else if !present && task.Start {
		if err := j.createContainer(ctx, name, task); err != nil {
			report.State = workload.Failed
			return report, err
		}
	} else if present && task.Restart {
		if task.Function != nil && !j.restartApplied(name, task, status) {
			if err := j.removeFunctionSidecars(ctx, name); err != nil {
				return report, err
			}
		}
		if err := j.restartContainer(ctx, name, task, status); err != nil {
			report.State = workload.Failed
			return report, err
		}
	} else if present && !status.Running && task.Start {
		if err := podmanAction(ctx, "start", name); err != nil {
			report.State = workload.Failed
			return report, err
		}
	}
	status, present, err = inspectContainer(ctx, name, localPodman)
	if err != nil {
		return report, err
	}
	if task.State == workload.Running {
		if present && status.Running {
			if task.Function == nil {
				if networkReady(name, status.Pid) {
					report.State = workload.Running
				}
			} else {
				if err := j.ensureFunctionSidecar(ctx, name, task); err != nil {
					return report, err
				}
				if networkReady(name, status.Pid) {
					if task.Function.Request != nil && time.Now().Before(task.Function.Request.ExpiresAt) {
						result, err := functionAdmin(ctx, name, *task.Function, *task.Function.Request)
						if err == nil && result.Status != http.StatusServiceUnavailable {
							report.State, report.Function = workload.Running, &result
						}
					} else if !task.Start {
						report.State = workload.Running
					} else if result, err := functionAdmin(ctx, name, *task.Function, functions.AdminRequest{}); err == nil && result.Status == http.StatusOK {
						report.State, report.FunctionReady = workload.Running, true
					} else if started, err := time.Parse(time.RFC3339Nano, status.StartedAt); err == nil && time.Since(started) > 45*time.Second {
						report.State = workload.Failed
					}
				}
			}
		} else if !task.Start {
			report.State = workload.Stopped
		}
	}
	if present {
		data, _ := exec.CommandContext(ctx, "/usr/bin/podman", "logs", "--tail", "100", name).CombinedOutput()
		secrets := task.Container.EnvironmentVariables
		if task.Function != nil {
			secrets = append(secrets, workload.Variable{SecureValue: &task.Function.MasterKey}, workload.Variable{SecureValue: &task.Function.StorageKey})
		}
		report.Logs = workload.RedactLogs(string(data), secrets)
	}
	return report, nil
}

func (j *joinClient) createContainer(ctx context.Context, name string, task workload.Task) error {
	c := task.Container
	cpu, memory, ok := c.Resources.Requests.Limits()
	if !ok {
		return errors.New("invalid workload limits in assignment")
	}
	policy := map[string]string{"Always": "always", "OnFailure": "on-failure", "Never": "no"}[task.RestartPolicy]
	if policy == "" {
		return errors.New("invalid workload restart policy in assignment")
	}
	file, err := os.CreateTemp(j.config.StateDirectory, ".workload-env-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	for _, variable := range c.EnvironmentVariables {
		if !variable.Valid() {
			return errors.Join(errors.New("invalid environment variable in workload assignment"), file.Close())
		}
		if _, err := fmt.Fprintf(file, "%s=%s\n", variable.Name, variable.Text()); err != nil {
			return errors.Join(err, file.Close())
		}
	}
	if task.Function != nil && j.config.TelemetryBufferBytes > 0 {
		if _, err := fmt.Fprintln(file, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4318/v1/traces\nOTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json"); err != nil {
			return errors.Join(err, file.Close())
		}
		memory -= 24
		cpu -= 40
	}
	if err := file.Close(); err != nil {
		return err
	}
	if task.Function != nil {
		memory -= 88
		cpu -= 200
		if memory < 128 || cpu < 100 {
			return errors.New("invalid Function host limits")
		}
	}
	size := strconv.FormatInt(memory, 10) + "m"
	args := []string{"run", "--detach", "--pull=missing", "--name", name, "--network=none", "--cpus", strconv.FormatFloat(float64(cpu)/1000, 'f', 3, 64),
		"--memory", size, "--memory-swap", size, "--restart", policy, "--pids-limit=128", "--security-opt=no-new-privileges",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=NET_BIND_SERVICE", "--log-driver=k8s-file", "--log-opt=max-size=256kb", "--env-file", file.Name()}
	if task.Function != nil {
		secrets, _ := functionPaths(task.VolumeID)
		args = append(args, "--mount", "type=bind,source="+secrets+",target=/azure-functions-host/Secrets")
	} else if task.VolumeID != "" {
		args = append(args, "--mount", "type=bind,source="+filepath.Join(workloadMountRoot, task.VolumeID)+",target=/data")
	}
	args = append(args, "--", c.Image)
	args = append(args, c.Command...)
	return podmanAction(ctx, args...)
}

func (j *joinClient) restartApplied(name string, task workload.Task, status containerProcess) bool {
	path := filepath.Join(j.config.StateDirectory, name+".restart")
	saved, err := os.ReadFile(path)
	revision, prior, _ := strings.Cut(string(saved), "\n")
	return err == nil && revision == task.Revision && status.Running && status.StartedAt != prior
}

func (j *joinClient) restartContainer(ctx context.Context, name string, task workload.Task, status containerProcess) error {
	if j.restartApplied(name, task, status) {
		return nil
	}
	path := filepath.Join(j.config.StateDirectory, name+".restart")
	if err := replaceRuntimeFile(path, []byte(task.Revision+"\n"+status.StartedAt)); err != nil {
		return err
	}
	return podmanAction(ctx, "restart", "--time", "1", name)
}

func replaceRuntimeFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".runtime-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
