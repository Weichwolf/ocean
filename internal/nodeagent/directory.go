package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/workload"
)

var directoryImageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var directoryHostname = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,252}$`)
var directoryStartupChallenge = regexp.MustCompile(`^[a-f0-9]{32}$`)

type directoryIDMapEntry struct {
	ContainerID int64 `json:"container_id"`
	Size        int64 `json:"size"`
}

func directoryIDMapFits(entries []directoryIDMapEntry) bool {
	// Rootless Podman interprets --uidmap/--gidmap offsets within its parent
	// namespace. The Samba profile divides IDs 0–65535 among three ranges.
	var end int64
	for _, entry := range entries {
		if entry.ContainerID != end || entry.Size <= 0 {
			return false
		}
		if entry.Size >= 65536-end {
			return true
		}
		end += entry.Size
	}
	return false
}

func (j *joinClient) directoryRuntimeAvailable(ctx context.Context) bool {
	if j.config.DirectoryImage == "" || localPodman(ctx, "image", "exists", j.config.DirectoryImage).Run() != nil {
		return false
	}
	data, err := localPodman(ctx, "info", "--format", "{{json .Host.IDMappings}}").Output()
	var mapping struct {
		UIDMap []directoryIDMapEntry `json:"uidmap"`
		GIDMap []directoryIDMapEntry `json:"gidmap"`
	}
	return err == nil && json.Unmarshal(data, &mapping) == nil && directoryIDMapFits(mapping.UIDMap) && directoryIDMapFits(mapping.GIDMap)
}

func (j *joinClient) directoryTasks(ctx context.Context) (map[string]enrollment.Assignment, error) {
	tasks := make(map[string]enrollment.Assignment)
	if j.config.DirectoryImage == "" {
		return tasks, nil
	}
	placements, err := j.networkAssignments(ctx)
	if err != nil {
		return nil, err
	}
	for _, assignment := range placements {
		directory := assignment.Directory
		if directory == nil {
			continue
		}
		index, peers := directory.ControllerIndex, directory.ControllerIPv4
		if !taskIdentityPattern.MatchString(assignment.ID) || !taskIdentityPattern.MatchString(assignment.Generation) ||
			!taskIdentityPattern.MatchString(assignment.TenantID) || !taskIdentityPattern.MatchString(assignment.SubscriptionID) ||
			!directoryHostname.MatchString(directory.DNSName) || index < 1 || index > len(peers) || peers[index-1] != assignment.PrivateIPv4 ||
			directory.WriterIndex < 0 || directory.WriterIndex > len(peers) ||
			!assignment.PrivateIPv4.Is4() || assignment.Resources.CPUMillis < 1 || assignment.Resources.MemoryMiB < 1 {
			return nil, errors.New("invalid directory task in host assignments")
		}
		if directory.RetireReplica != "" && (!directory.IsWriter() || !taskIdentityPattern.MatchString(directory.RetireReplica)) ||
			directory.PromoteFrom != "" && (!directory.IsWriter() || !taskIdentityPattern.MatchString(directory.PromoteFrom) || directory.RetireReplica != "") {
			return nil, errors.New("invalid directory retirement task")
		}
		name := containerName(directoryTaskID(assignment))
		tasks[name] = assignment
	}
	return tasks, nil
}

func directoryTaskID(assignment enrollment.Assignment) workload.AssignmentID {
	return workload.AssignmentID{TenantID: assignment.TenantID, SubscriptionID: assignment.SubscriptionID,
		ID: assignment.ID, Generation: assignment.Generation}
}

func (j *joinClient) directoryBootstrap(ctx context.Context, a enrollment.Assignment) (enrollment.DirectoryBootstrap, error) {
	var bootstrap enrollment.DirectoryBootstrap
	path := j.url() + "/directories/" + a.TenantID + "/" + a.Generation + "/bootstrap"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return bootstrap, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return bootstrap, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return bootstrap, fmt.Errorf("directory bootstrap returned HTTP %d", response.StatusCode)
	}
	sids := response.Header.Values(enrollment.DirectoryDomainSIDHeader)
	secret, err := io.ReadAll(io.LimitReader(response.Body, 129))
	if len(sids) != 1 || sids[0] != "" && !(enrollment.DirectoryHealth{Ready: true, DomainSID: sids[0]}).Valid() {
		clear(secret)
		return bootstrap, errors.New("invalid directory identity response")
	}
	establishedPrimary := sids[0] != "" && a.Directory.IsWriter()
	if err != nil || establishedPrimary && len(secret) != 0 || !establishedPrimary && (len(secret) < 24 || len(secret) > 128) {
		clear(secret)
		return bootstrap, errors.New("invalid directory bootstrap response")
	}
	return enrollment.DirectoryBootstrap{DomainSID: sids[0], Credential: secret}, nil
}

const directoryControllerPath = "/usr/local/lib/ocean-directory/controller.py"

var errDirectoryPromotionBlocked = errors.New("the directory replica is still serving read-only SYSVOL while promotion awaits a consistent policy snapshot")

func (j *joinClient) confirmDirectoryStartup(ctx context.Context, name string, assignment enrollment.Assignment) error {
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	result, err := localPodman(probe, "exec", name, "/usr/bin/timeout", "3", "/usr/bin/python3",
		directoryControllerPath, "startup-identity").Output()
	cancel()
	if err != nil {
		// A controller outside the startup handshake has nothing to authorize.
		return nil
	}
	fields := strings.Fields(string(result))
	if len(fields) != 2 || !(enrollment.DirectoryHealth{Ready: true, DomainSID: fields[0]}).Valid() ||
		!directoryStartupChallenge.MatchString(fields[1]) {
		return errors.New("invalid staged directory identity")
	}
	body, _ := json.Marshal(map[string]string{"domainSid": fields[0]})
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/identity"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory startup authorization returned HTTP %d", response.StatusCode)
	}
	return podmanAction(ctx, "exec", name, "/usr/bin/python3", directoryControllerPath, "authorize-startup", fields[0], fields[1])
}

func (j *joinClient) reportDirectoryHealth(ctx context.Context, assignment enrollment.Assignment, health enrollment.DirectoryHealth) error {
	payload, _ := json.Marshal(health)
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/health"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory health report returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (j *joinClient) acknowledgeDirectoryRetirement(ctx context.Context, name string, assignment enrollment.Assignment) error {
	retired := assignment.Directory.RetireReplica
	action := "retire-replica"
	if assignment.Directory.PromoteFrom != "" {
		retired, action = assignment.Directory.PromoteFrom, "promotion-status"
	}
	if err := podmanAction(ctx, "exec", name, "/usr/bin/timeout", "12", "/usr/bin/python3",
		directoryControllerPath, action, retired); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"retiredGeneration": retired})
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/replica-retired"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory retirement acknowledgement returned HTTP %d", response.StatusCode)
	}
	return nil
}

func directoryControllerHealth(ctx context.Context, name string) enrollment.DirectoryHealth {
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	result, err := localPodman(probe, "exec", name, "/usr/bin/timeout", "3", "/usr/bin/python3",
		directoryControllerPath, "health").Output()
	health := enrollment.DirectoryHealth{Ready: true, DomainSID: strings.TrimSpace(string(result))}
	if err != nil || !health.Valid() {
		return enrollment.DirectoryHealth{}
	}
	return health
}

func (j *joinClient) reconcileDirectoryControllers(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 20*time.Second)
		tasks, err := j.directoryTasks(round)
		if err == nil {
			err = j.syncDirectoryContainers(round, tasks)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("directory controller reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (j *joinClient) syncDirectoryContainers(ctx context.Context, tasks map[string]enrollment.Assignment) error {
	names, err := localPodman(ctx, "ps", "--all", "--filter", "label=ocean.directory-controller", "--format", "{{.Names}}").Output()
	if err != nil {
		return errors.New("could not list local directory controllers")
	}
	var failures []error
	for name := range strings.FieldsSeq(string(names)) {
		if _, assigned := tasks[name]; !assigned && validRuntimeName(name) {
			// Keep the controller volume and stop servicing the stale assignment.
			failures = append(failures, podmanAction(ctx, "stop", "--ignore", "--time", "5", name))
		}
	}
	for name, task := range tasks {
		var health enrollment.DirectoryHealth
		var syncErr error
		if !task.NetworkUnavailable && task.Network != nil {
			syncErr = j.syncDirectoryContainer(ctx, name, task)
			failures = append(failures, syncErr)
			if syncErr == nil || errors.Is(syncErr, errDirectoryPromotionBlocked) {
				health = directoryControllerHealth(ctx, name)
			}
			if syncErr == nil && !health.Ready {
				failures = append(failures, j.confirmDirectoryStartup(ctx, name, task))
			}
		}
		reportErr := j.reportDirectoryHealth(ctx, task, health)
		failures = append(failures, reportErr)
		if syncErr == nil && reportErr == nil && health.Ready && task.Directory.IsWriter() {
			if task.Directory.RetireReplica != "" || task.Directory.PromoteFrom != "" {
				if err := j.acknowledgeDirectoryRetirement(ctx, name, task); err != nil {
					failures = append(failures, err)
					continue
				}
			}
			failures = append(failures, j.runDirectoryJoinTask(ctx, name, task), j.runDirectoryGraphTask(ctx, name, task))
		}
	}
	return errors.Join(failures...)
}

func (j *joinClient) syncDirectoryContainer(ctx context.Context, name string, a enrollment.Assignment) error {
	directory := a.Directory
	status, present, err := inspectContainer(ctx, name, localPodman)
	if err != nil {
		return err
	}
	if status.Running {
		if directory.PromoteFrom == "" {
			return nil
		}
		label, err := localPodman(ctx, "inspect", "--type", "container", "--format",
			`{{index .Config.Labels "ocean.directory-promotion"}}`, name).Output()
		if err != nil {
			return errors.New("could not inspect the directory promotion generation")
		}
		if strings.TrimSpace(string(label)) == directory.PromoteFrom {
			return nil
		}
		if err := podmanAction(ctx, "exec", name, "/usr/bin/timeout", "8", "/usr/bin/python3",
			directoryControllerPath, "promotion-preflight"); err != nil {
			return errDirectoryPromotionBlocked
		}
		if err := podmanAction(ctx, "stop", "--time", "5", name); err != nil {
			return err
		}
	}
	bootstrap, err := j.directoryBootstrap(ctx, a)
	if err != nil {
		return err
	}
	defer clear(bootstrap.Credential)
	if present {
		// A restarted controller needs a fresh authorization and fresh tmpfs.
		if err := podmanAction(ctx, "rm", "--ignore", name); err != nil {
			return err
		}
	}
	if len(bootstrap.Credential) > 0 {
		createSecret := localPodman(ctx, "secret", "create", "--replace", name, "-")
		createSecret.Stdin = bytes.NewReader(bootstrap.Credential)
		if err := createSecret.Run(); err != nil {
			return errors.New("could not prepare a private directory bootstrap credential")
		}
	}
	if err := localPodman(ctx, "volume", "exists", name).Run(); err != nil {
		var missing *exec.ExitError
		if !errors.As(err, &missing) || missing.ExitCode() != 1 {
			return errors.New("could not verify the persistent directory volume")
		}
		if err := podmanAction(ctx, "volume", "create", name); err != nil {
			return err
		}
	}
	size := strconv.FormatInt(a.Resources.MemoryMiB, 10) + "m"
	cpu := strconv.FormatFloat(float64(a.Resources.CPUMillis)/1000, 'f', 3, 64)
	index := strconv.Itoa(directory.ControllerIndex)
	args := []string{"run", "--detach", "--pull=never", "--name", name,
		"--hostname", "dc0" + index, "--network=none", "--label", "ocean.directory-controller",
		"--cpus", cpu, "--memory", size, "--memory-swap", size, "--pids-limit", "128",
		"--security-opt=no-new-privileges", "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=SETUID", "--cap-add=SETGID",
		"--cap-add=NET_BIND_SERVICE", "--log-driver=k8s-file", "--log-opt=max-size=256kb",
		"--uidmap", "0:0:1", "--uidmap", "1:1:60000", "--uidmap", "3000000:60001:5535",
		"--gidmap", "0:0:1", "--gidmap", "1:1:60000", "--gidmap", "3000000:60001:5535",
		"--tmpfs", "/run/ocean-directory-startup:rw,mode=0700",
		"--mount", "type=volume,source=" + name + ",target=/var/lib/ocean-ad",
		"--env", "OCEAN_AD_DNS_NAME=" + directory.DNSName, "--env", "OCEAN_AD_NETBIOS_NAME=" + directory.NetBIOSName,
		"--env", "OCEAN_AD_DIRECTORY_ID=" + directory.DirectoryID, "--env", "OCEAN_AD_ADDRESS=" + a.PrivateIPv4.String(),
		"--env", "OCEAN_AD_CONTROLLER=" + index, "--env", "OCEAN_AD_WRITER=" + strconv.Itoa(max(directory.WriterIndex, 1)),
		"--env", "OCEAN_AD_REQUIRE_AUTHORIZATION=1",
		"--env", "OCEAN_AD_EXPECTED_SID=" + bootstrap.DomainSID}
	if len(bootstrap.Credential) > 0 {
		args = append(args, "--secret", name+",target=ocean-directory-bootstrap,mode=0400")
	}
	peer := directory.ControllerIPv4[2-directory.ControllerIndex]
	if !directory.IsWriter() {
		args = append(args, "--env", "OCEAN_AD_PRIMARY="+peer.String())
	} else if peer.Is4() {
		args = append(args, "--env", "OCEAN_AD_REPLICA="+peer.String())
	}
	if directory.PromoteFrom != "" {
		args = append(args, "--label", "ocean.directory-promotion="+directory.PromoteFrom,
			"--env", "OCEAN_AD_PROMOTE="+directory.PromoteFrom)
	}
	return podmanAction(ctx, append(args, "--", j.config.DirectoryImage)...)
}
