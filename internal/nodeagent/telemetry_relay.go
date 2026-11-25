package nodeagent

import (
	"context"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
)

const relayImage = "docker.io/library/busybox@sha256:5624bb6777cf469b1fb50ae3f981b15d2715ee2fffaf20b9998cfb7843726835"

type telemetryTarget struct {
	assignment workload.AssignmentID
	function   bool
}

type telemetrySubmission struct {
	observations []telemetry.Observation
	persisted    chan error
}

type functionRelay struct {
	server    *http.Server
	pid       int
	directory string
	available bool
}

func (j *joinClient) setTelemetryTargets(tasks []workload.Task) {
	targets := make([]telemetryTarget, 0, len(tasks))
	for _, task := range tasks {
		if task.State != workload.Running {
			continue
		}
		if task.Function != nil && (task.Start || task.Restart) {
			continue
		}
		targets = append(targets, telemetryTarget{assignment: task.AssignmentID, function: task.Function != nil})
	}
	j.telemetryTargets.Store(&targets)
}

func (j *joinClient) startFunctionListener(name string, id telemetry.Assignment,
	submissions chan<- telemetrySubmission) (*functionRelay, error) {
	root := filepath.Join(j.config.StateDirectory, "otlp", name)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "collector.sock")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	const maxConnections = 4
	slots := make(chan struct{}, maxConnections)
	mux.HandleFunc("POST /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "collector busy", http.StatusTooManyRequests)
			return
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType != "application/json" {
			http.Error(w, "HTTP JSON trace payload required", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, telemetry.MaxBody)
		samples, err := telemetry.ParseTraces(r, time.Now().UTC())
		if err != nil {
			http.Error(w, "invalid trace payload", http.StatusBadRequest)
			return
		}
		if len(samples) > 0 {
			submission := telemetrySubmission{observations: make([]telemetry.Observation, 0, len(samples)), persisted: make(chan error, 1)}
			for _, sample := range samples {
				submission.observations = append(submission.observations, telemetry.Observation{Assignment: id, Sample: sample})
			}
			select {
			case submissions <- submission:
			default:
				http.Error(w, "collector busy", http.StatusTooManyRequests)
				return
			}
			select {
			case err = <-submission.persisted:
			case <-r.Context().Done():
				return
			case <-time.After(4 * time.Second):
				http.Error(w, "collector busy", http.StatusServiceUnavailable)
				return
			}
			if err != nil {
				http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	})
	server := &http.Server{Handler: mux, MaxHeaderBytes: 4096, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 4 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 8 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return &functionRelay{server: server, directory: root}, nil
}

func (relay *functionRelay) close() {
	_ = relay.server.Close()
	_ = os.Remove(relay.directory)
}

func reconcileRelay(ctx context.Context, name string, pid int, relay *functionRelay) error {
	if relay.available && relay.pid == pid {
		return nil
	}
	sidecar := name + "-telemetry"
	if relay.pid != pid {
		if err := podmanAction(ctx, "rm", "--ignore", "--force", "--time", "0", sidecar); err != nil {
			return err
		}
	}
	binary := "/usr/libexec/ocean/ocean-telemetry-relay"
	args := []string{"run", "--detach", "--pull=missing", "--name", sidecar, "--network=container:" + name, "--read-only", "--pids-limit=16",
		"--cpus", "0.04", "--memory", "24m", "--memory-swap", "24m", "--restart", "always",
		"--security-opt=no-new-privileges", "--cap-drop=ALL", "--log-driver=k8s-file", "--log-opt=max-size=16kb",
		"--env", "GOMEMLIMIT=14MiB", "--mount", "type=bind,source=" + relay.directory + ",target=/relay,ro",
		"--mount", "type=bind,source=" + binary + ",target=/ocean-telemetry-relay,ro",
		"--entrypoint", "/ocean-telemetry-relay", "--", relayImage}
	if err := podmanAction(ctx, args...); err != nil {
		return err
	}
	relay.pid, relay.available = pid, true
	return nil
}

func (j *joinClient) reconcileTelemetryRelays(ctx context.Context, logger *slog.Logger,
	running map[telemetryTarget]int, relays map[string]*functionRelay, submissions chan<- telemetrySubmission) {
	names := make(map[string]bool)
	for target, pid := range running {
		if !target.function {
			continue
		}
		name := containerName(target.assignment)
		names[name] = true
		if pid == 0 {
			continue
		}
		relay, exists := relays[name]
		if !exists {
			var err error
			relay, err = j.startFunctionListener(name, telemetryAssignmentID(target.assignment), submissions)
			if err != nil {
				logger.Warn("open Function telemetry socket", "placement", target.assignment.ID, "error", err)
				continue
			}
			relays[name] = relay
		}
		work, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := reconcileRelay(work, name, pid, relay)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("reconcile Function telemetry relay", "placement", target.assignment.ID, "error", err)
		}
	}
	for name, relay := range relays {
		if names[name] {
			continue
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := podmanAction(work, "rm", "--ignore", "--force", "--time", "0", name+"-telemetry")
		cancel()
		if err != nil {
			continue
		}
		relay.close()
		delete(relays, name)
	}
}
