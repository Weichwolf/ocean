//go:build e2e

package nodeagent

import (
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

// TestHostedWorkerProcess is launched as a foreground service in the RBD lab
// guest. Both services use their normal enrolled worker and storage code.
func TestHostedWorkerProcess(t *testing.T) {
	mode := os.Getenv("OCEAN_E2E_HOSTED_WORKER_MODE")
	if mode == "" {
		t.Skip("the mounted-volume probe runs this process in the lab guest")
	}
	directory := os.Getenv("OCEAN_E2E_HOSTED_WORKER_CONFIG")
	if !filepath.IsAbs(directory) {
		t.Fatal("the worker requires an absolute fixture configuration directory")
	}
	ctx, stop := signal.NotifyContext(t.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	agent := filepath.Join(directory, "config.json")
	var err error
	switch mode {
	case "storage":
		err = RunStorage(ctx, filepath.Join(directory, "storage.json"), agent, slog.Default())
	case "containers":
		err = RunContainerOffboardingE2E(ctx, agent, slog.Default(), make(chan struct{}))
	default:
		t.Fatal("unknown fixture worker mode")
	}
	if err != nil {
		t.Fatal(err)
	}
}
