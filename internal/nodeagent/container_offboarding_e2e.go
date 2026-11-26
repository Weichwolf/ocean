//go:build e2e

package nodeagent

import (
	"context"
	"log/slog"
)

// RunContainerOffboardingE2E runs the agent's workload reconciler using an
// enrolled test identity. The fixture creates its own disposable containers.
func RunContainerOffboardingE2E(ctx context.Context, path string, logger *slog.Logger, ready chan<- struct{}) error {
	if err := CheckRuntime(ctx); err != nil {
		return err
	}
	client, err := loadEnrolledClient(path)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	if _, err := client.containerTasks(ctx, false); err != nil {
		return err
	}
	close(ready)
	client.reconcileContainers(ctx, logger)
	return nil
}
