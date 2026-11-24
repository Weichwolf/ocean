package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// CheckRuntime verifies that the service account can use rootless Podman.
func CheckRuntime(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "podman", "info", "--format", "{{.Host.Security.Rootless}}").Output()
	if err != nil {
		return fmt.Errorf("probe Podman: %w", err)
	}
	if strings.TrimSpace(string(output)) != "true" {
		return errors.New("Podman must be running in rootless mode")
	}
	return nil
}
