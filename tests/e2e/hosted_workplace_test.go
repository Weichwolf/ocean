//go:build e2e

package e2e

import (
	"os"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func hostedWorkplaceSteps() []harness.Step {
	step := harness.Step{Name: "hosted-audit-retention", Cases: []string{"WORKPLACE-42"},
		Command: []string{"go", "test", "-tags=e2e", "-run", "^TestHostedAuditRetention$", "./internal/controlplane"},
		Timeout: 2 * time.Minute}
	if os.Getenv("OCEAN_E2E_HOSTED_ETCD") == "" {
		step.BlockedReason = "Provide the disposable loopback etcd endpoint in OCEAN_E2E_HOSTED_ETCD."
	}
	step = requireFile(step, os.Getenv("OCEAN_E2E_HOSTED_AZ"), "the pinned Azure CLI executable in OCEAN_E2E_HOSTED_AZ")
	return []harness.Step{step}
}
