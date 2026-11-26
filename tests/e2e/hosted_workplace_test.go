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
	placement := step
	placement.Name = "hosted-placement-policy"
	placement.Cases = []string{"WORKPLACE-43"}
	placement.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedPlacement$", "./internal/controlplane"}
	operator := step
	operator.Name = "hosted-operator-placement"
	operator.Cases = []string{"WORKPLACE-44"}
	operator.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedOperatorPlacement$", "./internal/controlplane"}
	recovery := harness.Step{Name: "hosted-backup-and-recovery", Cases: []string{"WORKPLACE-45", "WORKPLACE-46"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-run", "^TestHostedRecoveryTarget$", "./internal/controlplane"}}
	recovery = requireFile(recovery, os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), "the pinned etcd archive in OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	return []harness.Step{step, placement, operator, recovery}
}
