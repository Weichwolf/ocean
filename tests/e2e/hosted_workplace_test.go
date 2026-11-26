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
	recovery := harness.Step{Name: "hosted-backup-and-recovery", Cases: []string{"WORKPLACE-45", "WORKPLACE-46", "WORKPLACE-47", "WORKPLACE-48"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-run", "^TestHostedRecoveryTarget$", "./internal/controlplane"}}
	recovery = requireFile(recovery, os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), "the pinned etcd archive in OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	recovery = requireFile(recovery, os.Getenv("OCEAN_E2E_HOSTED_AZ"), "the pinned Azure CLI executable in OCEAN_E2E_HOSTED_AZ")
	suspension := recovery
	suspension.Name, suspension.Cases = "hosted-container-suspension", []string{"WORKPLACE-49"}
	suspension.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedContainerOffboarding$", "./internal/controlplane"}
	if suspension.BlockedReason == "" && os.Getenv("OCEAN_E2E_HOSTED_PODMAN_IMAGE") == "" {
		suspension.BlockedReason = "Provide a local Debian container image in OCEAN_E2E_HOSTED_PODMAN_IMAGE."
	}
	volume := suspension
	volume.Name, volume.Cases = "hosted-mounted-volume-suspension", []string{"WORKPLACE-50"}
	volume.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedMountedVolumeOffboarding$", "./internal/controlplane"}
	volume.Timeout = 4 * time.Minute
	if volume.BlockedReason == "" && os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE") == "" {
		volume.BlockedReason = "Provide the running Ceph lab directory in OCEAN_E2E_HOSTED_CEPH_STATE."
	}
	return []harness.Step{step, placement, operator, recovery, suspension, volume}
}
