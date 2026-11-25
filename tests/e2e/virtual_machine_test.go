//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func virtualMachineSteps() []harness.Step {
	step := harness.Step{Name: "packaged-windows-vm", Cases: []string{"VM-01", "VM-02"}, Timeout: 27 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-tags=e2e", "-count=1", "-timeout=25m", "-v", "-run",
			"^TestPackagedVMWorker$", "./internal/controlplane"}}
	for _, input := range []string{"OCEAN_E2E_VM_WORKER_STATE", "OCEAN_E2E_VM_ETCD", "OCEAN_E2E_VM_DISK_PIN", "OCEAN_E2E_VM_VARS_PIN",
		"OCEAN_E2E_VM_AZ", "OCEAN_E2E_VM_SMB_AUTH", "OCEAN_E2E_VM_FENCE_PROFILE"} {
		if os.Getenv(input) == "" {
			step.BlockedReason = "Provide " + input + " for the isolated Windows VM and fencing lab."
			return []harness.Step{step}
		}
	}
	state := os.Getenv("OCEAN_E2E_VM_WORKER_STATE")
	step = requireFile(step, filepath.Join(state, "state.json"), "the prepared KVM lab")
	step = requireFile(step, filepath.Join(state, "storage-pki", "lab-fencer.pub"), "the lab fencer public key")
	step = requireFile(step, os.Getenv("OCEAN_E2E_VM_FENCE_PROFILE"), "the original VM lab profile")
	step = requireFile(step, os.Getenv("OCEAN_E2E_VM_SMB_AUTH"), "the private SMB authentication file")
	return []harness.Step{step}
}
