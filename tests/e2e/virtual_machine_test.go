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
		Command: []string{"go", "test", "-tags=e2e", "-timeout=25m", "-run",
			"^TestPackagedVMWorker$", "./internal/controlplane"}}
	for _, input := range []string{"OCEAN_E2E_VM_WORKER_STATE", "OCEAN_E2E_VM_ETCD", "OCEAN_E2E_VM_DISK_PIN", "OCEAN_E2E_VM_VARS_PIN",
		"OCEAN_E2E_VM_AZ", "OCEAN_E2E_VM_SMB_AUTH", "OCEAN_E2E_VM_FENCE_PROFILE"} {
		if os.Getenv(input) == "" {
			step.BlockedReason = "Provide " + input + " for the isolated Windows VM and fencing lab."
			break
		}
	}
	state := os.Getenv("OCEAN_E2E_VM_WORKER_STATE")
	step = requireFile(step, filepath.Join(state, "state.json"), "the prepared KVM lab")
	step = requireFile(step, filepath.Join(state, "storage-pki", "lab-fencer.pub"), "the lab fencer public key")
	step = requireFile(step, os.Getenv("OCEAN_E2E_VM_FENCE_PROFILE"), "the original VM lab profile")
	step = requireFile(step, os.Getenv("OCEAN_E2E_VM_SMB_AUTH"), "the private SMB authentication file")
	linux := harness.Step{Name: "packaged-debian-desktop-vm", Cases: []string{"VM-03"}, Timeout: 18 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-timeout=16m", "-run",
			"^TestPackagedLinuxVMWorker$", "./internal/controlplane"}}
	for _, input := range []string{"OCEAN_E2E_VM_LINUX_STATE", "OCEAN_E2E_VM_ETCD", "OCEAN_E2E_VM_AZ",
		"OCEAN_E2E_VM_LINUX_DISK_PIN", "OCEAN_E2E_VM_LINUX_VARS_PIN", "OCEAN_E2E_VM_LINUX_SSH_KEY", "OCEAN_E2E_VM_LINUX_KNOWN_HOSTS"} {
		if os.Getenv(input) == "" {
			linux.BlockedReason = "Provide " + input + " for the isolated Debian desktop VM lab."
			break
		}
	}
	linuxState := os.Getenv("OCEAN_E2E_VM_LINUX_STATE")
	linux = requireFile(linux, filepath.Join(linuxState, "state.json"), "the prepared KVM lab")
	linux = requireFile(linux, filepath.Join(linuxState, "storage-pki", "lab-fencer.pub"), "the lab fencer public key")
	linux = requireFile(linux, os.Getenv("OCEAN_E2E_VM_LINUX_SSH_KEY"), "the disposable desktop fixture SSH key")
	linux = requireFile(linux, os.Getenv("OCEAN_E2E_VM_LINUX_KNOWN_HOSTS"), "the pinned desktop fixture SSH host key")
	desktopFence := harness.Step{Name: "packaged-desktop-vm-fence", Cases: []string{"WORKPLACE-37"}, Timeout: 24 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-timeout=22m", "-run",
			"^TestPackagedDesktopVMFence$", "./internal/controlplane"},
		BlockedReason: linux.BlockedReason,
		Evidence:      []harness.EvidenceSource{{Name: "desktop-vm-fence.tsv", Path: filepath.Join(linuxState, "evidence", "desktop-vm-fence.tsv")}}}
	desktopFence = requireFile(desktopFence, os.Getenv("OCEAN_E2E_VM_FENCE_PROFILE"), "the original two-worker KVM lab profile")
	pair := harness.Step{Name: "packaged-assigned-desktop-pair", Cases: []string{"WORKPLACE-40"}, Timeout: 24 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-timeout=22m", "-run",
			"^TestPackagedAssignedDesktopPair$", "./internal/controlplane"},
		BlockedReason: linux.BlockedReason,
		Evidence: []harness.EvidenceSource{
			{Name: "desktop-pair.tsv", Path: filepath.Join(linuxState, "evidence", "desktop-pair.tsv")},
			{Name: "desktop-pair-rdp.tsv", Path: filepath.Join(linuxState, "evidence", "desktop-pair-rdp.tsv")},
		}}
	windowsState := os.Getenv("OCEAN_E2E_VM_RDP_WINDOWS_STATE")
	windowsPair := pair
	windowsPair.Name = "packaged-assigned-desktop-pair-windows"
	windowsPair.Cases = []string{"WORKPLACE-41"}
	windowsPair.Command = []string{"go", "test", "-tags=e2e", "-timeout=22m", "-run",
		"^TestPackagedAssignedDesktopPairWindows$", "./internal/controlplane"}
	windowsPair = requireFile(windowsPair, filepath.Join(windowsState, "rdp-root.cer"), "the Windows RDP fixture's disposable root certificate")
	windowsPair = requireFile(windowsPair, filepath.Join(windowsState, "rdp-root.key"), "the Windows RDP fixture's private signing key")
	windowsPair = requireFile(windowsPair, filepath.Join(windowsState, "windows-11", "guest-serial.log"), "the Windows 11 fixture's serial capture")
	return []harness.Step{step, linux, desktopFence, pair, windowsPair}
}
