//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
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
	recovery := harness.Step{Name: "hosted-backup-and-recovery", Cases: []string{"WORKPLACE-45", "WORKPLACE-46", "WORKPLACE-47", "WORKPLACE-48", "WORKPLACE-52"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-run", "^TestHostedRecoveryTarget$", "./internal/controlplane"}}
	recovery = requireFile(recovery, os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), "the pinned etcd archive in OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	recovery = requireFile(recovery, os.Getenv("OCEAN_E2E_HOSTED_AZ"), "the pinned Azure CLI executable in OCEAN_E2E_HOSTED_AZ")
	telemetry := recovery
	telemetry.Name, telemetry.Cases = "hosted-telemetry-policy", []string{"WORKPLACE-61"}
	telemetry.Command = []string{"go", "test", "-mod=readonly", "-tags=e2e", "-count=1", "-run", "^TestHostedTelemetryPolicy$", "./internal/controlplane"}
	telemetry.Timeout = 4 * time.Minute
	suspension := recovery
	suspension.Name, suspension.Cases = "hosted-container-suspension", []string{"WORKPLACE-49"}
	suspension.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedContainerOffboarding$", "./internal/controlplane"}
	if suspension.BlockedReason == "" && os.Getenv("OCEAN_E2E_HOSTED_PODMAN_IMAGE") == "" {
		suspension.BlockedReason = "Provide a local Debian container image in OCEAN_E2E_HOSTED_PODMAN_IMAGE."
	}
	volume := suspension
	volume.Name, volume.Cases = "hosted-mounted-volume-suspension", []string{"WORKPLACE-50", "WORKPLACE-51"}
	volume.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedMountedVolumeOffboarding$", "./internal/controlplane"}
	volume.Timeout = 4 * time.Minute
	if volume.BlockedReason == "" && os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE") == "" {
		volume.BlockedReason = "Provide the running Ceph lab directory in OCEAN_E2E_HOSTED_CEPH_STATE."
	}
	smb := recovery
	smb.Name, smb.Cases = "hosted-smb-offboarding", []string{"WORKPLACE-53", "WORKPLACE-54", "WORKPLACE-60"}
	smb.Command = []string{"go", "test", "-mod=readonly", "-tags=e2e", "-count=1", "-run", "^TestHostedSMBOffboarding$", "./internal/controlplane"}
	smb.Timeout = 4 * time.Minute
	if smb.BlockedReason == "" && os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE") == "" {
		smb.BlockedReason = "Provide the running AD and Ceph lab in OCEAN_E2E_HOSTED_CEPH_STATE."
	}
	fixture := os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE")
	if smb.BlockedReason == "" && fixture == "" {
		smb.BlockedReason = "Provide the disposable SMB member fixture in OCEAN_E2E_SMB_MEMBER_FIXTURE."
	}
	smb = requireFile(smb, filepath.Join(fixture, "member-rbd.json"), "the disposable SMB member identity")
	smb = requireFile(smb, filepath.Join(fixture, "smbwriter"), "the disposable SMB writer credential")
	ha := smb
	ha.Name, ha.Cases = "hosted-smb-ha-offboarding", []string{"WORKPLACE-55", "WORKPLACE-56"}
	ha.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedSMBHAOffboarding$", "./internal/controlplane"}
	ha.Timeout = 6 * time.Minute
	ha = requireFile(ha, os.Getenv("OCEAN_E2E_SMB_FAILOVER_PROFILE"), "the SMB HA lab profile in OCEAN_E2E_SMB_FAILOVER_PROFILE")
	ha = requireFile(ha, filepath.Join(fixture, "failover-state-id"), "the encrypted Samba membership image ID")
	ha = requireFile(ha, filepath.Join(fixture, "failover-state.key"), "the private Samba membership image key")
	smb = requireFile(smb, filepath.Join(fixture, "smbreader"), "the disposable SMB reader credential")
	smb = requireFile(smb, filepath.Join(fixture, "smbdenied"), "the disposable ungrouped SMB credential")
	vm := recovery
	vm.Name, vm.Cases = "hosted-vm-offboarding", []string{"WORKPLACE-57"}
	vm.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedVMOffboarding$", "./internal/controlplane"}
	vm.Timeout = 9 * time.Minute
	for _, input := range []string{"OCEAN_E2E_VM_LINUX_STATE", "OCEAN_E2E_VM_LINUX_DISK_PIN", "OCEAN_E2E_VM_LINUX_VARS_PIN"} {
		if vm.BlockedReason == "" && os.Getenv(input) == "" {
			vm.BlockedReason = "Provide " + input + " for the disposable hosted VM KVM lab."
		}
	}
	vm = requireFile(vm, filepath.Join(os.Getenv("OCEAN_E2E_VM_LINUX_STATE"), "state.json"), "the prepared KVM lab")
	vm = requireFile(vm, os.Getenv("OCEAN_E2E_VM_LINUX_SSH_KEY"), "the disposable Debian VM SSH key")
	vm = requireFile(vm, os.Getenv("OCEAN_E2E_VM_LINUX_KNOWN_HOSTS"), "the pinned Debian VM host key")
	directory := recovery
	directory.Name, directory.Cases = "hosted-directory-offboarding", []string{"WORKPLACE-58"}
	directory.Command = []string{"go", "test", "-tags=e2e", "-run", "^TestHostedDirectoryOffboarding$", "./internal/controlplane"}
	directory.Timeout = 8 * time.Minute
	if directory.BlockedReason == "" && (os.Getenv("OCEAN_E2E_PACKAGED_DIRECTORY_STATE") == "" || os.Getenv("OCEAN_E2E_SAMBA_IMAGE") == "") {
		directory.BlockedReason = "Provide the disposable Samba KVM state and pinned Samba image."
	}
	directory = requireFile(directory, filepath.Join(os.Getenv("OCEAN_E2E_PACKAGED_DIRECTORY_STATE"), "state.json"), "the three-node directory lab")
	keycloak := recovery
	keycloak.Name, keycloak.Cases = "hosted-keycloak-offboarding", []string{"WORKPLACE-59"}
	keycloak.Command = []string{"go", "test", "-mod=readonly", "-tags=e2e", "-count=1", "-run", "^TestHostedKeycloakOffboarding$", "./internal/controlplane"}
	keycloak.Timeout = 5 * time.Minute
	if keycloak.BlockedReason == "" && (os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK") == "" || os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_CLIENT") == "") {
		keycloak.BlockedReason = "Provide the disposable Keycloak issuer URL and admin client ID."
	}
	keycloak = requireFile(keycloak, os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK_CA"), "the Keycloak CA file in OCEAN_E2E_HOSTED_KEYCLOAK_CA")
	keycloak = requireFile(keycloak, os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_SECRET"), "the private Keycloak admin secret file in OCEAN_E2E_KEYCLOAK_ADMIN_SECRET")
	return []harness.Step{step, placement, operator, telemetry, recovery, suspension, volume, smb, ha, vm, directory, keycloak}
}
