//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func domainJoinSteps(options labOptions) []harness.Step {
	const stateVariable = "OCEAN_E2E_DOMAIN_STATE"
	const script = "verify_domain_join.py"
	debian := probe("debian-domain-join", options.domain, stateVariable, script, []string{"WORKPLACE-01"},
		[]string{"debian-domain-join.json"}, "--debian-image", options.domainImage)
	steps := []harness.Step{requireFile(debian, options.domainImage, "OCEAN_E2E_DEBIAN_IMAGE")}
	for _, fixture := range []struct{ profile, id string }{
		{"server-core", "WORKPLACE-02"},
		{"windows-11", "WORKPLACE-03"},
	} {
		name := fixture.profile + "-domain-join"
		step := probe(name, options.domain, stateVariable, script, []string{fixture.id},
			[]string{name + ".json"}, "--windows-profile", fixture.profile)
		for _, file := range []string{"media.json", "join.json", "machine.json", "identity.json"} {
			step = requireFile(step, filepath.Join(options.domain, fixture.profile, file), fixture.profile+" "+file)
		}
		steps = append(steps, step)
	}
	runtime := harness.Step{Name: "samba-controller-pair", Cases: []string{"WORKPLACE-04"}, Timeout: 4 * time.Minute,
		Command: []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage}}
	if options.sambaImage == "" {
		runtime.BlockedReason = "Provide OCEAN_E2E_SAMBA_IMAGE with the locally built controller image ID."
	} else if _, err := exec.LookPath("podman"); err != nil {
		runtime.BlockedReason = "Install rootless Podman for the directory runtime probe."
	}
	recovery := harness.Step{Name: "directory-backup-recovery", Cases: []string{"WORKPLACE-07"}, Timeout: 4 * time.Minute,
		Command:       []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage, "--restore"},
		BlockedReason: runtime.BlockedReason}
	if _, err := exec.LookPath("openssl"); err != nil && recovery.BlockedReason == "" {
		recovery.BlockedReason = "Install OpenSSL for the encrypted backup recovery probe."
	}
	cli := harness.Step{Name: "managed-directory-az", Cases: []string{"WORKPLACE-05"}, Timeout: 2 * time.Minute,
		Command: []string{"env", "OCEAN_E2E_DIRECTORY_CLI=1", "go", "test", "-count=1", "-v",
			"-run", "^TestManagedDirectoryHTTP$", "./internal/identity"}}
	if _, err := exec.LookPath("az"); err != nil {
		cli.BlockedReason = "Install the pinned Azure CLI 2.93.0 for the managed directory contract probe."
	}
	fencing := harness.Step{Name: "managed-directory-fencing", Cases: []string{"WORKPLACE-06"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestManagedDirectoryReservation$", "./internal/controlplane"}}
	if os.Getenv("OCEAN_E2E_DIRECTORY_ETCD") == "" {
		fencing.BlockedReason = "Provide OCEAN_E2E_DIRECTORY_ETCD with a disposable etcd endpoint."
	}
	return append(steps, runtime, cli, fencing, recovery)
}
