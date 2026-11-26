//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func provisioningSteps(options labOptions) []harness.Step {
	pkg := probe("agent-package", options.small, "OCEAN_E2E_SMALL_STATE", "verify_agent_package.py",
		[]string{"HOST-01", "LAB-01"}, []string{"agent-package.json"}, "--node", "farm-1-node-03", "--package", options.packageDeb)
	pkg = requireFile(pkg, options.packageDeb, "OCEAN_E2E_PACKAGE")
	host := probe("host-enrollment", options.small, "OCEAN_E2E_SMALL_STATE", "verify_enrollment.py",
		[]string{"HOST-01", "LAB-01"}, []string{"host-enrollment.json"}, "--node", "farm-1-node-03")
	scaleCases := []string{"LAB-02"}
	if options.phaseOne {
		scaleCases = append(scaleCases, "HOST-01")
	}
	scale := probe("sixteen-node-placement", options.scale, "OCEAN_E2E_SCALE_STATE", "verify_scale16.py", scaleCases,
		[]string{"scale-16.json"}, "--package", options.packageDeb)
	scale = requireFile(scale, options.packageDeb, "OCEAN_E2E_PACKAGE")
	scale.Timeout = 45 * time.Minute
	rackInventory := rackInventoryStep(options.evidence)
	return []harness.Step{
		regional(options, "cli-contract", "verify_arm.py", []string{"CONTRACT-01", "CONTRACT-02"}, []string{"arm-resource-groups.json"}),
		regional(options, "inventory", "verify_inventory.py", []string{"CONTRACT-02"}, []string{"arm-inventory.json"}),
		regional(options, "operations", "verify_operations.py", []string{"CONTRACT-03"}, []string{"arm-operations.json"}),
		probe("small-topology", options.small, "OCEAN_E2E_SMALL_STATE", "verify_lab_topology.py", []string{"LAB-01"},
			[]string{"small-topology.json"}, "--profile", "single-farm-3"),
		pkg,
		host,
		rackInventory,
		rackInstallStep(options.evidence),
		scale,
		regional(options, "mixed-node-placement", "verify_lab_topology.py", []string{"LAB-03"},
			[]string{"mixed-topology.json"}, "--profile", "storage-ha"),
		regional(options, "placement", "verify_placement.py", []string{"LAB-03"}, []string{"host-placement.json"},
			"--small", "farm-1-node-05", "--large", "farm-1-node-06", "--storage-workers"),
	}
}

func rackInstallStep(evidence string) harness.Step {
	step := rackInventoryStep(evidence)
	step.Name, step.Cases, step.Timeout = "rack-debian-install-join", []string{"RACK-02"}, 7*time.Minute
	step.Command = []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-run", "^TestRackInstallAndJoin$", "./internal/controlplane"}
	path := filepath.Join(evidence, "rack-debian-install.json")
	step.Env[1] = "OCEAN_E2E_RACK_EVIDENCE=" + path
	step.Evidence = []harness.EvidenceSource{{Name: "rack-debian-install.json", Path: path}}
	for _, input := range []string{"OCEAN_E2E_RACK_IMAGE", "OCEAN_E2E_RACK_PACKAGE"} {
		file := os.Getenv(input)
		step = requireFile(step, file, input)
	}
	for _, tool := range []string{"qemu-system-x86_64", "qemu-img", "genisoimage", "ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install " + tool + " for the rack installation probe."
		}
	}
	if _, err := os.Stat("/dev/kvm"); err != nil && step.BlockedReason == "" {
		step.BlockedReason = "Provide local KVM access for the Debian first-boot probe."
	}
	return step
}

func rackInventoryStep(evidence string) harness.Step {
	named, err := exec.LookPath(envOr("OCEAN_E2E_RACK_BIND_BINARY", "named"))
	path := filepath.Join(evidence, "rack-inventory-dns.json")
	step := harness.Step{Name: "regional-rack-inventory-dns", Cases: []string{"RACK-01"}, Timeout: 2 * time.Minute,
		Command:  []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-run", "^TestRackInventoryAndDNS$", "./internal/controlplane"},
		Env:      []string{"OCEAN_E2E_RACK_BIND_BINARY=" + named, "OCEAN_E2E_RACK_EVIDENCE=" + path},
		Evidence: []harness.EvidenceSource{{Name: "rack-inventory-dns.json", Path: path}},
	}
	if err != nil {
		step.BlockedReason = "Install BIND 9 or set OCEAN_E2E_RACK_BIND_BINARY to its named executable."
	}
	if os.Getenv("OCEAN_E2E_ETCD_ENDPOINTS") == "" || os.Getenv("OCEAN_E2E_ETCD_PKI") == "" {
		step.BlockedReason = "Provide the disposable regional etcd endpoint and client PKI."
	}
	for _, tool := range []string{"nsupdate", "dig"} {
		if _, err := exec.LookPath(tool); err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install bind9-dnsutils for the rack DNS probe."
		}
	}
	return step
}
