//go:build e2e

package e2e

import (
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func resilienceSteps(options labOptions) []harness.Step {
	restore := regional(options, "independent-restore", "verify_storage_mounts.py", []string{"HA-04"},
		[]string{"storage-recovery.json", "storage-recovery-data.log"}, "--observer", "farm-1-node-03", "--restore-from-backups", options.backup)
	restore = requireFile(restore, options.backup, "OCEAN_E2E_ETCD_ARCHIVE")
	return []harness.Step{
		regional(options, "local-replicas", "verify_replica_sets.py", []string{"SCALE-01", "HA-01"}, []string{"replica-sets.json"}),
		regional(options, "partition-and-writer-fence", "verify_storage_mounts.py", []string{"HA-01", "HA-02"},
			[]string{"storage-fencing.json"}, "--fence"),
		regional(options, "workload-quorum-loss", "verify_workload_quorum.py", []string{"HA-03"}, []string{"workload-quorum.json"}),
		regional(options, "region-failover", "verify_region.py", []string{"HA-05", "HA-06"}, []string{"region-failover.json"}, "--profile", "lab/profiles/storage-ha.yaml", "--cli"),
		restore,
		farmPairingStep(options.evidence, false),
		farmPairingStep(options.evidence, true),
	}
}

func farmPairingStep(evidence string, routing bool) harness.Step {
	name, id, filename := "wireguard-farm-pairing", "FED-01", "farm-pairing.json"
	if routing {
		name, id, filename = "wireguard-farm-routing", "FED-02", "farm-routing.json"
	}
	output := filepath.Join(evidence, filename)
	step := harness.Step{
		Name: name, Cases: []string{id}, Timeout: 3 * time.Minute,
		Command:  []string{"unshare", "-Urn", "--", "python3", "-B", "lab/verify_farm_pairing.py", "--output", output},
		Evidence: []harness.EvidenceSource{{Name: filename, Path: output}},
	}
	for _, tool := range []struct{ flag, variable, name string }{
		{"--etcd", "OCEAN_E2E_ETCD_BINARY", "etcd"}, {"--etcdctl", "OCEAN_E2E_ETCDCTL_BINARY", "etcdctl"},
		{"--wg", "OCEAN_E2E_WG_BINARY", "wg"}, {"--dnsmasq", "OCEAN_E2E_DNSMASQ_BINARY", "/usr/sbin/dnsmasq"},
	} {
		path, err := exec.LookPath(envOr(tool.variable, tool.name))
		if err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install " + tool.name + " or provide " + tool.variable + "."
		}
		step.Command = append(step.Command, tool.flag, path)
	}
	for _, name := range []string{"unshare", "nsenter", "ip", "openssl", "curl", "ping", "dig"} {
		if _, err := exec.LookPath(name); err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install " + name + " for the WireGuard federation probe."
		}
	}
	if routing {
		bird, err := exec.LookPath(envOr("OCEAN_E2E_BIRD_BINARY", "/usr/sbin/bird"))
		if err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install BIRD 2 or provide OCEAN_E2E_BIRD_BINARY."
		}
		birdc, err := exec.LookPath(envOr("OCEAN_E2E_BIRDC_BINARY", filepath.Join(filepath.Dir(bird), "birdc")))
		if err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install birdc or provide OCEAN_E2E_BIRDC_BINARY."
		}
		if _, err := exec.LookPath("/usr/sbin/sysctl"); err != nil && step.BlockedReason == "" {
			step.BlockedReason = "Install procps for the forwarding setup."
		}
		step.Command = append(step.Command, "--bird", bird, "--birdc", birdc)
	}
	return step
}
