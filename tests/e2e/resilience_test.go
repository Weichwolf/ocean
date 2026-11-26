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
		geoIngressStep(options.evidence),
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
	addFederationTool(&step, "--etcd", "OCEAN_E2E_ETCD_BINARY", "etcd")
	addFederationTool(&step, "--etcdctl", "OCEAN_E2E_ETCDCTL_BINARY", "etcdctl")
	addFederationTool(&step, "", "", "ping")
	addWireGuardTools(&step)
	if routing {
		addBirdTools(&step)
	}
	return step
}

func geoIngressStep(evidence string) harness.Step {
	const filename = "geo-ingress.json"
	output := filepath.Join(evidence, filename)
	step := harness.Step{
		Name: "geo-https-ingress", Cases: []string{"FED-03"}, Timeout: time.Minute,
		Command:  []string{"unshare", "-Urn", "--", "python3", "-B", "lab/verify_geo_ingress.py", "--output", output},
		Evidence: []harness.EvidenceSource{{Name: filename, Path: output}},
	}
	addWireGuardTools(&step)
	addBirdTools(&step)
	addFederationTool(&step, "--haproxy", "OCEAN_E2E_HAPROXY_BINARY", "/usr/sbin/haproxy")
	return step
}

func addWireGuardTools(step *harness.Step) {
	addFederationTool(step, "--wg", "OCEAN_E2E_WG_BINARY", "wg")
	addFederationTool(step, "--dnsmasq", "OCEAN_E2E_DNSMASQ_BINARY", "/usr/sbin/dnsmasq")
	for _, name := range []string{"unshare", "nsenter", "ip", "openssl", "curl", "dig", "python3"} {
		addFederationTool(step, "", "", name)
	}
}

func addBirdTools(step *harness.Step) {
	bird := addFederationTool(step, "--bird", "OCEAN_E2E_BIRD_BINARY", "/usr/sbin/bird")
	addFederationTool(step, "--birdc", "OCEAN_E2E_BIRDC_BINARY", filepath.Join(filepath.Dir(bird), "birdc"))
	addFederationTool(step, "", "", "/usr/sbin/sysctl")
}

func addFederationTool(step *harness.Step, option, variable, name string) string {
	command := name
	if variable != "" {
		command = envOr(variable, name)
	}
	path, err := exec.LookPath(command)
	if err != nil && step.BlockedReason == "" {
		step.BlockedReason = "Install " + name + " for the federation probe."
		if variable != "" {
			step.BlockedReason = "Install " + name + " or provide " + variable + "."
		}
	}
	if option != "" {
		step.Command = append(step.Command, option, path)
	}
	return path
}
