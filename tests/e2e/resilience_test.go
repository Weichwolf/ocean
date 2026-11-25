//go:build e2e

package e2e

import "github.com/Weichwolf/ocean/tests/e2e/internal/harness"

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
	}
}
