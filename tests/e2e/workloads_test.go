//go:build e2e

package e2e

import (
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func workloadSteps(options labOptions) []harness.Step {
	fixtureEvidence := filepath.Join(options.evidence, "native-function-images.json")
	return []harness.Step{
		{Name: "function-runtime-images", Cases: []string{"FUNCTION-01", "FUNCTION-02"}, Timeout: 20 * time.Minute,
			Command:  []string{"python3", "-B", "lab/verify_function_fixtures.py", "--output", fixtureEvidence},
			Evidence: []harness.EvidenceSource{{Name: "images.json", Path: fixtureEvidence}}},
		regional(options, "container-runtime", "verify_container_groups.py", []string{"CONTAINER-01", "CONTAINER-02", "LAB-03"},
			[]string{"container-groups.json"}),
		regional(options, "persistent-storage", "verify_storage_mounts.py", []string{"STORAGE-01"}, []string{"storage-mounts.json"}),
		regional(options, "encrypted-storage", "verify_storage_backend.py", []string{"STORAGE-02"},
			[]string{"rbd-encryption.json", "rbd-encryption.log"}),
		regional(options, "functions", "verify_functions.py", []string{"FUNCTION-01", "FUNCTION-02", "NETWORK-03", "LAB-03"},
			[]string{"http-functions.json"}),
		regional(options, "monitor", "verify_monitor_controlplane.py", []string{"OBS-01", "OBS-03"},
			[]string{"monitor-controlplane.json"}),
		regional(options, "application-insights", "verify_insights.py", []string{"OBS-02"}, []string{"application-insights.json"}),
		regional(options, "telemetry-outage", "verify_telemetry_outage.py", []string{"OBS-02", "OBS-04"}, []string{"telemetry-outage.json"}),
	}
}
