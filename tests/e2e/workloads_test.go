//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func workloadSteps(options labOptions) []harness.Step {
	fixtureEvidence := filepath.Join(options.evidence, "native-function-images.json")
	nativeZIP := harness.Step{Name: "native-functions-zip", Cases: []string{"ZIP-01"}, Timeout: 3 * time.Minute,
		Command: []string{"go", "test", "-tags=e2e", "-run", "^TestNativeZIPFunction$", "./internal/functions"},
		Env:     []string{"OCEAN_E2E_FUNCTIONS_ZIP_NATIVE=1"}}
	if _, err := exec.LookPath("podman"); err != nil {
		nativeZIP.BlockedReason = "Install rootless Podman for the prebuilt Functions probe."
	}
	packageStore := harness.Step{Name: "regional-functions-zip-store", Cases: []string{"ZIP-02"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-run", "^TestRegionalFunctionPackages$", "./internal/controlplane"},
		Env:     []string{"OCEAN_E2E_FUNCTIONS_PACKAGE_STORE=1"}}
	slotSwap := packageStore
	slotSwap.Name, slotSwap.Cases = "regional-functions-slot-swap", []string{"ZIP-03"}
	slotSwap.Command = []string{"go", "test", "-race", "-tags=e2e", "-run", "^TestRegionalFunctionSlotSwap$", "./internal/controlplane"}
	if os.Getenv("OCEAN_E2E_ETCD_ENDPOINTS") == "" || os.Getenv("OCEAN_E2E_ETCD_PKI") == "" {
		packageStore.BlockedReason = "Provide OCEAN_E2E_ETCD_ENDPOINTS and OCEAN_E2E_ETCD_PKI for the package storage probe."
		slotSwap.BlockedReason = "Provide OCEAN_E2E_ETCD_ENDPOINTS and OCEAN_E2E_ETCD_PKI for the slot swap probe."
	}
	costLedger := harness.Step{Name: "regional-cost-ledger", Cases: []string{"COST-01"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-run", "^TestRegionalCostLedger$", "./internal/controlplane"},
		Env:     []string{"OCEAN_E2E_COST_LEDGER=1"}}
	if os.Getenv("OCEAN_E2E_ETCD_ENDPOINTS") == "" || os.Getenv("OCEAN_E2E_ETCD_PKI") == "" {
		costLedger.BlockedReason = "Provide OCEAN_E2E_ETCD_ENDPOINTS and OCEAN_E2E_ETCD_PKI for the cost ledger probe."
	}
	return []harness.Step{
		nativeZIP, packageStore, slotSwap, costLedger,
		{Name: "function-runtime-images", Cases: []string{"FUNCTION-01", "FUNCTION-02"}, Timeout: 20 * time.Minute,
			Command:  []string{"python3", "-B", "lab/verify_function_fixtures.py", "--output", fixtureEvidence},
			Evidence: []harness.EvidenceSource{{Name: "images.json", Path: fixtureEvidence}}},
		regional(options, "container-runtime", "verify_container_groups.py", []string{"CONTAINER-01", "CONTAINER-02", "LAB-03", "CONTRACT-03"},
			[]string{"container-groups.json"}, "--parallel-create"),
		regional(options, "persistent-storage", "verify_storage_mounts.py", []string{"STORAGE-01"}, []string{"storage-mounts.json"}),
		regional(options, "encrypted-storage", "verify_storage_backend.py", []string{"STORAGE-02"},
			[]string{"rbd-encryption.json", "rbd-encryption.log"}),
		regional(options, "functions", "verify_functions.py", []string{"FUNCTION-01", "FUNCTION-02", "NETWORK-03", "LAB-03", "CONTRACT-03"},
			[]string{"http-functions.json"}, "--parallel-create"),
		regional(options, "functions-zip-slots", "verify_functions_zip.py", []string{"PROFILE-02"}, []string{"functions-zip-slots.json"}),
		regional(options, "cost-management", "verify_cost_management.py", []string{"PROFILE-03"}, []string{"cost-management.json"}),
		regional(options, "monitor", "verify_monitor_controlplane.py", []string{"OBS-01", "OBS-03"},
			[]string{"monitor-controlplane.json"}),
		regional(options, "application-insights", "verify_insights.py", []string{"OBS-02"}, []string{"application-insights.json"}),
		regional(options, "telemetry-outage", "verify_telemetry_outage.py", []string{"OBS-02", "OBS-04"}, []string{"telemetry-outage.json"}),
	}
}
