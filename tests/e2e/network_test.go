//go:build e2e

package e2e

import (
	"os"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func networkSteps(options labOptions) []harness.Step {
	wireguard := regional(options, "wireguard-api", "verify_wireguard_api.py", []string{"NETWORK-05", "HA-01"},
		[]string{"wireguard-api.json"}, "--package", options.packageDeb)
	wireguard = requireFile(wireguard, options.packageDeb, "OCEAN_E2E_PACKAGE")
	ipsec := harness.Step{Name: "regional-ipsec-lifecycle", Cases: []string{"IPSEC-02"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-run", "^TestIPsecRegionalLifecycle$", "./internal/controlplane"},
		Env:     []string{"OCEAN_E2E_IPSEC_REGIONAL=1"}}
	if os.Getenv("OCEAN_E2E_ETCD_ENDPOINTS") == "" || os.Getenv("OCEAN_E2E_ETCD_PKI") == "" {
		ipsec.BlockedReason = "Provide OCEAN_E2E_ETCD_ENDPOINTS and OCEAN_E2E_ETCD_PKI for the disposable regional etcd cluster."
	}
	return []harness.Step{
		regional(options, "tenant-network-and-firewall", "verify_network.py", []string{"NETWORK-01"},
			[]string{"virtual-network-arm.json", "routed-podman-firewall.log"}, "--firewall-node", "farm-1-node-04"),
		regional(options, "https-ingress", "verify_application_gateway_lifecycle.py", []string{"NETWORK-02", "HA-01"},
			[]string{"application-gateway-lifecycle.json"}),
		regional(options, "bicep-deployment", "verify_deployment.py", []string{"NETWORK-04"},
			[]string{"network-deployment-arm.json"}),
		wireguard,
		probe("routed-ipsec-gateway", options.ipsec, "OCEAN_E2E_IPSEC_LAB_STATE", "verify_ipsec_gateway.py",
			[]string{"IPSEC-01"}, nil),
		ipsec,
	}
}
