//go:build e2e

package e2e

import "github.com/Weichwolf/ocean/tests/e2e/internal/harness"

func networkSteps(options labOptions) []harness.Step {
	wireguard := regional(options, "wireguard-api", "verify_wireguard_api.py", []string{"NETWORK-05", "HA-01"},
		[]string{"wireguard-api.json"}, "--package", options.packageDeb)
	wireguard = requireFile(wireguard, options.packageDeb, "OCEAN_E2E_PACKAGE")
	return []harness.Step{
		regional(options, "tenant-network-and-firewall", "verify_network.py", []string{"NETWORK-01"},
			[]string{"virtual-network-arm.json", "routed-podman-firewall.log"}, "--firewall-node", "farm-1-node-04"),
		regional(options, "https-ingress", "verify_application_gateway_lifecycle.py", []string{"NETWORK-02", "HA-01"},
			[]string{"application-gateway-lifecycle.json"}),
		regional(options, "bicep-deployment", "verify_deployment.py", []string{"NETWORK-04"},
			[]string{"network-deployment-arm.json"}),
		wireguard,
	}
}
