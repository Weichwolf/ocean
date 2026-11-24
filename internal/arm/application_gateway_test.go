package arm

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
)

func TestApplicationGatewayCLIShape(t *testing.T) {
	data, err := os.ReadFile("../../tests/e2e/testdata/application-gateway-deployment.json")
	if err != nil {
		t.Fatal(err)
	}
	const subscription = "a3d3a78f-3e23-4a5e-95a9-974f947de067"
	scope := SubscriptionScope{SubscriptionID: subscription}
	address := ResourceAddress{Group: "gateway-lab", Path: deploymentType + "/ag_deploy_disposable"}
	read := func(data []byte) (ApplicationGatewayDeployment, error) {
		var input deploymentInput
		if err := strictJSON(bytes.NewReader(data), &input); err != nil {
			return ApplicationGatewayDeployment{}, err
		}
		return compileApplicationGateway(scope, address, "farm-1", input.Properties.Template, input.Properties.Parameters)
	}
	parsed, err := read(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Deployment != address ||
		parsed.ResourceAddress != (ResourceAddress{Group: "gateway-lab", Path: applicationGatewayType + "/ingress"}) ||
		parsed.PublicIP.Path != "Microsoft.Network/publicIPAddresses/external" ||
		parsed.Subnet.Path != "Microsoft.Network/virtualNetworks/private/subnets/workloads" ||
		parsed.Backend != netip.MustParseAddrPort("10.89.1.4:8080") || parsed.CertificateName != "ingressSslCert" ||
		parsed.password != "disposable" || string(parsed.certificatePFX) != "test-pfx" {
		t.Fatal("the gateway template produced unexpected desired state")
	}
	for _, edit := range []struct {
		name string
		from string
		to   string
	}{
		{"foreign reference", subscription, "8a95b237-0c3b-4bb1-9c5f-34ce786e8b48"},
		{"selected client workload port", `"Port": "8080"`, `"Port": "0"`},
		{"certificate projection", `"[reference('ingress')]"`, `"[parameters('certPassword')]"`},
		{"nonredundant gateway", `"capacity": 2`, `"capacity": 1`},
		{"unknown setting", `"privateLinkConfigurations"`, `"unverifiedSettings"`},
	} {
		t.Run(edit.name, func(t *testing.T) {
			changed := bytes.Replace(data, []byte(edit.from), []byte(edit.to), 1)
			if bytes.Equal(changed, data) {
				t.Fatal("the fixture did not contain the expected field")
			}
			if _, err := read(changed); err == nil {
				t.Fatal("an unsupported Application Gateway template was accepted")
			}
		})
	}
}
