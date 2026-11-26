package arm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
)

type ipsecCLIRequest struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   json.RawMessage
}

func TestIPsecCLIRequestShape(t *testing.T) {
	data, err := os.ReadFile("../../tests/e2e/testdata/ipsec-cli-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var requests []ipsecCLIRequest
	if err := json.Unmarshal(data, &requests); err != nil || len(requests) != 5 {
		t.Fatalf("expected five captured requests: %v", err)
	}
	const region = "ocean-lab"
	const subscription = "22222222-2222-4222-8222-222222222222"
	scope := SubscriptionScope{SubscriptionID: subscription}
	routes := []string{"vpn", "vpn", "deployment", "vpn", "vpn"}
	versions := []string{VPNGatewayAPIVersion, VPNLocalGatewayAPIVersion, resourceAPIVersion, VPNGatewayAPIVersion, VPNGatewayAPIVersion}
	methods := []string{http.MethodPut, http.MethodPut, http.MethodPut, http.MethodGet, http.MethodDelete}
	for index, request := range requests {
		route := parseRoute(strings.Split(strings.TrimPrefix(request.Path, "/"), "/"))
		query := request.Query["api-version"]
		if route.collection != routes[index] || route.group != "ipsec" ||
			len(query) != 1 || query[0] != versions[index] || request.Method != methods[index] {
			t.Fatalf("unexpected route for %s %s: %#v", request.Method, request.Path, route)
		}
	}
	address := ResourceAddress{Group: "ipsec"}
	address.Path = VPNVirtualGatewayType + "/cloud"
	gateway, err := readVPNVirtualGateway(bytes.NewReader(requests[0].Body), scope, address, region)
	if err != nil || gateway.Address != address || gateway.IPConfigName != "vnetGatewayConfig0" ||
		gateway.PublicIP.Path != "Microsoft.Network/publicIPAddresses/cloudip" ||
		gateway.Subnet.Path != "Microsoft.Network/virtualNetworks/cloudnet/subnets/GatewaySubnet" {
		t.Fatalf("unexpected VPN gateway or invalid CLI properties: %v", err)
	}
	for _, changed := range []string{
		strings.Replace(string(requests[0].Body), `"activeActive": false`, `"activeActive": true`, 1),
		strings.Replace(string(requests[0].Body), "/subnets/GatewaySubnet", "/subnets/workloads", 1),
	} {
		if _, err := readVPNVirtualGateway(strings.NewReader(changed), scope, address, region); err == nil {
			t.Fatal("accepted a VPN gateway with unsupported topology")
		}
	}
	address.Path = VPNLocalGatewayType + "/peer"
	local, err := readVPNLocalGateway(bytes.NewReader(requests[1].Body), address, region)
	if err != nil || local.Address != address || local.Peer.Endpoint != netip.MustParseAddr("198.51.100.7") ||
		len(local.Peer.Prefixes) != 1 || local.Peer.Prefixes[0] != netip.MustParsePrefix("10.55.0.0/24") {
		t.Fatalf("unexpected local gateway or invalid CLI properties: %v", err)
	}
	if changed := bytes.Replace(requests[1].Body, []byte("198.51.100.7"), []byte("10.55.0.7"), 1); !bytes.Equal(changed, requests[1].Body) {
		if _, err := readVPNLocalGateway(bytes.NewReader(changed), address, region); err == nil {
			t.Fatal("accepted a peer endpoint inside a customer prefix")
		}
	} else {
		t.Fatal("the local gateway fixture does not contain the peer address")
	}
	deployment := requests[2]
	route := parseRoute(strings.Split(strings.TrimPrefix(deployment.Path, "/"), "/"))
	address.Path = deploymentType + "/" + route.name
	var releasedKey []byte
	store := testVPNStore{deploy: func(_ context.Context, gotScope SubscriptionScope, actor string, desired VPNConnectionDeployment, commit bool) (VPNChangeResult, error) {
		if gotScope != scope || actor != "owner" || !commit || desired.Deployment != address ||
			desired.Address.Path != VPNConnectionType+"/tunnel" || desired.VirtualGateway != gateway.Address || desired.LocalGateway != local.Address ||
			string(desired.SharedKey) != "disposable-ipsec-test-key" {
			t.Fatal("the pinned CLI template produced unexpected desired state")
		}
		releasedKey = desired.SharedKey
		return VPNChangeResult{}, ErrGatewayExecutionUnavailable
	}}
	server := Server{Location: region, VPN: store}
	put := func(body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, deployment.Path+"?api-version="+resourceAPIVersion, bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.deployment(t.Context(), w, r, scope, "owner", "", route.group, route.name)
		return w
	}
	w := put(deployment.Body)
	if w.Code != http.StatusServiceUnavailable || len(releasedKey) == 0 || !bytes.Equal(releasedKey, make([]byte, len(releasedKey))) ||
		strings.Contains(w.Body.String(), "disposable-ipsec-test-key") {
		t.Fatal("the deployment did not release its credential securely after regional dispatch")
	}
	for _, edit := range []struct{ name, from, to string }{
		{"foreign gateway", subscription, "8a95b237-0c3b-4bb1-9c5f-34ce786e8b48"},
		{"cross-group gateway", "/resourceGroups/ipsec/", "/resourceGroups/another/"},
		{"BGP", `"enableBgp": false`, `"enableBgp": true`},
		{"policy selectors", `"usePolicyBasedTrafficSelectors": false`, `"usePolicyBasedTrafficSelectors": true`},
		{"credential in outputs", "[reference('tunnel')]", "[parameters('sharedKey')]"},
		{"unsupported protocol", `"connectionType": "IPSec"`, `"connectionType": "Vnet2Vnet"`},
		{"unexpected property", `"routingWeight"`, `"unsupportedProperty"`},
	} {
		t.Run(edit.name, func(t *testing.T) {
			changed := bytes.Replace(deployment.Body, []byte(edit.from), []byte(edit.to), 1)
			if bytes.Equal(changed, deployment.Body) {
				t.Fatal("the fixture does not contain the field under test")
			}
			w := put(changed)
			if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "disposable-ipsec-test-key") {
				t.Fatalf("unexpected response from the rejected VPN template: HTTP %d", w.Code)
			}
		})
	}
}

type testVPNStore struct {
	VPNStore
	deploy func(context.Context, SubscriptionScope, string, VPNConnectionDeployment, bool) (VPNChangeResult, error)
}

func (s testVPNStore) DeployVPNConnection(ctx context.Context, scope SubscriptionScope, actor string,
	desired VPNConnectionDeployment, commit bool) (VPNChangeResult, error) {
	return s.deploy(ctx, scope, actor, desired, commit)
}
