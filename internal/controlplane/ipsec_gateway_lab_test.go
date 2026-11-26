//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestIPsecRegionalLifecycle(t *testing.T) {
	if os.Getenv("OCEAN_E2E_IPSEC_REGIONAL") != "1" {
		t.Skip("requires a disposable regional etcd cluster")
	}
	r := openLabRegion(t)
	name := "ipsec-test-" + operationID()
	r.root = "/ocean/v1/regions/" + name
	r.keys, r.values = initialRecords(r.root, name, "cell-1")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := r.client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	ctx, stop := context.WithTimeout(t.Context(), time.Minute)
	defer stop()
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	public := netip.MustParseAddr("198.18.24.1")
	slot := ipsecSlot{Name: "lab-vpn", Host: "gw-a", TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		PublicIPv4: public, InsideIPv4: netip.MustParsePrefix("10.91.1.1/24")}
	key := make([]byte, 32)
	rand.Read(key)
	path := filepath.Join(t.TempDir(), "seal.key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	clear(key)
	r.publicIPv4 = []netip.Addr{public}
	var err error
	r.ipsec, err = openIPsec(&ipsecConfig{SharedKeyEnvelopeFile: path, Slots: []ipsecSlot{slot},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.231.1.0/24")}}, r.publicIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	const group, actor = "ipsec-lab", "lab-owner"
	cert := []byte("local fixture certificate for gw-a")
	otherCert := []byte("local fixture certificate for gw-other")
	ipsecFixtureHost(t, ctx, r, slot.Host, cert)
	ipsecFixtureHost(t, ctx, r, "gw-other", otherCert)
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: name, Tags: map[string]string{}}, actor); err != nil {
		t.Fatal(err)
	}
	address := func(path string) arm.ResourceAddress { return arm.ResourceAddress{Group: group, Path: path} }
	vnet := address("Microsoft.Network/virtualNetworks/tenant")
	publicIP := address(network.PublicIPType + "/vpn-ip")
	gateway := address(arm.VPNVirtualGatewayType + "/cloud")
	local := address(arm.VPNLocalGatewayType + "/site")
	connection := address(arm.VPNConnectionType + "/tunnel")
	subnet := address(vnet.Path + "/subnets/GatewaySubnet")
	networkProperties := network.VNetProperties{AddressSpace: network.AddressSpace{Prefixes: []string{"10.91.0.0/16"}},
		ProvisioningState: arm.OperationSucceeded, Subnets: []network.Subnet{
			{Name: "GatewaySubnet", Properties: network.SubnetProperties{AddressPrefix: "10.91.0.0/24"}},
			{Name: "apps", Properties: network.SubnetProperties{AddressPrefix: slot.InsideIPv4.Masked().String()}},
		}}
	resources := []arm.InventoryResource{
		{Address: vnet, APIVersion: network.VNetAPIVersion, Location: name, Properties: ipsecFixtureJSON(t, networkProperties)},
		{Address: publicIP, APIVersion: network.PublicIPAPIVersion, Location: name, SKU: arm.ResourceSKU{Name: "Standard"},
			Properties: ipsecFixtureJSON(t, network.PublicIPAddressProperties{AllocationMethod: "Static", IPVersion: "IPv4",
				ProvisioningState: arm.OperationSucceeded})},
	}
	for _, resource := range resources {
		if err := r.PutInventoryResource(ctx, scope, resource); err != nil {
			t.Fatal(err)
		}
	}
	request := arm.VPNVirtualGatewayRequest{Address: gateway, PublicIP: publicIP, Subnet: subnet, Location: name, IPConfigName: "vnetGatewayConfig0"}
	created, err := r.PutVPNVirtualGateway(ctx, scope, actor, request)
	if err != nil || !created.Created || created.Operation == nil {
		t.Fatalf("could not reserve a pending regional IPsec gateway: %v", err)
	}
	same, err := r.PutVPNVirtualGateway(ctx, scope, actor, request)
	if err != nil || same.Created || same.Operation == nil || same.Operation.ID != created.Operation.ID {
		t.Fatalf("gateway replay did not preserve its operation: %v", err)
	}
	if _, err := r.DeleteGroup(ctx, scope, group, actor); !errors.Is(err, arm.ErrGroupInUse) {
		t.Fatalf("resource group deletion bypassed the live gateway: %v", err)
	}
	if err := r.ReportIPsecStatus(ctx, slot.Host, otherCert, slot.Name, enrollment.IPsecStatus{Generation: created.Operation.ID, Ready: true}); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("a foreign certificate was able to report gateway readiness: %v", err)
	}
	report := func(op *arm.Operation, ready, connected, removed bool) {
		t.Helper()
		if err := r.ReportIPsecStatus(ctx, slot.Host, cert, slot.Name, enrollment.IPsecStatus{
			Generation: op.ID, Ready: ready, Connected: connected, Removed: removed}); err != nil {
			t.Fatal(err)
		}
	}
	assertOperation := func(op *arm.Operation, expected string) {
		t.Helper()
		got, err := r.GetOperation(ctx, scope, op.ID)
		if err != nil || got == nil || got.Status != expected {
			t.Fatalf("IPsec operation %s did not reach %s: %v", op.Kind, expected, err)
		}
	}
	assertOperation(created.Operation, arm.OperationInProgress)
	report(created.Operation, true, false, false)
	assertOperation(created.Operation, arm.OperationSucceeded)
	peer := network.IPsecPeer{Endpoint: netip.MustParseAddr("198.18.24.2"), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.92.1.0/24")}}
	if _, err := r.PutVPNLocalGateway(ctx, scope, actor, arm.VPNLocalGatewayRequest{
		Address: local, Location: name, Peer: peer}); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	defer clear(secret)
	deploy := arm.VPNConnectionDeployment{Address: connection, Deployment: address("Microsoft.Resources/deployments/ipsec-first"),
		VirtualGateway: gateway, LocalGateway: local, Location: name, SharedKey: secret}
	overlap := address(arm.VPNLocalGatewayType + "/overlap")
	if _, err := r.PutVPNLocalGateway(ctx, scope, actor, arm.VPNLocalGatewayRequest{
		Address: overlap, Location: name, Peer: network.IPsecPeer{Endpoint: peer.Endpoint,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.91.0.0/24")}}}); err != nil {
		t.Fatal(err)
	}
	bad := deploy
	bad.LocalGateway = overlap
	var invalid arm.InvalidDeployment
	if _, err := r.DeployVPNConnection(ctx, scope, actor, bad, true); !errors.As(err, &invalid) {
		t.Fatalf("the regional provider accepted a peer prefix overlapping GatewaySubnet: %v", err)
	}
	if validated, err := r.DeployVPNConnection(ctx, scope, actor, deploy, false); err != nil || validated.Operation != nil {
		t.Fatalf("read-only validation failed: %v", err)
	}
	if state, err := r.GetVPNResource(ctx, scope, "", connection); err != nil || state != nil {
		t.Fatalf("template validation mutated the connection: %v", err)
	}
	first, err := r.DeployVPNConnection(ctx, scope, actor, deploy, true)
	if err != nil || first.Operation == nil {
		t.Fatalf("could not create the regional IPsec connection: %v", err)
	}
	retry := deploy
	retry.Deployment = address("Microsoft.Resources/deployments/ipsec-retry")
	replayed, err := r.DeployVPNConnection(ctx, scope, actor, retry, true)
	if err != nil || replayed.Operation == nil || replayed.Operation.ID != first.Operation.ID {
		t.Fatalf("a retry under a new CLI deployment name duplicated the operation: %v", err)
	}
	retry.SharedKey = bytes.Repeat([]byte{0x65}, 32)
	if _, err := r.DeployVPNConnection(ctx, scope, actor, retry, true); err == nil {
		t.Fatal("a retry replaced the key of an existing VPN connection")
	}
	if _, err := r.DeleteVPNResource(ctx, scope, actor, local); !errors.Is(err, arm.ErrLinkedResourceInUse) {
		t.Fatalf("local gateway deletion bypassed its connection: %v", err)
	}
	if tasks, err := r.IPsecAssignments(ctx, "gw-other", otherCert); err != nil || len(tasks) != 0 {
		t.Fatalf("an unassigned gateway host received a task: %v", err)
	}
	tasks, err := r.IPsecAssignments(ctx, slot.Host, cert)
	if err != nil || len(tasks) != 1 || !bytes.Equal(tasks[0].SharedKey, secret) {
		t.Fatalf("the authenticated assignment did not contain the sealed desired key: %v", err)
	}
	clear(tasks[0].SharedKey)
	assertNoKey := func() {
		t.Helper()
		records, err := r.client.Get(ctx, r.root+"/", clientv3.WithPrefix())
		if err != nil {
			t.Fatal(err)
		}
		base64Key := []byte(base64.StdEncoding.EncodeToString(secret))
		for _, record := range records.Kvs {
			if bytes.Contains(record.Value, secret) || bytes.Contains(record.Value, base64Key) {
				t.Fatal("plaintext IPsec credential reached durable regional state")
			}
		}
	}
	assertNoKey()
	expectStatus := func(expected string) {
		t.Helper()
		got, err := r.GetVPNResource(ctx, scope, "", connection)
		var properties struct {
			Status string `json:"connectionStatus"`
		}
		if err != nil || got == nil || json.Unmarshal(got.Properties, &properties) != nil || properties.Status != expected {
			t.Fatalf("IPsec connection status did not agree with the fresh worker observation: %s, %v", expected, err)
		}
	}
	report(first.Operation, true, false, false)
	assertOperation(first.Operation, arm.OperationSucceeded)
	expectStatus("NotConnected")
	report(first.Operation, true, true, false)
	expectStatus("Connected")
	if _, err := r.GetVPNResource(ctx, scope, "unassigned-reader", connection); !errors.Is(err, arm.ErrRoleDenied) {
		t.Fatalf("group-scoped reader authorization was bypassed: %v", err)
	}
	for _, item := range []arm.ResourceAddress{deploy.Deployment, replayed.Resource.Address} {
		result, err := r.GetInventoryResource(ctx, scope, "", item)
		if err != nil || result == nil || result.ProvisioningState != arm.OperationSucceeded || !bytes.Contains(result.Properties, []byte(`"outputs"`)) {
			t.Fatalf("a replayed deployment did not receive its ARM output: %v", err)
		}
	}
	time.Sleep(4100 * time.Millisecond)
	expectStatus("NotConnected")
	dispose, err := r.DeleteVPNResource(ctx, scope, actor, connection)
	if err != nil || dispose == nil {
		t.Fatalf("connection teardown did not start: %v", err)
	}
	if err := r.ReportIPsecStatus(ctx, slot.Host, cert, slot.Name, enrollment.IPsecStatus{
		Generation: first.Operation.ID, Ready: true, Connected: true}); !errors.Is(err, enrollment.ErrGatewayAssignmentChanged) {
		t.Fatalf("a stale generation could refresh the withdrawn tunnel: %v", err)
	}
	tasks, err = r.IPsecAssignments(ctx, slot.Host, cert)
	if err != nil || len(tasks) != 1 || !tasks[0].Remove || tasks[0].ReleaseAddress || len(tasks[0].SharedKey) != 0 {
		t.Fatalf("the connection removal assignment was incorrect: %v", err)
	}
	report(dispose, false, false, true)
	assertOperation(dispose, arm.OperationSucceeded)
	if done, err := r.DeleteVPNResource(ctx, scope, actor, connection); done != nil || err != nil {
		t.Fatalf("connection deletion replay was not idempotent: %v", err)
	}
	end, err := r.DeleteVPNResource(ctx, scope, actor, gateway)
	if err != nil || end == nil {
		t.Fatalf("gateway teardown did not start: %v", err)
	}
	tasks, err = r.IPsecAssignments(ctx, slot.Host, cert)
	if err != nil || len(tasks) != 1 || !tasks[0].ReleaseAddress {
		t.Fatalf("the gateway teardown did not withdraw its public address: %v", err)
	}
	report(end, false, false, true)
	assertOperation(end, arm.OperationSucceeded)
	if tasks, err := r.IPsecAssignments(ctx, slot.Host, cert); err != nil || len(tasks) != 0 {
		t.Fatalf("a completed teardown left a slot assignment: %v", err)
	}
	if _, err := r.DeleteVPNResource(ctx, scope, actor, local); err != nil {
		t.Fatal(err)
	}
	assertNoKey()
	if _, err := r.DeleteGroup(ctx, scope, group, actor); err != nil {
		t.Fatalf("completed gateway teardown left a group reservation: %v", err)
	}
	t.Log("Live etcd preserved one operation across retries. The regional provider rejected overlapping routes, kept shared keys out of durable projections, expired stale peer status and released gateway claims after worker acknowledgement.")
}

func ipsecFixtureJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ipsecFixtureHost(t *testing.T, ctx context.Context, r *Region, name string, certificate []byte) {
	t.Helper()
	lease, err := r.client.Grant(ctx, 75)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := r.client.Revoke(cleanup, lease.ID); err != nil {
			t.Error(err)
		}
	})
	host := enrollment.Host{HostID: name, Cell: "cell-1", Pool: "lab", Roles: []string{"gateway"}, Certificate: certificate}
	live := enrollment.Availability{HostID: name, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles}
	_, err = r.client.Txn(ctx).Then(clientv3.OpPut(r.hostKey("registered", name), string(ipsecFixtureJSON(t, host))),
		clientv3.OpPut(r.hostKey("live", name), string(ipsecFixtureJSON(t, live)), clientv3.WithLease(lease.ID))).Commit()
	if err != nil {
		t.Fatal(err)
	}
}
