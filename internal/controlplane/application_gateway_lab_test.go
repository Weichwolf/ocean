//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
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

func TestApplicationGatewayReservations(t *testing.T) {
	if os.Getenv("OCEAN_E2E_GATEWAY_RESERVATION") != "1" {
		t.Skip("requires a disposable regional etcd cluster")
	}
	r := openLabRegion(t)
	name := "appgw-test-" + operationID()
	r.root = "/ocean/v1/regions/" + name
	r.keys, r.values = initialRecords(r.root, name, "cell-1")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if _, err := r.client.Delete(ctx, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	r.publicIPv4 = []netip.Addr{netip.MustParseAddr("198.51.100.20")}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ingress.key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	r.gatewayControl, err = openGatewayControl(&applicationGatewayConfig{
		CertificateKeyFile: keyPath, Slots: []gatewaySlot{{Name: "ingress-a", Hosts: []string{"gw-a", "gw-b"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	certA, certB := []byte("gw-a local fixture identity"), []byte("gw-b local fixture identity")
	for _, peer := range []struct {
		name string
		cert []byte
	}{{"gw-a", certA}, {"gw-b", certB}, {"gw-other", []byte("other local fixture identity")}} {
		lease, err := r.client.Grant(ctx, 90)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = r.client.Revoke(ctx, lease.ID)
		})
		host := enrollment.Host{HostID: peer.name, Roles: []string{"gateway"}, Cell: "cell-1", Pool: "lab", Certificate: peer.cert}
		live := enrollment.Availability{HostID: peer.name, Roles: host.Roles, Cell: host.Cell, Pool: host.Pool}
		hostData, _ := json.Marshal(host)
		liveData, _ := json.Marshal(live)
		if _, err := r.client.Txn(ctx).Then(clientv3.OpPut(r.hostKey("registered", peer.name), string(hostData)),
			clientv3.OpPut(r.hostKey("live", peer.name), string(liveData), clientv3.WithLease(lease.ID))).Commit(); err != nil {
			t.Fatal(err)
		}
	}
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	group := "gateway-fixture"
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: name, Tags: map[string]string{}}, "lab-owner"); err != nil {
		t.Fatal(err)
	}
	vnet := arm.ResourceAddress{Group: group, Path: "Microsoft.Network/virtualNetworks/workloads"}
	public := arm.ResourceAddress{Group: group, Path: network.PublicIPType + "/https"}
	put := func(address arm.ResourceAddress, version string, properties any) {
		t.Helper()
		data, _ := json.Marshal(properties)
		if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: address, APIVersion: version,
			Location: name, Properties: data, ProvisioningState: arm.OperationSucceeded}); err != nil {
			t.Fatal(err)
		}
	}
	put(vnet, network.VNetAPIVersion, network.VNetProperties{AddressSpace: network.AddressSpace{Prefixes: []string{"10.89.1.0/24"}},
		ProvisioningState: arm.OperationSucceeded, Subnets: []network.Subnet{
			network.NewSubnet(vnet.ID(scope), "service", network.SubnetProperties{AddressPrefix: "10.89.1.0/24"}),
		}})
	put(public, network.PublicIPAPIVersion, network.PublicIPAddressProperties{AllocationMethod: "Static", IPVersion: "IPv4",
		IdleTimeout: 4, ProvisioningState: arm.OperationSucceeded})
	tlsBundle := []byte("fixture envelope plaintext marker")
	desired := arm.ApplicationGatewayDeployment{
		ResourceAddress: arm.ResourceAddress{Group: group, Path: "Microsoft.Network/applicationGateways/public"},
		Deployment:      arm.ResourceAddress{Group: group, Path: "Microsoft.Resources/deployments/ag_deploy_fixture"},
		PublicIP:        public, Subnet: arm.ResourceAddress{Group: group, Path: vnet.Path + "/subnets/service"},
		Backend: netip.MustParseAddrPort("10.89.1.4:8080"), Location: name, CertificateName: "testCertificate",
		Certificate: network.HTTPSCertificate{Hostname: "ingress.ocean.test", PublicCertificate: []byte("fixture public data"), Bundle: tlsBundle},
	}
	started, err := r.DeployApplicationGateway(ctx, scope, "lab-owner", desired, true)
	if err != nil || started.Operation == nil || !started.Created {
		t.Fatalf("gateway reservation failed: %v", err)
	}
	replayed, err := r.DeployApplicationGateway(ctx, scope, "lab-owner", desired, true)
	if err != nil || replayed.Operation == nil || replayed.Operation.ID != started.Operation.ID || replayed.Created {
		t.Fatalf("gateway request retry changed its allocation: %v", err)
	}
	if _, err := r.DeleteGroup(ctx, scope, group, "lab-owner"); !errors.Is(err, arm.ErrGroupInUse) {
		t.Fatalf("resource group deletion bypassed the gateway reservation: %v", err)
	}
	record, err := r.client.Get(ctx, r.gatewayRecordKey(scope, desired.ResourceAddress))
	if err != nil || len(record.Kvs) != 1 || bytes.Contains(record.Kvs[0].Value, tlsBundle) {
		t.Fatal("the regional record did not protect private certificate material")
	}
	allowed, err := r.HTTPSAssignments(ctx, "gw-a", certA)
	if err != nil || len(allowed) != 1 || !bytes.Equal(allowed[0].CertificateBundle, tlsBundle) ||
		allowed[0].Generation != started.Operation.ID || allowed[0].PublicIPv4.String() != "198.51.100.20" {
		t.Fatalf("the approved host did not receive the desired state: %v", err)
	}
	if _, err := r.HTTPSAssignments(ctx, "gw-a", certB); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("a different host certificate read the assignment: %v", err)
	}
	unassigned, err := r.HTTPSAssignments(ctx, "gw-other", []byte("other local fixture identity"))
	if err != nil || len(unassigned) != 0 {
		t.Fatalf("an unassigned gateway saw another host's configuration: %v", err)
	}
	status := enrollment.HTTPSGatewayStatus{Generation: operationID(), Ready: true, OwnsAddress: true}
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-a", certA, "ingress-a", status); !errors.Is(err, enrollment.ErrGatewayAssignmentChanged) {
		t.Fatalf("a stale generation reported readiness: %v", err)
	}
	status.Generation = started.Operation.ID
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-a", certA, "ingress-a", status); err != nil {
		t.Fatal(err)
	}
	operation, err := r.GetOperation(ctx, scope, status.Generation)
	if err != nil || operation == nil || operation.Status != arm.OperationInProgress {
		t.Fatal("one ready gateway completed the operation")
	}
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-b", certB, "ingress-a", status); err != nil {
		t.Fatal(err)
	}
	operation, err = r.GetOperation(ctx, scope, status.Generation)
	if err != nil || operation == nil || operation.Status != arm.OperationInProgress {
		t.Fatal("two declared address owners completed the operation")
	}
	status.OwnsAddress = false
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-b", certB, "ingress-a", status); err != nil {
		t.Fatal(err)
	}
	operation, err = r.GetOperation(ctx, scope, status.Generation)
	if err != nil || operation == nil || operation.Status != arm.OperationSucceeded {
		t.Fatal("one owner and two ready gateways did not complete the operation")
	}
	deployment, err := r.GetInventoryResource(ctx, scope, "", desired.Deployment)
	if err != nil || deployment == nil || deployment.ProvisioningState != arm.OperationSucceeded ||
		!bytes.Contains(deployment.Properties, []byte(`"applicationGateway"`)) || bytes.Contains(deployment.Properties, tlsBundle) {
		t.Fatal("the deployment did not expose a redacted terminal result")
	}
	deletion, err := r.DeleteApplicationGateway(ctx, scope, "lab-owner", desired.ResourceAddress)
	if err != nil || deletion == nil || deletion.Status != arm.OperationInProgress {
		t.Fatalf("request gateway deletion: %v", err)
	}
	repeatedDelete, err := r.DeleteApplicationGateway(ctx, scope, "lab-owner", desired.ResourceAddress)
	if err != nil || repeatedDelete == nil || repeatedDelete.ID != deletion.ID {
		t.Fatalf("gateway deletion retry changed its generation: %v", err)
	}
	pendingRemoval, err := r.GetInventoryResource(ctx, scope, "", desired.ResourceAddress)
	if err != nil || pendingRemoval == nil || pendingRemoval.ProvisioningState != "Deleting" {
		t.Fatal("the inventory did not reflect the accepted gateway deletion")
	}
	teardown, err := r.HTTPSAssignments(ctx, "gw-a", certA)
	if err != nil || len(teardown) != 1 || !teardown[0].Delete || teardown[0].Generation != deletion.ID ||
		len(teardown[0].CertificateBundle) != 0 {
		t.Fatalf("the gateway did not receive the expected teardown assignment: %v", err)
	}
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-a", certA, "ingress-a", status); !errors.Is(err, enrollment.ErrGatewayAssignmentChanged) {
		t.Fatalf("the superseded generation could still report readiness: %v", err)
	}
	removed := enrollment.HTTPSGatewayStatus{Generation: deletion.ID, Removed: true}
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-a", certA, "ingress-a", removed); err != nil {
		t.Fatal(err)
	}
	operation, err = r.GetOperation(ctx, scope, deletion.ID)
	if err != nil || operation == nil || operation.Status != arm.OperationInProgress {
		t.Fatal("one removal receipt released the gateway")
	}
	if err := r.ReportHTTPSGatewayStatus(ctx, "gw-b", certB, "ingress-a", removed); err != nil {
		t.Fatal(err)
	}
	operation, err = r.GetOperation(ctx, scope, deletion.ID)
	if err != nil || operation == nil || operation.Status != arm.OperationSucceeded {
		t.Fatal("both removal receipts did not complete the deletion")
	}
	liveGateway, err := r.GetInventoryResource(ctx, scope, "", desired.ResourceAddress)
	if err != nil || liveGateway != nil {
		t.Fatal("a removed gateway still appeared in the resource group")
	}
	if repeated, err := r.DeleteApplicationGateway(ctx, scope, "lab-owner", desired.ResourceAddress); err != nil || repeated != nil {
		t.Fatal("repeating a completed deletion created another operation")
	}
	desired.Deployment.Path = "Microsoft.Resources/deployments/ag_deploy_recycled"
	recycled, err := r.DeployApplicationGateway(ctx, scope, "lab-owner", desired, true)
	if err != nil || recycled.Operation == nil || recycled.Operation.ID == started.Operation.ID {
		t.Fatalf("gateway teardown did not release reusable reservations: %v", err)
	}
	t.Log("etcd reserved one slot and subnet, encrypted certificates, scoped assignments, gated success on one owner, and released capacity after both removals")
}
