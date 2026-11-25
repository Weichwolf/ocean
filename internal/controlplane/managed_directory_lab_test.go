//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestManagedDirectoryReservation(t *testing.T) {
	endpoint := os.Getenv("OCEAN_E2E_DIRECTORY_ETCD")
	if endpoint == "" {
		t.Skip("requires a disposable etcd endpoint")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	region := &Region{client: client, name: "farm-1", root: "/ocean/tests/directory/" + operationID()}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := client.Delete(cleanup, region.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	}()
	seed := func(publish bool) (identity.TenantReservation, identity.DirectorySpec) {
		t.Helper()
		tenant := identity.TenantReservation{TenantID: operationID(), Administrator: operationID(),
			SubscriptionID: operationID(), Fingerprint: operationID()}
		if _, err := region.ReserveTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		sub := identity.Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
			DisplayName: "Directory Lab", Members: []string{tenant.Administrator}}
		if publish {
			if _, err := region.PublishSubscription(ctx, tenant, sub); err != nil {
				t.Fatal(err)
			}
		}
		scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
		if _, _, err := region.PutGroup(ctx, scope, arm.Group{Name: "lab", Location: region.name, Tags: map[string]string{}}, tenant.Administrator); err != nil {
			t.Fatal(err)
		}
		vnet := arm.ResourceAddress{Group: "lab", Path: "Microsoft.Network/virtualNetworks/directory"}
		properties, err := json.Marshal(network.VNetProperties{
			AddressSpace: network.AddressSpace{Prefixes: []string{"10.86.0.0/24"}}, ProvisioningState: "Succeeded",
			Subnets: []network.Subnet{network.NewSubnet(vnet.ID(scope), "office", network.SubnetProperties{AddressPrefix: "10.86.0.0/28"})},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := region.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: vnet, APIVersion: network.VNetAPIVersion,
			Location: region.name, ProvisioningState: "Succeeded", Properties: properties}); err != nil {
			t.Fatal(err)
		}
		return tenant, identity.DirectorySpec{DNSName: "ad.example.test", NetBIOSName: "OFFICE", SubnetID: vnet.ID(scope) + "/subnets/office"}
	}
	first, spec := seed(true)
	second, foreign := seed(true)
	unpublished, pending := seed(false)
	if _, err := region.RequestManagedDirectory(ctx, unpublished, pending); !errors.Is(err, identity.ErrDirectoryTenant) {
		t.Fatalf("unpublished tenant request returned %v", err)
	}
	if _, err := region.RequestManagedDirectory(ctx, first, foreign); !errors.Is(err, identity.ErrDirectorySubnet) {
		t.Fatalf("foreign subnet request returned %v", err)
	}
	missing := spec
	missing.SubnetID += "-missing"
	if _, err := region.RequestManagedDirectory(ctx, first, missing); !errors.Is(err, identity.ErrDirectorySubnet) {
		t.Fatalf("missing subnet request returned %v", err)
	}
	var requested [12]identity.ManagedDirectory
	var errs [12]error
	var writers sync.WaitGroup
	for i := range requested {
		writers.Go(func() { requested[i], errs[i] = region.RequestManagedDirectory(ctx, first, spec) })
	}
	writers.Wait()
	for i, directory := range requested {
		if errs[i] != nil || !directory.Valid(first) || directory != requested[0] {
			t.Fatalf("writer %d returned %+v (error %v)", i, directory, errs[i])
		}
	}
	spec.DNSName, spec.SubnetID = strings.ToUpper(spec.DNSName), strings.ToUpper(spec.SubnetID)
	if replay, err := region.RequestManagedDirectory(ctx, first, spec); err != nil || replay != requested[0] {
		t.Fatalf("the equivalent request did not replay: %+v %v", replay, err)
	}
	spec.NetBIOSName = "OTHER"
	if _, err := region.RequestManagedDirectory(ctx, first, spec); !errors.Is(err, identity.ErrDirectoryConflict) {
		t.Fatalf("conflicting directory request returned %v", err)
	}
	if directory, err := region.LookupManagedDirectory(ctx, second); err != nil || directory != nil {
		t.Fatalf("a second tenant could see the existing reservation: %+v %v", directory, err)
	}
	if directory, err := region.RequestManagedDirectory(ctx, second, foreign); err != nil || !directory.Valid(second) || directory.ID == requested[0].ID {
		t.Fatalf("an independent tenant could not request its own directory: %+v %v", directory, err)
	}
	if read, err := region.LookupManagedDirectory(ctx, first); err != nil || read == nil || *read != requested[0] {
		t.Fatalf("the accepted directory was not persisted: %+v %v", read, err)
	}
	forged := first
	forged.Administrator = second.Administrator
	if _, err := region.LookupManagedDirectory(ctx, forged); !errors.Is(err, identity.ErrDirectoryTenant) {
		t.Fatalf("forged registration lookup returned %v", err)
	}
	scope := arm.SubscriptionScope{TenantID: first.TenantID, SubscriptionID: first.SubscriptionID}
	events, err := client.Get(ctx, region.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	var changes int
	for _, item := range events.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(item.Value, &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == "Ocean.Identity/directories/write" {
			changes++
			if event.Actor != first.Administrator || event.Target != requested[0].ID || event.Outcome != "Accepted" {
				t.Fatalf("unexpected managed directory audit event %+v", event)
			}
		}
	}
	if changes != 1 {
		t.Fatalf("concurrent directory requests produced %d audit events", changes)
	}

	t.Run("controller pair", func(t *testing.T) {
		testManagedDirectoryPlacement(t, ctx, region, first, requested[0], second, foreign)
	})
}

func testManagedDirectoryPlacement(t *testing.T, ctx context.Context, r *Region, tenant identity.TenantReservation,
	directory identity.ManagedDirectory, second identity.TenantReservation, secondSpec identity.DirectorySpec) {
	t.Helper()
	r.cell = "cell-1"
	r.directoryCapacity = enrollment.Capacity{CPUMillis: 400, MemoryMiB: 384}
	keyFile := filepath.Join(t.TempDir(), "workloads.key")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{9}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	r.workloads, err = openWorkloadControl(&workloadConfig{SecretsKeyFile: keyFile,
		DefaultPlacement: PlacementPolicy{Pools: []string{"approved"}, Quota: enrollment.Capacity{CPUMillis: 800, MemoryMiB: 768}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapManagedDirectories(ctx); err != nil {
		t.Fatal(err)
	}
	configured := r.directoryCapacity
	r.directoryCapacity.MemoryMiB++
	if err := r.bootstrapManagedDirectories(ctx); err == nil {
		t.Fatal("another replica accepted conflicting directory settings")
	}
	r.directoryCapacity = configured
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if _, err := r.DeleteGroup(ctx, scope, "lab", tenant.Administrator); !errors.Is(err, arm.ErrGroupInUse) {
		t.Fatalf("the directory subnet hold did not protect its group: %v", err)
	}
	setPolicy := func(scope arm.SubscriptionScope, quota enrollment.Capacity) {
		t.Helper()
		if err := r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"approved"}, Quota: quota}); err != nil {
			t.Fatal(err)
		}
	}
	client := r.client
	lease, err := client.Grant(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = client.Revoke(cleanup, lease.ID)
	}()
	seedHost := func(id, pool string, networked bool) {
		t.Helper()
		host := enrollment.Host{HostID: id, Cell: r.cell, Pool: pool, Roles: []string{"compute"}, Certificate: []byte(id)}
		live := enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles,
			ContainerNetwork: networked, DirectoryRuntime: id != "host-e", Capacity: enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 2048}}
		registration, _ := json.Marshal(host)
		report, _ := json.Marshal(live)
		if _, err := client.Txn(ctx).Then(clientv3.OpPut(r.hostKey("registered", id), string(registration)),
			clientv3.OpPut(r.hostKey("live", id), string(report), clientv3.WithLease(lease.ID))).Commit(); err != nil {
			t.Fatal(err)
		}
	}
	assertUnplaced := func(scope arm.SubscriptionScope) {
		t.Helper()
		placement, err := client.Get(ctx, r.managedDirectoryPlacementKey(scope.TenantID), clientv3.WithCountOnly())
		if err != nil || placement.Count != 0 {
			t.Fatalf("a failed attempt published a pair: %v", err)
		}
		used, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
		if err != nil || used.used != (enrollment.Capacity{}) {
			t.Fatalf("a failed attempt billed tenant capacity: %+v %v", used, err)
		}
	}
	setPolicy(scope, configured)
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("one controller of quota returned %v", err)
	}
	assertUnplaced(scope)
	pairCapacity := addCapacity(configured, configured)
	setPolicy(scope, pairCapacity)
	seedHost("host-a", "approved", true)
	seedHost("host-b", "approved", false)
	seedHost("host-c", "outside", true)
	seedHost("host-d", "approved", true)
	seedHost("host-e", "approved", true)
	if err := r.SetHostDraining(ctx, "host-d", true); err != nil {
		t.Fatal(err)
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); !errors.Is(err, ErrNoEligibleHost) {
		t.Fatalf("one eligible controller host returned %v", err)
	}
	assertUnplaced(scope)
	if used, err := r.counter(ctx, r.hostKey("placement-usage", "host-a")); err != nil || used.used != (enrollment.Capacity{}) {
		t.Fatalf("a failed attempt billed host capacity: %+v %v", used, err)
	}
	seedHost("host-b", "approved", true)
	var placementErrs [8]error
	var workers sync.WaitGroup
	for i := range placementErrs {
		workers.Go(func() { placementErrs[i] = r.placeManagedDirectory(ctx, tenant.TenantID) })
	}
	workers.Wait()
	for i, err := range placementErrs {
		if err != nil {
			t.Fatalf("reconciler %d returned %v", i, err)
		}
	}
	result, err := client.Get(ctx, r.managedDirectoryPlacementKey(tenant.TenantID))
	var latest directoryPlacement
	if err != nil || len(result.Kvs) != 1 || json.Unmarshal(result.Kvs[0].Value, &latest) != nil || latest.DirectoryID != directory.ID {
		t.Fatalf("no controller pair matching the directory: %+v %v", latest, err)
	}
	left, right := latest.Controllers[0], latest.Controllers[1]
	if left.HostID != "host-a" || right.HostID != "host-b" || left.PrivateIPv4 == right.PrivateIPv4 ||
		!left.PrivateIPv4.Is4() || !right.PrivateIPv4.Is4() || left.Generation == right.Generation {
		t.Fatalf("invalid distinct placements %+v", latest.Controllers)
	}
	password, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation)
	if err != nil || !bytes.HasPrefix(password, []byte("Ocn9-")) || bytes.Equal(password, latest.Bootstrap) {
		t.Fatal("the assigned host could not recover the sealed bootstrap credential")
	}
	defer clear(password)
	retry, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation)
	if err != nil || !bytes.Equal(retry, password) {
		t.Fatal("a retry changed the directory bootstrap credential")
	}
	clear(retry)
	for _, request := range []struct{ host, certificate, generation string }{
		{left.HostID, "other-certificate", left.Generation},
		{left.HostID, left.HostID, right.Generation},
		{right.HostID, right.HostID, right.Generation},
	} {
		if secret, err := r.HostDirectoryBootstrap(ctx, request.host, []byte(request.certificate), tenant.TenantID, request.generation); secret != nil || !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatal("an unauthorized host or generation could read a bootstrap credential")
		}
	}
	if used, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage"); err != nil || used.used != pairCapacity {
		t.Fatalf("tenant capacity was not charged exactly once: %+v %v", used.used, err)
	}
	for i, reservation := range latest.Controllers {
		if used, err := r.counter(ctx, r.hostKey("placement-usage", reservation.HostID)); err != nil || used.used != configured {
			t.Fatalf("host capacity was not charged exactly once: %+v %v", used.used, err)
		}
		page, err := r.HostAssignments(ctx, reservation.HostID, []byte(reservation.HostID), "")
		if err != nil || len(page.Assignments) != 1 {
			t.Fatalf("controller assignment could not be read by its host: %+v %v", page, err)
		}
		assignment := page.Assignments[0]
		if assignment.Generation != reservation.Generation || assignment.PrivateIPv4 != reservation.PrivateIPv4 ||
			assignment.NetworkUnavailable || assignment.Network == nil || assignment.TenantID != tenant.TenantID {
			t.Fatalf("the assigned host received the wrong tenant network or generation: %+v", assignment)
		}
		controller := assignment.Directory
		if controller == nil || controller.DirectoryID != directory.ID || controller.ControllerIndex != i+1 ||
			controller.ControllerIPv4[0] != left.PrivateIPv4 || controller.ControllerIPv4[1] != right.PrivateIPv4 ||
			controller.DNSName != directory.Spec.DNSName || controller.NetBIOSName != directory.Spec.NetBIOSName {
			t.Fatalf("the host can not identify its own directory controller and peer: %+v", controller)
		}
		if _, err := r.HostAssignments(ctx, reservation.HostID, []byte("foreign-cert"), ""); !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatalf("a mismatched production certificate could read the assignment: %v", err)
		}
	}
	other := arm.SubscriptionScope{TenantID: second.TenantID, SubscriptionID: second.SubscriptionID}
	setPolicy(other, pairCapacity)
	parent, name, _ := arm.SubnetParent(other, secondSpec.SubnetID)
	for i := 4; i < 14; i++ {
		key := r.subnetNetworkPlacements(other, parent, name) + fmt.Sprintf("10.86.0.%d", i)
		if _, err := client.Put(ctx, key, "used"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.placeManagedDirectory(ctx, second.TenantID); !errors.Is(err, ErrSubnetAddressExhausted) {
		t.Fatalf("a subnet with only one available address returned %v", err)
	}
	assertUnplaced(other)
	request := PlacementRequest{ID: "ordinary-placement", Cell: r.cell, Role: "compute", Resources: configured,
		SubnetID: secondSpec.SubnetID, NeedsContainerNetwork: true}
	ordinary, err := r.ReservePlacement(ctx, other, request)
	if err != nil || ordinary.PrivateIPv4.String() != "10.86.0.14" {
		t.Fatalf("a failed pair consumed the final address or broke single placement: %+v %v", ordinary, err)
	}
	if err := r.ReleasePlacement(ctx, other, ordinary.Cell, ordinary.ID, ordinary.Generation); err != nil {
		t.Fatal(err)
	}
	assertUnplaced(other)
	// Make a second address available. The background controller must pick
	// up the pending request without another client submission.
	key := r.subnetNetworkPlacements(other, parent, name) + "10.86.0.13"
	if _, err := client.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	reconcile, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.reconcileManagedDirectories(reconcile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	defer func() {
		cancel()
		<-done
	}()
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		placed, err := client.Get(ctx, r.managedDirectoryPlacementKey(other.TenantID), clientv3.WithCountOnly())
		if err != nil {
			t.Fatal(err)
		}
		if placed.Count == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("the background controller did not place the pending directory")
		case <-timer.C:
		}
	}
	if err := r.RevokeHost(ctx, left.HostID); err != nil {
		t.Fatal(err)
	}
	if secret, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation); secret != nil || !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a revoked primary could recover the bootstrap credential")
	}
}
