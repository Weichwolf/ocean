//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	primary, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation)
	if err != nil || primary.DomainSID != "" || !bytes.HasPrefix(primary.Credential, []byte("Ocn9-")) || bytes.Equal(primary.Credential, latest.Bootstrap) {
		t.Fatal("the assigned host could not recover the sealed bootstrap credential")
	}
	defer clear(primary.Credential)
	retry, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation)
	if err != nil || !bytes.Equal(retry.Credential, primary.Credential) || retry.DomainSID != "" {
		t.Fatal("a retry changed the directory bootstrap credential")
	}
	clear(retry.Credential)
	peerBootstrap, err := r.HostDirectoryBootstrap(ctx, right.HostID, []byte(right.HostID), tenant.TenantID, right.Generation)
	if err != nil || !bytes.Equal(peerBootstrap.Credential, primary.Credential) {
		t.Fatal("the assigned replica could not read the expected bootstrap credential")
	}
	clear(peerBootstrap.Credential)
	for _, request := range []struct{ host, certificate, generation string }{
		{left.HostID, "other-certificate", left.Generation},
		{left.HostID, left.HostID, right.Generation},
		{right.HostID, right.HostID, left.Generation},
	} {
		if bootstrap, err := r.HostDirectoryBootstrap(ctx, request.host, []byte(request.certificate), tenant.TenantID, request.generation); bootstrap.Credential != nil || !errors.Is(err, enrollment.ErrHostDenied) {
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
	assertHealth := func(left, right, provisioned bool) {
		t.Helper()
		state, err := r.LookupManagedDirectory(ctx, tenant)
		if err != nil || state == nil || state.Controllers[0].Ready != left || state.Controllers[1].Ready != right ||
			(!state.ProvisionedAt.IsZero()) != provisioned || state.Controllers[0].DNSName != "dc01."+directory.Spec.DNSName ||
			state.Controllers[1].PrivateIPv4 != latest.Controllers[1].PrivateIPv4 {
			t.Fatalf("unexpected directory health %+v, error %v", state, err)
		}
	}
	const domainSID = "S-1-5-21-123-456-789"
	const differentSID = "S-1-5-21-123-456-999"
	commit := func(controller Reservation, sid string) error {
		return r.CommitDirectoryIdentity(ctx, controller.HostID, []byte(controller.HostID), tenant.TenantID, controller.Generation, sid)
	}
	ready := enrollment.DirectoryHealth{Ready: true, DomainSID: domainSID}
	report := func(controller Reservation, health enrollment.DirectoryHealth) {
		t.Helper()
		if err := r.ReportDirectoryHealth(ctx, controller.HostID, []byte(controller.HostID), tenant.TenantID, controller.Generation, health); err != nil {
			t.Fatal(err)
		}
	}
	assertHealth(false, false, false)
	if err := commit(right, domainSID); !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
		t.Fatal("an uninitialized replica committed a primary domain identity")
	}
	report(left, ready)
	assertHealth(false, false, false)
	if err := commit(left, domainSID); err != nil {
		t.Fatalf("initial primary could not commit its SID: %v", err)
	}
	if err := commit(left, domainSID); err != nil {
		t.Fatalf("startup retry could not confirm the same SID: %v", err)
	}
	if err := commit(left, differentSID); !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
		t.Fatal("the established primary could replace the fixed SID")
	}
	if err := commit(right, differentSID); !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
		t.Fatal("the replica confirmed a different SID")
	}
	if err := commit(right, domainSID); err != nil {
		t.Fatal(err)
	}
	reopen, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation)
	if err != nil || len(reopen.Credential) != 0 || reopen.DomainSID != domainSID {
		t.Fatal("the primary received a bootstrap credential after its domain SID was established")
	}
	if err := r.ReportDirectoryHealth(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, right.Generation, ready); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a host reported health of another controller")
	}
	if err := r.ReportDirectoryHealth(ctx, left.HostID, []byte(left.HostID), second.TenantID, left.Generation, ready); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a host reported health for another tenant")
	}
	report(left, ready)
	assertHealth(true, false, false)
	report(right, enrollment.DirectoryHealth{Ready: true, DomainSID: differentSID})
	assertHealth(true, false, false)
	report(right, ready)
	report(right, ready)
	assertHealth(true, true, true)
	events, err := client.Get(ctx, r.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	var provisioned int
	for _, item := range events.Kvs {
		var event arm.AuditEvent
		if json.Unmarshal(item.Value, &event) == nil && event.Action == "Ocean.Identity/directories/provision" &&
			event.Target == directory.ID && event.Outcome == "Succeeded" {
			provisioned++
		}
	}
	if provisioned != 1 {
		t.Fatalf("duplicate health report committed %d provisioning audit events", provisioned)
	}
	old, _ := json.Marshal(directoryObservation{DirectoryHealth: ready, ObservedAt: time.Now().Add(-enrollment.HostAvailabilityTTL - time.Second)})
	if _, err := client.Put(ctx, r.directoryObservationKey(tenant.TenantID, left.Generation), string(old), clientv3.WithLease(lease.ID)); err != nil {
		t.Fatal(err)
	}
	assertHealth(false, true, true)
	report(left, ready)
	report(right, enrollment.DirectoryHealth{Ready: true, DomainSID: differentSID})
	assertHealth(true, false, true)
	report(right, enrollment.DirectoryHealth{})
	assertHealth(true, false, true)
	report(right, ready)
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
	cancel()
	<-done
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.directoryFencer = public
	if err := r.bootstrapDirectoryFencing(ctx); err != nil {
		t.Fatal(err)
	}
	right = testDirectoryReplicaReplacement(t, ctx, r, tenant, directory.ID, left, right, ready, private)
	assertHealth(true, true, true)
	seedHost("host-f", "approved", true)
	testDirectoryPrimaryReplacement(t, ctx, r, tenant, directory, left, right, ready, private)
	if bootstrap, err := r.HostDirectoryBootstrap(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation); bootstrap.Credential != nil || !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a revoked primary could recover the bootstrap credential")
	}
	if err := r.ReportDirectoryHealth(ctx, left.HostID, []byte(left.HostID), tenant.TenantID, left.Generation, ready); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a revoked primary reported health")
	}
	if err := commit(left, domainSID); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("a revoked primary confirmed startup")
	}
	assertHealth(true, true, true)
}

func testDirectoryReplicaReplacement(t *testing.T, ctx context.Context, r *Region, tenant identity.TenantReservation,
	directoryID string, primary, retired Reservation, ready enrollment.DirectoryHealth, private ed25519.PrivateKey) Reservation {
	t.Helper()
	proof := identity.DirectoryReplicaFence{Action: identity.ReplaceDirectoryReplica, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DirectoryID: directoryID, HostID: retired.HostID, PlacementID: retired.ID,
		Generation: retired.Generation, Observation: "PoweredOff", ObservedAt: time.Now().UTC()}
	sign := func(proof identity.DirectoryReplicaFence) identity.SignedDirectoryFence {
		data, _ := json.Marshal(proof)
		return identity.SignedDirectoryFence{Attestation: data, Signature: ed25519.Sign(private, data)}
	}
	valid := sign(proof)
	if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, valid); !errors.Is(err, identity.ErrDirectoryFencePending) {
		t.Fatalf("a live replica accepted replacement: %v", err)
	}
	if _, err := r.client.Delete(ctx, r.hostKey("live", retired.HostID)); err != nil {
		t.Fatal(err)
	}
	assertPlacement := func(generation, repair string) directoryPlacement {
		t.Helper()
		current, err := r.client.Get(ctx, r.managedDirectoryPlacementKey(tenant.TenantID))
		var placement directoryPlacement
		if err != nil || len(current.Kvs) != 1 || json.Unmarshal(current.Kvs[0].Value, &placement) != nil ||
			placement.Controllers[0] != primary || placement.Controllers[1].Generation != generation || placement.Repair != repair {
			t.Fatalf("unexpected directory replacement placement: %+v, %v", placement, err)
		}
		return placement
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	assertPlacement(retired.Generation, "")
	withTime := proof
	withTime.ObservedAt = time.Now().Add(-3 * time.Minute)
	wrong := proof
	wrong.Generation = operationID()
	for _, evidence := range []identity.SignedDirectoryFence{
		{Attestation: valid.Attestation, Signature: make([]byte, ed25519.SignatureSize)}, sign(withTime), sign(wrong),
	} {
		if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, evidence); !errors.Is(err, identity.ErrDirectoryFenceDenied) {
			t.Fatalf("invalid fencing proof returned %v", err)
		}
	}
	if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, valid); err != nil {
		t.Fatal(err)
	}
	if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, valid); err != nil {
		t.Fatalf("retry of the accepted fence returned %v", err)
	}
	confirm := func(host Reservation) error {
		return r.ConfirmDirectoryReplicaRetirement(ctx, host.HostID, []byte(host.HostID), tenant.TenantID, host.Generation, retired.Generation)
	}
	if err := confirm(retired); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("retired host confirmed its own cleanup: %v", err)
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	page, err := r.HostAssignments(ctx, primary.HostID, []byte(primary.HostID), "")
	delivered := false
	for _, assignment := range page.Assignments {
		if assignment.TenantID == tenant.TenantID && assignment.Directory != nil && assignment.Directory.RetireReplica == retired.Generation {
			delivered = true
		}
	}
	if err != nil || !delivered {
		t.Fatal("the survivor did not receive the cleanup task")
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	assertPlacement(retired.Generation, retired.Generation)
	if err := confirm(primary); err != nil {
		t.Fatal(err)
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); !errors.Is(err, ErrNoEligibleHost) {
		t.Fatalf("replacement without a spare host returned %v", err)
	}
	assertPlacement(retired.Generation, retired.Generation)
	if err := r.SetHostDraining(ctx, "host-d", false); err != nil {
		t.Fatal(err)
	}
	usageBefore, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
	if err != nil {
		t.Fatal(err)
	}
	oldUsage, err := r.counter(ctx, r.hostKey("placement-usage", retired.HostID))
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var attempts [6]error
	for i := range attempts {
		workers.Go(func() { attempts[i] = r.placeManagedDirectory(ctx, tenant.TenantID) })
	}
	workers.Wait()
	for _, err := range attempts {
		if err != nil && !errors.Is(err, ErrNoEligibleHost) {
			t.Fatal(err)
		}
	}
	receipt, err := r.client.Get(ctx, r.directoryReplicaRepairKey(tenant.TenantID, retired.Generation))
	var repair directoryReplicaRepair
	if err != nil || len(receipt.Kvs) != 1 || json.Unmarshal(receipt.Kvs[0].Value, &repair) != nil ||
		repair.ReplacementGeneration == "" || repair.ReplacementGeneration == retired.Generation ||
		!ed25519.Verify(r.directoryFencer, repair.SignedFence.Attestation, repair.SignedFence.Signature) {
		t.Fatalf("no durable replacement receipt: %v", err)
	}
	replacement := assertPlacement(repair.ReplacementGeneration, "").Controllers[1]
	usageAfter, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
	if err != nil || usageAfter.used != usageBefore.used || replacement.HostID != "host-d" || replacement.PrivateIPv4 != retired.PrivateIPv4 {
		t.Fatalf("replacement changed tenant capacity or address: %+v, %v", replacement, err)
	}
	newUsage, err := r.counter(ctx, r.hostKey("placement-usage", replacement.HostID))
	oldRemaining, oldErr := r.counter(ctx, r.hostKey("placement-usage", retired.HostID))
	if err != nil || oldErr != nil || newUsage.used != retired.Resources || addCapacity(oldRemaining.used, retired.Resources) != oldUsage.used {
		t.Fatalf("replacement did not transfer exactly one host reservation: %v, %v", err, oldErr)
	}
	if err := confirm(primary); err != nil {
		t.Fatalf("the surviving controller could not retry the cleanup acknowledgement: %v", err)
	}
	if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, valid); err != nil {
		t.Fatalf("the signed request was not idempotent after placement: %v", err)
	}
	if _, err := r.HostDirectoryBootstrap(ctx, retired.HostID, []byte(retired.HostID), tenant.TenantID, retired.Generation); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatal("the retired placement still obtained its bootstrap")
	}
	bootstrap, err := r.HostDirectoryBootstrap(ctx, replacement.HostID, []byte(replacement.HostID), tenant.TenantID, replacement.Generation)
	defer clear(bootstrap.Credential)
	if err != nil || bootstrap.DomainSID != ready.DomainSID || len(bootstrap.Credential) == 0 {
		t.Fatalf("the new replica did not receive its established identity and join credential: %v", err)
	}
	if err := r.CommitDirectoryIdentity(ctx, replacement.HostID, []byte(replacement.HostID), tenant.TenantID, replacement.Generation, ready.DomainSID); err != nil {
		t.Fatal(err)
	}
	if err := r.ReportDirectoryHealth(ctx, replacement.HostID, []byte(replacement.HostID), tenant.TenantID, replacement.Generation, ready); err != nil {
		t.Fatal(err)
	}
	t.Logf("Rejected invalid power evidence and withheld placement until survivor acknowledgement. Transferred %s from %s to %s with a new generation and unchanged tenant capacity.",
		replacement.PrivateIPv4, retired.HostID, replacement.HostID)
	return replacement
}

func testDirectoryPrimaryReplacement(t *testing.T, ctx context.Context, r *Region, tenant identity.TenantReservation,
	directory identity.ManagedDirectory, failed, survivor Reservation, ready enrollment.DirectoryHealth, key ed25519.PrivateKey) {
	t.Helper()
	proof := identity.DirectoryReplicaFence{Action: identity.ReplaceDirectoryPrimary, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DirectoryID: directory.ID, HostID: failed.HostID, PlacementID: failed.ID,
		Generation: failed.Generation, Observation: "PoweredOff", ObservedAt: time.Now().UTC()}
	data, _ := json.Marshal(proof)
	signed := identity.SignedDirectoryFence{Attestation: data, Signature: ed25519.Sign(key, data)}
	admit := func() error { return r.RequestDirectoryPrimaryReplacement(ctx, tenant, signed) }
	if err := admit(); !errors.Is(err, identity.ErrDirectoryFencePending) {
		t.Fatalf("the still-live primary could be replaced: %v", err)
	}
	if err := r.RequestDirectoryReplicaReplacement(ctx, tenant, signed); !errors.Is(err, identity.ErrDirectoryFenceDenied) {
		t.Fatalf("a primary attestation was accepted for ordinary replica replacement: %v", err)
	}
	if _, err := r.client.Delete(ctx, r.hostKey("live", failed.HostID)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Delete(ctx, r.directoryObservationKey(tenant.TenantID, survivor.Generation)); err != nil {
		t.Fatal(err)
	}
	if err := admit(); !errors.Is(err, identity.ErrDirectoryFencePending) {
		t.Fatalf("promotion accepted a survivor with no recent observation: %v", err)
	}
	report := func(controller Reservation) {
		t.Helper()
		if err := r.ReportDirectoryHealth(ctx, controller.HostID, []byte(controller.HostID), tenant.TenantID, controller.Generation, ready); err != nil {
			t.Fatal(err)
		}
	}
	report(survivor)
	if err := admit(); err != nil {
		t.Fatal(err)
	}
	confirm := func(host Reservation, certificate []byte) error {
		return r.ConfirmDirectoryReplicaRetirement(ctx, host.HostID, certificate, tenant.TenantID, host.Generation, failed.Generation)
	}
	if err := confirm(failed, []byte(failed.HostID)); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("the fenced writer was able to acknowledge its own replacement: %v", err)
	}
	if err := confirm(survivor, []byte(failed.HostID)); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("a foreign certificate acknowledged promotion: %v", err)
	}
	if err := confirm(survivor, []byte(survivor.HostID)); !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
		t.Fatalf("the survivor's pre-promotion health was reused: %v", err)
	}
	placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
	readPlacement := func() (directoryPlacement, int64) {
		t.Helper()
		rows, err := r.client.Get(ctx, placementKey)
		var state directoryPlacement
		if err != nil || rows.Count != 1 || json.Unmarshal(rows.Kvs[0].Value, &state) != nil {
			t.Fatalf("could not inspect promotion placement: %v", err)
		}
		return state, rows.Header.Revision
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	pending, rev := readPlacement()
	if !pending.Promoting || pending.writerSlot() != 1 || pending.Controllers != [2]Reservation{failed, survivor} {
		t.Fatalf("replacement moved a reservation before promotion: %+v", pending)
	}
	if _, _, err := r.readyDirectoryWriter(ctx, directory, rev); !errors.Is(err, identity.ErrDirectoryJoinUnavailable) {
		t.Fatalf("a directory mutation could choose a writer during promotion: %v", err)
	}
	if _, err := r.HostDirectoryGraphTask(ctx, survivor.HostID, []byte(survivor.HostID), tenant.TenantID, survivor.Generation); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("the prospective writer could read an unconfirmed Graph task: %v", err)
	}
	assignment := func(controller Reservation) enrollment.DirectoryAssignment {
		t.Helper()
		page, err := r.HostAssignments(ctx, controller.HostID, []byte(controller.HostID), "")
		if err == nil {
			for _, a := range page.Assignments {
				if a.Generation == controller.Generation && a.Directory != nil {
					return *a.Directory
				}
			}
		}
		t.Fatalf("missing controller assignment: %v", err)
		return enrollment.DirectoryAssignment{}
	}
	job := assignment(survivor)
	if !job.IsWriter() || job.PromoteFrom != failed.Generation || job.ControllerIndex != 2 {
		t.Fatalf("missing promotion authorization: %+v", job)
	}
	bootstrap, err := r.HostDirectoryBootstrap(ctx, survivor.HostID, []byte(survivor.HostID), tenant.TenantID, survivor.Generation)
	if err != nil || bootstrap.DomainSID != ready.DomainSID || len(bootstrap.Credential) != 0 {
		t.Fatalf("the promoted writer did not receive the established SID without a bootstrap credential: %v", err)
	}
	report(survivor)
	if err := confirm(survivor, []byte(survivor.HostID)); err != nil {
		t.Fatal(err)
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	current, rev := readPlacement()
	newReplica := current.Controllers[0]
	if current.Promoting || current.Repair != "" || current.Controllers[1] != survivor || newReplica.HostID != "host-f" ||
		newReplica.Generation == failed.Generation || newReplica.PrivateIPv4 != failed.PrivateIPv4 {
		t.Fatalf("bad slot-one replacement: %+v", current)
	}
	if a := assignment(newReplica); a.IsWriter() || a.ControllerIndex != 1 || a.WriterIndex != 2 || a.ControllerIPv4 != job.ControllerIPv4 {
		t.Fatalf("new DC01 was not assigned as the replica: %+v", a)
	}
	if a := assignment(survivor); !a.IsWriter() || a.PromoteFrom != "" {
		t.Fatalf("promotion was not cleared after replacement: %+v", a)
	}
	if writer, _, err := r.readyDirectoryWriter(ctx, directory, rev); err != nil || writer != survivor {
		t.Fatalf("the region did not route updates to the surviving writer: %v", err)
	}
	if err := admit(); err != nil {
		t.Fatalf("accepted primary fence did not replay after replacement: %v", err)
	}
	report(newReplica)
	t.Log("Primary fencing required fresh survivor health, withheld writer work and placement pending acknowledgement, then routed updates to DC02 and reserved a new read-only DC01.")
}
