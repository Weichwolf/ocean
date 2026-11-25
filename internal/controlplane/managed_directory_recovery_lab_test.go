//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

func testDirectoryPairRecovery(t *testing.T, ctx context.Context, r *Region, tenant identity.TenantReservation, id string,
	ready enrollment.DirectoryHealth, authority ed25519.PrivateKey, seedSpare func()) {
	t.Helper()
	key := r.managedDirectoryPlacementKey(tenant.TenantID)
	readPlacement := func() directoryPlacement {
		t.Helper()
		current, err := r.client.Get(ctx, key)
		var placement directoryPlacement
		if err != nil || current.Count != 1 || json.Unmarshal(current.Kvs[0].Value, &placement) != nil {
			t.Fatalf("could not read recovery placement: %v", err)
		}
		return placement
	}
	old := readPlacement()
	join := enrollment.DirectoryJoinInput{ID: operationID(), Machine: "FIXTUREPC", ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Password: "Fixture9-" + strings.Repeat("M", 32)}
	if view, err := r.RequestDirectoryJoin(ctx, tenant, join); err != nil || view.State != identity.DirectoryJoinPending {
		t.Fatalf("could not stage a pre-recovery join: %+v %v", view, err)
	}
	fence := identity.DirectoryRecoveryFence{Action: identity.RecoverDirectory, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, RecoveryID: operationID(), DirectoryID: id,
		BackupSHA256: strings.Repeat("a", 64), Observation: "PoweredOff", ObservedAt: time.Now().UTC()}
	for _, controller := range old.Controllers {
		fence.Controllers = append(fence.Controllers, identity.DirectoryRecoveryController{
			HostID: controller.HostID, PlacementID: controller.ID, Generation: controller.Generation})
	}
	sign := func(fence identity.DirectoryRecoveryFence) identity.SignedDirectoryFence {
		raw, _ := json.Marshal(fence)
		return identity.SignedDirectoryFence{Attestation: raw, Signature: ed25519.Sign(authority, raw)}
	}
	admit := func() (*identity.DirectoryRecovery, error) {
		return r.RequestDirectoryRecovery(ctx, tenant, fence.RecoveryID, sign(fence))
	}
	if _, err := r.client.Delete(ctx, r.hostKey("live", old.Controllers[0].HostID)); err != nil {
		t.Fatal(err)
	}
	if _, err := admit(); !errors.Is(err, identity.ErrDirectoryFencePending) {
		t.Fatalf("one surviving host did not block pair recovery: %v", err)
	}
	if _, err := r.client.Delete(ctx, r.hostKey("live", old.Controllers[1].HostID)); err != nil {
		t.Fatal(err)
	}
	incorrect := fence
	incorrect.Controllers = append([]identity.DirectoryRecoveryController(nil), fence.Controllers...)
	incorrect.Controllers[1].Generation = operationID()
	if _, err := r.RequestDirectoryRecovery(ctx, tenant, fence.RecoveryID, sign(incorrect)); !errors.Is(err, identity.ErrDirectoryFenceDenied) {
		t.Fatalf("a stale controller generation was accepted: %v", err)
	}
	for i := 0; i < 2; i++ {
		if view, err := admit(); err != nil || view.State != identity.DirectoryRecoveryFenced {
			t.Fatalf("pair fence did not converge: %+v %v", view, err)
		}
	}
	if view, err := r.LookupDirectoryJoin(ctx, tenant, join.ID); err != nil || view.State != identity.DirectoryJoinRevoked || view.UPN != "" {
		t.Fatalf("old pending delegation remained visible as active: %+v %v", view, err)
	}
	for _, controller := range old.Controllers {
		if err := r.CommitDirectoryIdentity(ctx, controller.HostID, []byte(controller.HostID), tenant.TenantID, controller.Generation, ready.DomainSID); !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatalf("a retired generation received startup approval: %v", err)
		}
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); !errors.Is(err, ErrNoEligibleHost) || readPlacement().Controllers != old.Controllers {
		t.Fatalf("recovery used incomplete capacity: %v", err)
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	tenantUsage, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
	if err != nil {
		t.Fatal(err)
	}
	seedSpare()
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
	placed := readPlacement()
	writer, replica := placed.Controllers[0], placed.Controllers[1]
	if placed.Recovery != fence.RecoveryID || placed.writerSlot() != 0 || placed.Names[0] == placed.Names[1] ||
		writer.HostID != "host-g" || replica.HostID != "host-h" ||
		writer.PrivateIPv4 != old.Controllers[0].PrivateIPv4 || replica.PrivateIPv4 != old.Controllers[1].PrivateIPv4 ||
		writer.Generation == old.Controllers[0].Generation || replica.Generation == old.Controllers[1].Generation {
		t.Fatalf("invalid recovery placement: %+v", placed)
	}
	if view, err := r.LookupDirectoryRecovery(ctx, tenant, fence.RecoveryID); err != nil ||
		view.State != identity.DirectoryRecoveryStaged || view.Writer != writer.HostID || view.BackupSHA != fence.BackupSHA256 {
		t.Fatalf("invalid recovery destination: %+v %v", view, err)
	}
	if after, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage"); err != nil || after.used != tenantUsage.used {
		t.Fatalf("recovery changed the tenant quota charge: %+v %v", after, err)
	}
	page, err := r.HostAssignments(ctx, writer.HostID, []byte(writer.HostID), "")
	if err != nil || len(page.Assignments) != 1 || page.Assignments[0].Directory.RecoverySHA256 != fence.BackupSHA256 ||
		page.Assignments[0].Directory.RecoveryID != fence.RecoveryID || page.Assignments[0].Directory.ControllerNames != placed.Names {
		t.Fatalf("the recovery task is not bound to the assigned writer: %+v %v", page, err)
	}
	bootstrap := func(host Reservation) (enrollment.DirectoryBootstrap, error) {
		return r.HostDirectoryBootstrap(ctx, host.HostID, []byte(host.HostID), tenant.TenantID, host.Generation)
	}
	writerKeys, err := bootstrap(writer)
	defer clear(writerKeys.Credential)
	if err != nil || !bytes.HasPrefix(writerKeys.Credential, []byte("Ocn9-")) || writerKeys.DomainSID != ready.DomainSID {
		t.Fatalf("the writer did not receive its recovery bootstrap: %v", err)
	}
	if keys, err := bootstrap(replica); len(keys.Credential) != 0 || !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
		t.Fatalf("the unstarted writer released a join credential: %v", err)
	}
	report := func(host Reservation) {
		t.Helper()
		if err := r.ReportDirectoryHealth(ctx, host.HostID, []byte(host.HostID), tenant.TenantID, host.Generation, ready); err != nil {
			t.Fatal(err)
		}
	}
	report(writer)
	replicaKeys, err := bootstrap(replica)
	defer clear(replicaKeys.Credential)
	if err != nil || !bytes.Equal(writerKeys.Credential, replicaKeys.Credential) {
		t.Fatalf("the replica did not receive the new join credential after writer health: %v", err)
	}
	if _, err := r.HostDirectoryGraphTask(ctx, writer.HostID, []byte(writer.HostID), tenant.TenantID, writer.Generation); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("Graph resumed before both controllers reported ready: %v", err)
	}
	report(replica)
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	if view, err := admit(); err != nil || view.State != identity.DirectoryRecoveryReady {
		t.Fatalf("the completed recovery did not replay: %+v %v", view, err)
	}
	if keys, err := bootstrap(writer); err != nil || len(keys.Credential) != 0 {
		t.Fatalf("the recovered writer still received a first-start secret: %v", err)
	}
	state, err := r.LookupManagedDirectory(ctx, tenant)
	if err != nil || state == nil || !state.Controllers[0].Writer || !state.Controllers[0].Ready || !state.Controllers[1].Ready ||
		state.Controllers[0].DNSName != placed.Names[0]+"."+state.Spec.DNSName {
		t.Fatalf("invalid ready projection: %+v %v", state, err)
	}
	if fresh, err := r.RequestDirectoryJoin(ctx, tenant, join); err != nil || fresh.State != identity.DirectoryJoinRevoked {
		t.Fatalf("a pre-recovery join could be reopened: %+v %v", fresh, err)
	}
	t.Log("Fenced both original generations, waited for two distinct hosts, rotated bootstrap credentials, revoked an old join, and completed only after two current SID observations.")
}
