//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func checkHostedPurgeView(t *testing.T, raw []byte, id, volume, state string) identity.HostedFilePurge {
	t.Helper()
	var view struct {
		identity.HostedFilePurge
		State string `json:"state"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || view.ID != id || view.VolumeID != volume || view.State != state ||
		!view.Valid(view.TenantID, id) || view.CompletedAt.IsZero() != (state == "Pending") {
		t.Fatalf("unexpected hosted deletion decision for %s: %v", state, err)
	}
	return view.HostedFilePurge
}

func verifyNativeHostedFilePurge(t *testing.T, ctx context.Context, r *Region, host enrollment.Host, share storageShareRecord, probe hostedPurgeProbe,
	az func(string, string, string, string) []byte, startStorage func(), run func(string, io.Reader), rbd string, removalRetried func() bool) {
	t.Helper()
	volume := share.Volume.ID
	image := "ocean/" + volume
	snapshot := image + "@hosted-retention-fixture"
	run("sudo "+rbd+" snap create "+snapshot, nil)
	az("put", probe.path, strings.Replace(probe.body, share.Scope.SubscriptionID+"/resourceGroups", operationID()+"/resourceGroups", 1), "InvalidShareId")
	decision := checkHostedPurgeView(t, az("put", probe.path, probe.body, ""), probe.id, volume, "Pending")
	if decision.ApprovalID != probe.approval || decision.ShareID != share.Address.ID(share.Scope) || decision.Worker != host.HostID {
		t.Fatal("the deletion decision did not preserve its approval, share and storage worker")
	}
	retry := checkHostedPurgeView(t, az("put", probe.path, probe.body, ""), probe.id, volume, "Pending")
	if !sameFilePurge(decision, retry) {
		t.Fatal("an identical deletion retry changed the authoritative decision")
	}
	az("put", probe.path, strings.Replace(probe.body, probe.approval, operationID(), 1), "FileShareDeletionConflict")
	az("put", strings.Replace(probe.path, probe.id, operationID(), 1), probe.body, "FileShareDeletionConflict")
	page, err := r.HostShareJobs(ctx, host.HostID, host.Certificate)
	if err != nil || len(page) != 1 || !page[0].Delete || page[0].Volume.ID != volume || len(page[0].VolumeKey) != 0 {
		t.Fatalf("expected a single authenticated deletion job without key material: %v", err)
	}
	started := time.Now()
	startStorage()
	pollVMWorker(t, ctx, 20*time.Second, "a real deletion attempt blocked by the retained RBD snapshot", removalRetried)
	checkHostedPurgeView(t, az("get", probe.path, "", ""), probe.id, volume, "Pending")
	run("sudo "+rbd+" info "+image, nil)
	run("sudo "+rbd+" snap rm "+snapshot, nil)
	pollVMWorker(t, ctx, 25*time.Second, "the storage worker to remove the authorized RBD image", func() bool {
		current, err := r.HostedFilePurge(ctx, share.Scope.TenantID, probe.id)
		return err == nil && current != nil && !current.CompletedAt.IsZero()
	})
	done := checkHostedPurgeView(t, az("get", probe.path, "", ""), probe.id, volume, "Succeeded")
	if !sameFilePurge(decision, done) {
		t.Fatal("completion changed the authoritative deletion decision")
	}
	run("sudo "+rbd+" ls ocean --format json | python3 -c 'import json,sys; assert sys.argv[1] not in json.load(sys.stdin)' "+volume, nil)
	requireHostedFilePurged(t, ctx, r, share.Scope, share.Address, volume)
	t.Logf("A retained Ceph snapshot blocked physical deletion. After the snapshot was released, the authorized storage worker deleted the exact RBD image and Ocean removed its sealed key, inventory and writer grant. The deletion probe took %d ms.", time.Since(started).Milliseconds())
}

func requireHostedFilePurged(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, address arm.ResourceAddress, volume string) {
	t.Helper()
	result, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(r.shareKey(scope, address), clientv3.WithCountOnly()),
		clientv3.OpGet(r.inventoryPrefix(scope)+address.Key(), clientv3.WithCountOnly()),
		clientv3.OpGet(r.writerKey(scope, volume), clientv3.WithCountOnly())).Commit()
	if err != nil {
		t.Fatal(err)
	}
	for _, reply := range result.Responses {
		if reply.GetResponseRange().Count != 0 {
			t.Fatal("completed file deletion left regional inventory, a sealed key or a writer grant")
		}
	}
}

func verifyHostedFilePurgeReplay(t *testing.T, ctx context.Context, restored *Region, share storageShareRecord, writer containerRecord,
	decision identity.HostedFilePurge, raw []byte) {
	t.Helper()
	started := time.Now()
	volume := share.Volume.ID
	replayed := checkHostedPurgeView(t, raw, decision.ID, volume, "Pending")
	if !sameFilePurge(replayed, decision) {
		t.Fatal("startup replay changed the authoritative deletion decision")
	}
	scope := share.Scope
	local := restored.filePurgeKey(scope.TenantID, decision.ID)
	queued := restored.filePurgeJobKey(decision.Worker, decision.VolumeID)
	snapshot, err := restored.client.Txn(ctx).Then(clientv3.OpGet(local, clientv3.WithCountOnly()), clientv3.OpGet(queued),
		clientv3.OpGet(restored.shareKey(scope, share.Address), clientv3.WithCountOnly())).Commit()
	if err != nil || snapshot.Responses[0].GetResponseRange().Count != 1 || len(snapshot.Responses[1].GetResponseRange().Kvs) != 1 ||
		string(snapshot.Responses[1].GetResponseRange().Kvs[0].Value) != local || snapshot.Responses[2].GetResponseRange().Count != 1 {
		t.Fatalf("the restored API reopened before replaying the queued deletion: %v", err)
	}
	host := decision.Worker
	cert := []byte(host)
	ready := func(want bool) {
		t.Helper()
		jobs, err := restored.HostShareJobs(ctx, host, cert)
		if !want && (err != nil || len(jobs) != 0) ||
			want && (err != nil || len(jobs) != 1 || !jobs[0].Delete || jobs[0].Volume.ID != volume || len(jobs[0].VolumeKey) != 0) {
			t.Fatalf("unexpected restored deletion job availability (want runnable %t): %v", want, err)
		}
	}
	ready(false)
	if err := restored.CompleteShareJob(ctx, host, cert, volume); !errors.Is(err, identity.ErrHostedPurgeState) {
		t.Fatalf("a restored deletion accepted a premature completion without fresh regional receipts: %v", err)
	}
	// This fixture exercises restored metadata. The native KVM case verifies
	// the worker commands that produce these two receipts.
	assignment := workload.AssignmentID{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		ID: writer.Reservation.ID, Generation: writer.Reservation.Generation, Revision: writer.Operation}
	if err := restored.ReportVolumeUnmount(ctx, host, cert, storage.UnmountReceipt{VolumeID: volume,
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, PlacementID: assignment.ID,
		Generation: assignment.Generation, Revision: assignment.Revision, Suspend: true}); err != nil {
		t.Fatal(err)
	}
	ready(false)
	if err := restored.ReportContainerTask(ctx, host, cert, workload.Report{AssignmentID: assignment, State: workload.Suspended}); err != nil {
		t.Fatal(err)
	}
	replacement := share
	replacement.Volume.ID = "vol-" + operationID()
	shareKey := restored.shareKey(scope, share.Address)
	if _, err := restored.client.Do(ctx, putJSON(shareKey, replacement)); err != nil {
		t.Fatal(err)
	}
	ready(false)
	if _, err := restored.client.Do(ctx, putJSON(shareKey, share)); err != nil {
		t.Fatal(err)
	}
	ready(true)
	if err := restored.CompleteShareJob(ctx, host, cert, volume); err != nil {
		t.Fatal(err)
	}
	requireHostedFilePurged(t, ctx, restored, scope, share.Address, volume)
	completed, err := restored.HostedFilePurge(ctx, scope.TenantID, decision.ID)
	if err != nil || completed == nil || completed.CompletedAt.IsZero() || !sameFilePurge(*completed, decision) {
		t.Fatalf("the restored region did not record completion for the original approval: %v", err)
	}
	ready(false)
	t.Logf("The restored metadata replayed the independent deletion before API admission. Both current writer receipts were required, a replacement volume hid the deletion job, and the original regional sealed key and writer grant were removed. The replay probe took %d ms.", time.Since(started).Milliseconds())
}
