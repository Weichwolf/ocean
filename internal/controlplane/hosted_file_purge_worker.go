package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) certifyFilePurgeJob(ctx context.Context, host, pool, volume, key string, revision int64) (identity.HostedFilePurge, error) {
	var empty identity.HostedFilePurge
	if r.deletionLedger == nil {
		return empty, errors.New("file deletion requires the independent ledger")
	}
	prefix := r.root + "/hosted-file-purges/"
	tenant, id, found := strings.Cut(strings.TrimPrefix(key, prefix), "/")
	if !strings.HasPrefix(key, prefix) || !found || !storage.ValidID(volume) {
		return empty, errors.New("invalid hosted file deletion job reference")
	}
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return empty, err
	}
	if len(rows.Kvs) != 1 {
		return empty, errors.New("hosted file deletion job has no regional decision")
	}
	decision, err := decodeFilePurge(rows.Kvs[0].Value, tenant, id)
	if err != nil || decision.Worker != host || decision.VolumeID != volume || !decision.CompletedAt.IsZero() {
		return empty, errors.New("invalid hosted file deletion job")
	}
	if pool != decision.Pool {
		return empty, identity.ErrHostedPurgeState
	}
	authoritative, err := r.deletionLedger.readFilePurge(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	parent, err := r.HostedOffboarding(ctx, tenant)
	if err != nil {
		return empty, err
	}
	if authoritative == nil || !sameFilePurge(decision, *authoritative) || parent == nil || parent.SubscriptionID != decision.SubscriptionID {
		return empty, errors.New("hosted file deletion requires current ledger authorization")
	}
	return decision, nil
}

func (r *Region) filePurgeBoundary(ctx context.Context, decision identity.HostedFilePurge, at int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	scope := purgeScope(decision)
	policy, err := r.hostedPlacementAt(ctx, scope, decision.Pool, at)
	if errors.Is(err, ErrPlacementPolicy) {
		return nil, nil, identity.ErrHostedPurgeState
	}
	if err != nil {
		return nil, nil, err
	}
	address, _ := hostedFileShareAddress(scope, decision.ShareID)
	shareKey, inventory, writerKey := r.shareKey(scope, address), r.inventoryPrefix(scope)+address.Key(), r.writerKey(scope, decision.VolumeID)
	share, err := r.client.Get(ctx, shareKey, clientv3.WithRev(at))
	if err != nil {
		return nil, nil, err
	}
	view, err := r.client.Get(ctx, inventory, clientv3.WithRev(at))
	if err != nil {
		return nil, nil, err
	}
	checks := []clientv3.Cmp{policy}
	var writes []clientv3.Op
	if len(share.Kvs) == 1 && len(view.Kvs) == 1 {
		var found storageShareRecord
		if json.Unmarshal(share.Kvs[0].Value, &found) != nil || found.Scope != scope || found.Address.Key() != address.Key() ||
			found.Volume.ID != decision.VolumeID || !ownedShare(found.Address, found.Account) ||
			!identifier.MatchString(found.Host) || !identifier.MatchString(found.Operation) {
			return nil, nil, identity.ErrHostedPurgeState
		}
		checks = append(checks, clientv3.Compare(clientv3.ModRevision(shareKey), "=", share.Kvs[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(inventory), "=", view.Kvs[0].ModRevision))
		writes = append(writes, clientv3.OpDelete(shareKey), clientv3.OpDelete(inventory), clientv3.OpDelete(r.storageJobKey(found.Host, found.Operation)))
	} else if len(share.Kvs) == 0 && len(view.Kvs) == 0 {
		// An older regional snapshot may predate both share records.
		checks = append(checks, clientv3.Compare(clientv3.Version(shareKey), "=", 0), clientv3.Compare(clientv3.Version(inventory), "=", 0))
	} else {
		return nil, nil, identity.ErrHostedPurgeState
	}
	writers, err := r.client.Get(ctx, writerKey, clientv3.WithRev(at))
	if err != nil {
		return nil, nil, err
	}
	if len(writers.Kvs) == 0 {
		checks = append(checks, clientv3.Compare(clientv3.Version(writerKey), "=", 0))
		return checks, writes, nil
	}
	fence, err := r.hostedFileWriterReceipts(ctx, scope, address, decision.VolumeID, writers.Kvs[0].Value, at)
	if err != nil {
		return nil, nil, err
	}
	checks = append(checks, fence...)
	checks = append(checks, clientv3.Compare(clientv3.ModRevision(writerKey), "=", writers.Kvs[0].ModRevision))
	return checks, append(writes, clientv3.OpDelete(writerKey)), nil
}

func (r *Region) hostedFileWriterReceipts(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress, volume string,
	data []byte, at int64) ([]clientv3.Cmp, error) {
	var writer volumeWriter
	if json.Unmarshal(data, &writer) != nil || !writer.Resource.Valid() || !identifier.MatchString(writer.Host) {
		return nil, identity.ErrHostedPurgeState
	}
	key := r.containerKey(scope, writer.Resource)
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(at))
	if err != nil {
		return nil, err
	}
	var container containerRecord
	if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &container) != nil || container.Volume == nil ||
		container.Volume.ID != volume || container.Volume.Share.Key() != address.Key() || container.Reservation.ID != writer.PlacementID ||
		writer != writerFor(container) || !identifier.MatchString(writer.Generation) || !identifier.MatchString(writer.PlacementID) ||
		!identifier.MatchString(container.Operation) {
		return nil, identity.ErrHostedPurgeState
	}
	unmounted := r.suspendedVolumeReceiptKey(scope, volume, writer.Generation, container.Operation)
	stopped := r.hostedContainerReceiptKey(scope, writer.PlacementID, writer.Generation)
	receipts, err := r.client.Txn(ctx).Then(clientv3.OpGet(unmounted, clientv3.WithRev(at)), clientv3.OpGet(stopped, clientv3.WithRev(at))).Commit()
	if err != nil {
		return nil, err
	}
	for _, response := range receipts.Responses {
		kv := response.GetResponseRange().Kvs
		if len(kv) != 1 || string(kv[0].Value) != writer.Host {
			return nil, identity.ErrHostedPurgeState
		}
	}
	return []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", rows.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.Value(unmounted), "=", writer.Host), clientv3.Compare(clientv3.Value(stopped), "=", writer.Host)}, nil
}

func (r *Region) completeHostedFilePurge(ctx context.Context, host string, certificate []byte, id string) error {
	hostKey, liveKey := r.hostKey("registered", host), r.hostKey("live", host)
	job := r.filePurgeJobKey(host, id)
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(hostKey), clientv3.OpGet(liveKey), clientv3.OpGet(job)).Commit()
	if err != nil {
		return err
	}
	pool, err := r.authorizeStorageJobHost(host, certificate, read)
	if err != nil {
		return err
	}
	jobs := read.Responses[2].GetResponseRange().Kvs
	if len(jobs) == 0 {
		return nil
	}
	key := string(jobs[0].Value)
	decision, err := r.certifyFilePurgeJob(ctx, host, pool, id, key, read.Header.Revision)
	if err != nil {
		return err
	}
	if isHostedSMBPurge(decision) {
		return enrollment.ErrHostDenied
	}
	checks, writes, err := r.filePurgeBoundary(ctx, decision, read.Header.Revision)
	if err != nil {
		return err
	}
	checks = append(checks, clientv3.Compare(clientv3.ModRevision(job), "=", jobs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(hostKey), "=", read.Responses[0].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.Version(liveKey), ">", 0))
	return r.finishHostedFilePurge(ctx, decision, job, key, checks, writes)
}

func (r *Region) finishHostedFilePurge(ctx context.Context, decision identity.HostedFilePurge, job, key string, checks []clientv3.Cmp, writes []clientv3.Op) error {
	decision.CompletedAt = time.Now().UTC()
	if decision.CompletedAt.Before(decision.DecidedAt) {
		decision.CompletedAt = decision.DecidedAt
	}
	completion := r.auditOp(purgeScope(decision), arm.AuditEvent{Time: decision.CompletedAt, Actor: decision.Worker,
		Action: "Ocean.Hosted/offboarding/completeFilePurge", Target: decision.ShareID, Outcome: arm.OperationSucceeded})
	writes = append(writes, putJSON(key, decision), clientv3.OpDelete(job), completion)
	result, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
	if err == nil && !result.Succeeded {
		return enrollment.ErrWorkloadChanged
	}
	return err
}
