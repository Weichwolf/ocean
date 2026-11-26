package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func purgeScope(decision identity.HostedFilePurge) arm.SubscriptionScope {
	return arm.SubscriptionScope{TenantID: decision.TenantID, SubscriptionID: decision.SubscriptionID}
}

func hostedFileShareAddress(scope arm.SubscriptionScope, id string) (arm.ResourceAddress, bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 13 {
		return arm.ResourceAddress{}, false
	}
	address := arm.ResourceAddress{Group: parts[4], Path: storage.AccountType + "/" + parts[8] + "/fileServices/default/shares/" + parts[12]}
	return address, address.Valid() && storage.ValidAccount(parts[8]) && storage.ValidShare(parts[12]) && strings.EqualFold(address.ID(scope), id)
}

func (r *Region) filePurgeKey(tenant, id string) string {
	return r.root + "/hosted-file-purges/" + tenant + "/" + id
}

func (r *Region) filePurgeJobKey(host, volume string) string {
	return r.hostKey("file-purges", host) + "/" + volume
}

func decodeFilePurge(data []byte, tenant, id string) (identity.HostedFilePurge, error) {
	var decision identity.HostedFilePurge
	if json.Unmarshal(data, &decision) != nil || !decision.Valid(tenant, id) || !storage.ValidID(decision.VolumeID) ||
		!strings.HasPrefix(decision.VolumeID, "vol-") || !identifier.MatchString(decision.Worker) || !identifier.MatchString(decision.Pool) {
		return decision, errors.New("invalid hosted file deletion decision")
	}
	if _, ok := hostedFileShareAddress(purgeScope(decision), decision.ShareID); !ok {
		return decision, errors.New("hosted file deletion decision has an invalid share ID")
	}
	return decision, nil
}

func (l *hostedLedger) filePurgePrefix() string { return l.prefix + "file-purges/" }

func (l *hostedLedger) readFilePurge(ctx context.Context, tenant, id string) (*identity.HostedFilePurge, error) {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := l.client.Get(probe, l.filePurgePrefix()+tenant+"/"+id)
	if err != nil {
		return nil, err
	}
	if err := l.verifyCluster(rows.Header.ClusterId); err != nil {
		return nil, err
	}
	if len(rows.Kvs) == 0 {
		return nil, nil
	}
	decision, err := decodeFilePurge(rows.Kvs[0].Value, tenant, id)
	if err != nil || !decision.CompletedAt.IsZero() {
		return nil, errors.New("invalid authoritative file deletion decision")
	}
	return &decision, nil
}

func sameFilePurge(a, b identity.HostedFilePurge) bool {
	a.CompletedAt, b.CompletedAt = time.Time{}, time.Time{}
	return a == b
}

func (r *Region) HostedFilePurge(ctx context.Context, tenant, id string) (*identity.HostedFilePurge, error) {
	if r.deletionLedger == nil || r.storage == nil {
		return nil, identity.ErrHostedPurgeState
	}
	decision, err := r.deletionLedger.readFilePurge(ctx, tenant, id)
	if err != nil || decision == nil {
		return nil, err
	}
	key := r.filePurgeKey(tenant, id)
	rows, err := r.client.Get(ctx, key)
	if err != nil || len(rows.Kvs) == 0 {
		return decision, err
	}
	local, err := decodeFilePurge(rows.Kvs[0].Value, tenant, id)
	if err != nil || !sameFilePurge(local, *decision) {
		return nil, errors.New("regional deletion decision differs from the independent ledger")
	}
	return &local, nil
}

func (r *Region) RequestHostedFilePurge(ctx context.Context, tenant, id, actor string, request identity.HostedFilePurgeRequest) (*identity.HostedFilePurge, error) {
	subscription, shareID, approval := request.SubscriptionID, request.ShareID, request.ApprovalID
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: subscription}
	address, ok := hostedFileShareAddress(scope, shareID)
	if !ok {
		return nil, identity.ErrHostedPurgeScope
	}
	prior, err := r.HostedFilePurge(ctx, tenant, id)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.SubscriptionID != subscription || !strings.EqualFold(prior.ShareID, shareID) || prior.ApprovalID != approval {
			return nil, identity.ErrHostedPurgeChanged
		}
		return prior, r.applyHostedFilePurge(ctx, *prior)
	}
	l := r.deletionLedger
	parentKey := l.prefix + "tenants/" + tenant
	parent, err := l.client.Get(ctx, parentKey)
	if err != nil {
		return nil, err
	}
	if err := l.verifyCluster(parent.Header.ClusterId); err != nil {
		return nil, err
	}
	if len(parent.Kvs) == 0 {
		return nil, identity.ErrHostedPurgeState
	}
	suspension, err := decodeOffboarding(tenant, parent.Kvs[0].Value)
	if err != nil {
		return nil, err
	}
	if suspension.SubscriptionID != subscription {
		return nil, identity.ErrPlacementTenantGone
	}
	record, pool, err := r.purgeFileTarget(ctx, scope, address)
	if err != nil {
		return nil, err
	}
	decision := identity.HostedFilePurge{ID: id, TenantID: tenant, SubscriptionID: subscription, ShareID: record.Address.ID(scope),
		VolumeID: record.Volume.ID, Worker: record.Host, Pool: pool, Actor: actor, ApprovalID: approval, DecidedAt: time.Now().UTC()}
	if decision.DecidedAt.Before(suspension.DecidedAt) {
		decision.DecidedAt = suspension.DecidedAt
	}
	key := l.filePurgePrefix() + tenant + "/" + id
	volume := l.prefix + "file-purge-volumes/" + tenant + "/" + record.Volume.ID
	result, err := l.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(parentKey), "=", parent.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(volume), "=", 0)).
		Then(putJSON(key, decision), clientv3.OpPut(volume, id)).Else(clientv3.OpGet(key)).Commit()
	if err != nil {
		return nil, err
	}
	if err := l.verifyCluster(result.Header.ClusterId); err != nil {
		return nil, err
	}
	if !result.Succeeded {
		rows := result.Responses[0].GetResponseRange().Kvs
		if len(rows) != 1 {
			return nil, identity.ErrHostedPurgeChanged
		}
		decision, err = decodeFilePurge(rows[0].Value, tenant, id)
		if err != nil || decision.SubscriptionID != subscription || !strings.EqualFold(decision.ShareID, shareID) || decision.ApprovalID != approval {
			return nil, identity.ErrHostedPurgeChanged
		}
	}
	return &decision, r.applyHostedFilePurge(ctx, decision)
}

func (r *Region) purgeFileTarget(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (storageShareRecord, string, error) {
	var record storageShareRecord
	rows, err := r.client.Get(ctx, r.shareKey(scope, address))
	if err != nil {
		return record, "", err
	}
	if len(rows.Kvs) == 0 {
		return record, "", identity.ErrPlacementTenantGone
	}
	if json.Unmarshal(rows.Kvs[0].Value, &record) != nil || record.Scope != scope || record.Address.Key() != address.Key() ||
		!ownedShare(record.Address, record.Account) || !storage.ValidID(record.Volume.ID) || !strings.HasPrefix(record.Volume.ID, "vol-") ||
		!slices.Contains(r.storage.workers, record.Host) {
		return record, "", errors.New("invalid file deletion target")
	}
	op, err := r.operationAt(ctx, scope, record.Operation, rows.Header.Revision)
	if err != nil {
		return record, "", err
	}
	if record.Deleting || op.Kind != createFileShare || op.Status != arm.OperationSucceeded {
		return record, "", identity.ErrHostedPurgeState
	}
	hosts, err := r.client.Get(ctx, r.hostKey("registered", record.Host), clientv3.WithRev(rows.Header.Revision))
	if err != nil {
		return record, "", err
	}
	var host enrollment.Host
	if len(hosts.Kvs) != 1 || json.Unmarshal(hosts.Kvs[0].Value, &host) != nil || host.HostID != record.Host ||
		host.RevokedAt != nil || !r.hosted.allowsPool(host.Pool) {
		return record, "", identity.ErrHostedPurgeState
	}
	if _, err := r.hostedPlacementAt(ctx, scope, host.Pool, rows.Header.Revision); err != nil {
		return record, "", err
	}
	return record, host.Pool, nil
}

func (r *Region) applyHostedFilePurge(ctx context.Context, decision identity.HostedFilePurge) error {
	key := r.filePurgeKey(decision.TenantID, decision.ID)
	job := r.filePurgeJobKey(decision.Worker, decision.VolumeID)
	if r.storage == nil || !slices.Contains(r.storage.workers, decision.Worker) || !r.hosted.allowsPool(decision.Pool) {
		return errors.New("file deletion requires its approved storage worker and pool")
	}
	audit := r.auditOp(purgeScope(decision), arm.AuditEvent{Time: decision.DecidedAt, Actor: decision.Actor,
		Action: "Ocean.Hosted/offboarding/requestFilePurge", Target: decision.ShareID, Outcome: "Pending"})
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(job), "=", 0)).
		Then(putJSON(key, decision), clientv3.OpPut(job, key), r.advanceBackupPolicy(), audit).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	rows := result.Responses[0].GetResponseRange().Kvs
	if len(rows) == 1 {
		local, err := decodeFilePurge(rows[0].Value, decision.TenantID, decision.ID)
		if err == nil && sameFilePurge(local, decision) {
			return nil
		}
	}
	return errors.New("regional file deletion decision conflicts with the independent ledger")
}

func (r *Region) replayHostedFilePurges(ctx context.Context, revision int64) error {
	l := r.deletionLedger
	prefix := l.filePurgePrefix()
	for cursor := prefix; ; {
		rows, err := l.client.Get(ctx, cursor, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(64), clientv3.WithRev(revision))
		if err != nil {
			return err
		}
		if err := l.verifyCluster(rows.Header.ClusterId); err != nil {
			return err
		}
		for _, row := range rows.Kvs {
			tenant, id, _ := strings.Cut(strings.TrimPrefix(string(row.Key), prefix), "/")
			decision, err := decodeFilePurge(row.Value, tenant, id)
			if err != nil || !decision.CompletedAt.IsZero() {
				return errors.New("invalid file deletion decision in the independent ledger")
			}
			parent, err := r.client.Get(ctx, r.offboardingMarker(tenant))
			if err != nil {
				return err
			}
			if len(parent.Kvs) != 1 {
				return errors.New("file deletion has no replayed suspension")
			}
			suspension, err := decodeOffboarding(tenant, parent.Kvs[0].Value)
			if err != nil || suspension.SubscriptionID != decision.SubscriptionID || decision.DecidedAt.Before(suspension.DecidedAt) {
				return errors.New("file deletion does not match its replayed suspension")
			}
			if err := r.applyHostedFilePurge(ctx, decision); err != nil {
				return err
			}
		}
		if !rows.More {
			return nil
		}
		cursor = string(rows.Kvs[len(rows.Kvs)-1].Key) + "\x00"
	}
}
