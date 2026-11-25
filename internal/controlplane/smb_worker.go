package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) smbWorkerSnapshot(ctx context.Context, host string, certificate []byte) (smbBinding, *clientv3.TxnResponse, error) {
	if r.smb == nil {
		return smbBinding{}, nil, enrollment.ErrHostDenied
	}
	binding, ok := r.smb.hosts[host]
	if !ok {
		return smbBinding{}, nil, enrollment.ErrHostDenied
	}
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(r.smbMemberKey(binding)), clientv3.OpGet(r.managedDirectoryKey(binding.TenantID))).Commit()
	if err != nil {
		return smbBinding{}, nil, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", read); err != nil {
		return smbBinding{}, nil, err
	}
	if !smbDirectoryMatches(binding, read.Responses[3].GetResponseRange().Kvs) {
		return smbBinding{}, nil, enrollment.ErrHostDenied
	}
	return binding, read, nil
}

func (r *Region) HostSMBPlan(ctx context.Context, host string, certificate []byte) (smb.Plan, error) {
	binding, read, err := r.smbWorkerSnapshot(ctx, host, certificate)
	if err != nil {
		return smb.Plan{}, err
	}
	records, revision, err := smbRecords(binding, read.Responses[2].GetResponseRange().Kvs)
	if err != nil {
		return smb.Plan{}, err
	}
	plan := smb.Plan{Revision: revision, Member: binding.Member}
	for _, record := range records {
		grant := smb.VolumeGrant{Volume: record.Volume, Withdraw: record.Deleting}
		if !grant.Withdraw {
			grant.Key, err = r.storage.sealer.Open(nil, nil, record.Envelope, r.smbVolumeLabel(binding, record.Volume.ID))
			if err != nil || len(grant.Key) != storage.KeySize {
				clear(grant.Key)
				plan.ClearKeys()
				return smb.Plan{}, errors.New("invalid SMB volume key envelope")
			}
			plan.Member.Shares = append(plan.Member.Shares, record.Policy.Share(record.Name, record.Volume.ID))
		}
		plan.Volumes = append(plan.Volumes, grant)
	}
	return plan, nil
}

func (r *Region) CompleteSMBPlan(ctx context.Context, host string, certificate []byte, revision int64) error {
	binding, read, err := r.smbWorkerSnapshot(ctx, host, certificate)
	if err != nil {
		return err
	}
	records, current, err := smbRecords(binding, read.Responses[2].GetResponseRange().Kvs)
	if err != nil {
		return err
	}
	if revision != current {
		return enrollment.ErrSMBPlanChanged
	}
	memberKey := r.smbMemberKey(binding)
	checks := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(memberKey), "=", revision),
		clientv3.Compare(clientv3.ModRevision(r.hostKey("registered", host)), "=", read.Responses[0].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(r.hostKey("live", host)), "=", read.Responses[1].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(r.managedDirectoryKey(binding.TenantID)), "=", read.Responses[3].GetResponseRange().Kvs[0].ModRevision),
	}
	now := time.Now().UTC()
	scope := binding.scope()
	remaining := make([]smbShareRecord, 0, len(records))
	var mutations []clientv3.Op
	for _, record := range records {
		if record.Ready {
			remaining = append(remaining, record)
			continue
		}
		op, err := r.operationAt(ctx, scope, record.Operation, read.Header.Revision)
		if err != nil {
			return err
		}
		if op.Status != arm.OperationInProgress || record.Deleting && op.Kind != removeSMBShare || !record.Deleting && op.Kind != putSMBShare {
			return errors.New("invalid pending SMB operation")
		}
		op.Status, op.FinishedAt = arm.OperationSucceeded, &now
		inventoryKey := r.inventoryPrefix(scope) + record.Address.Key()
		if record.Deleting {
			mutations = append(mutations, clientv3.OpDelete(inventoryKey), clientv3.OpDelete(r.smbGroupPrefix(scope, record.Address.Group)+record.Name))
		} else {
			record.Ready = true
			view := smbProjection(binding, record, r.name, arm.OperationSucceeded, now)
			mutations = append(mutations, putJSON(inventoryKey, view))
			remaining = append(remaining, record)
		}
		mutations = append(mutations, putJSON(r.operationKey(scope, op.ID), op), r.smbAudit(binding, record, *op, "reconcile", now))
	}
	if len(mutations) == 0 {
		return nil
	}
	mutations = append(mutations, putJSON(memberKey, remaining))
	result, err := r.client.Txn(ctx).If(checks...).Then(mutations...).Commit()
	if err == nil && !result.Succeeded {
		return enrollment.ErrSMBPlanChanged
	}
	return err
}
