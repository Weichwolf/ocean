package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type smbWorkerState struct {
	binding         smbBinding
	owner           smbOwner
	ownerRevision   int64
	read            *clientv3.TxnResponse
	directory       smb.DirectoryWriter
	placementRev    int64
	placementGuards []clientv3.Cmp
}

func (r *Region) smbWorkerSnapshot(ctx context.Context, host string, certificate []byte) (smbWorkerState, error) {
	if r.smb == nil {
		return smbWorkerState{}, enrollment.ErrHostDenied
	}
	binding, ok := r.smb.hosts[host]
	if !ok {
		return smbWorkerState{}, enrollment.ErrHostDenied
	}
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(r.smbMemberKey(binding)), clientv3.OpGet(r.managedDirectoryKey(binding.TenantID)),
		clientv3.OpGet(r.smbOwnerKey(binding)), clientv3.OpGet(r.managedDirectoryPlacementKey(binding.TenantID))).Commit()
	if err != nil {
		return smbWorkerState{}, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", read); err != nil {
		return smbWorkerState{}, err
	}
	owner, revision, err := readSMBOwner(binding, read.Responses[4].GetResponseRange().Kvs)
	if err != nil {
		return smbWorkerState{}, err
	}
	if owner.HostID != host || !smbDirectoryMatches(binding, read.Responses[3].GetResponseRange().Kvs) {
		return smbWorkerState{}, enrollment.ErrHostDenied
	}
	guards, err := r.hostedHostGuards(ctx, binding.scope(), host, read.Header.Revision)
	if errors.Is(err, ErrPlacementPolicy) {
		return smbWorkerState{}, enrollment.ErrHostDenied
	}
	if err != nil {
		return smbWorkerState{}, err
	}
	worker := smbWorkerState{binding: binding, owner: owner, ownerRevision: revision, read: read, placementGuards: guards}
	record := read.Responses[3].GetResponseRange().Kvs[0]
	placements := read.Responses[5].GetResponseRange().Kvs
	var native identity.ManagedDirectory
	var placement directoryPlacement
	if len(placements) == 1 {
		worker.placementRev = placements[0].ModRevision
		if json.Unmarshal(record.Value, &native) == nil && json.Unmarshal(placements[0].Value, &placement) == nil &&
			native.ID == placement.DirectoryID && !placement.Promoting && placement.Recovery == "" {
			index := placement.writerSlot()
			writer := smb.DirectoryWriter{Name: placement.controllerName(index) + "." + native.Spec.DNSName,
				Address: placement.Controllers[index].PrivateIPv4}
			if writer.ValidFor(binding.Member) {
				worker.directory = writer
			}
		}
	}
	return worker, nil
}

func (r *Region) HostSMBPlan(ctx context.Context, host string, certificate []byte) (smb.Plan, error) {
	worker, err := r.smbWorkerSnapshot(ctx, host, certificate)
	if err != nil {
		return smb.Plan{}, err
	}
	binding := worker.binding
	records, revision, err := smbRecords(binding, worker.read.Responses[2].GetResponseRange().Kvs)
	if err != nil {
		return smb.Plan{}, err
	}
	plan := smb.Plan{Revision: revision, Generation: worker.owner.Generation, Member: binding.Member, Directory: worker.directory}
	if binding.Member.StateVolumeID != "" {
		plan.StateKey, err = r.storage.sealer.Open(nil, nil, r.smb.states[binding.scope()], smbStateLabel(binding))
		if err != nil || len(plan.StateKey) != storage.KeySize {
			plan.ClearKeys()
			return smb.Plan{}, errors.New("invalid SMB member state key envelope")
		}
	}
	for _, record := range records {
		grant := smb.VolumeGrant{Volume: record.Volume, Withdraw: record.Deleting}
		if !grant.Withdraw {
			grant.Initialized = record.Ready || record.Initialized
			if !grant.Initialized {
				// Older pending updates predate the durable initialization flag.
				op, err := r.operationAt(ctx, binding.scope(), record.Operation, worker.read.Header.Revision)
				if err != nil {
					plan.ClearKeys()
					return smb.Plan{}, err
				}
				grant.Initialized = !op.StartedAt.Equal(record.CreatedAt)
			}
			grant.Key, err = r.smbShareEncryptionKey(binding, record)
			if err != nil {
				plan.ClearKeys()
				return smb.Plan{}, err
			}
			plan.Member.Shares = append(plan.Member.Shares, record.Policy.Share(record.Name, record.Volume.ID))
		}
		plan.Volumes = append(plan.Volumes, grant)
	}
	return plan, nil
}

func (r *Region) CompleteSMBPlan(ctx context.Context, host string, certificate []byte, receipt smb.Receipt) error {
	worker, err := r.smbWorkerSnapshot(ctx, host, certificate)
	if err != nil {
		return err
	}
	binding, read := worker.binding, worker.read
	records, current, err := smbRecords(binding, read.Responses[2].GetResponseRange().Kvs)
	if err != nil {
		return err
	}
	if receipt.Revision != current || receipt.Generation != worker.owner.Generation || receipt.Directory != worker.directory {
		return enrollment.ErrSMBPlanChanged
	}
	memberKey := r.smbMemberKey(binding)
	checks := append(worker.placementGuards,
		clientv3.Compare(clientv3.ModRevision(memberKey), "=", receipt.Revision),
		clientv3.Compare(clientv3.ModRevision(r.smbOwnerKey(binding)), "=", worker.ownerRevision),
		clientv3.Compare(clientv3.ModRevision(r.hostKey("registered", host)), "=", read.Responses[0].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(r.hostKey("live", host)), "=", read.Responses[1].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(r.managedDirectoryKey(binding.TenantID)), "=", read.Responses[3].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(r.managedDirectoryPlacementKey(binding.TenantID)), "=", worker.placementRev),
	)
	now := time.Now().UTC()
	scope := binding.scope()
	remaining := make([]smbShareRecord, 0, len(records))
	var mutations []clientv3.Op
	for _, record := range records {
		if !record.Deleting && worker.directory == (smb.DirectoryWriter{}) {
			return enrollment.ErrSMBPlanChanged
		}
		if record.Ready {
			remaining = append(remaining, record)
			continue
		}
		op, err := r.operationAt(ctx, scope, record.Operation, read.Header.Revision)
		if err != nil {
			return err
		}
		if op.Status != arm.OperationInProgress || record.Deleting && op.Kind != removeSMBShare ||
			!record.Deleting && op.Kind != putSMBShare && op.Kind != recoverSMBShare {
			return errors.New("invalid pending SMB operation")
		}
		op.Status, op.FinishedAt = arm.OperationSucceeded, &now
		inventoryKey := r.inventoryPrefix(scope) + record.Address.Key()
		if record.Deleting {
			mutations = append(mutations, clientv3.OpDelete(inventoryKey), clientv3.OpDelete(r.smbGroupPrefix(scope, record.Address.Group)+record.Name))
		} else {
			record.Ready, record.Initialized = true, true
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
