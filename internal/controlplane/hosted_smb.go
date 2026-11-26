package controlplane

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/smb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) purgeSMBTarget(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (hostedPurgeTarget, error) {
	var target hostedPurgeTarget
	if r.smb == nil {
		return target, identity.ErrPlacementTenantGone
	}
	binding, ok := r.smb.bindings[scope]
	if !ok {
		return target, identity.ErrPlacementTenantGone
	}
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.smbMemberKey(binding)), clientv3.OpGet(r.smbOwnerKey(binding))).Commit()
	if err != nil {
		return target, err
	}
	records, _, err := smbRecords(binding, snapshot.Responses[0].GetResponseRange().Kvs)
	if err != nil {
		return target, err
	}
	index := slices.IndexFunc(records, func(record smbShareRecord) bool { return record.Address.Key() == address.Key() })
	if index < 0 {
		return target, identity.ErrPlacementTenantGone
	}
	if !records[index].Ready || records[index].Deleting {
		return target, identity.ErrHostedPurgeState
	}
	owner, _, err := readSMBOwner(binding, snapshot.Responses[1].GetResponseRange().Kvs)
	if err != nil {
		return target, err
	}
	return hostedPurgeTarget{address: records[index].Address, volume: records[index].Volume.ID, host: owner.HostID, at: snapshot.Header.Revision}, nil
}

func (r *Region) smbSuspensionReceiptKey(worker smbWorkerState, memberRevision int64) string {
	revision := max(worker.ownerRevision, memberRevision)
	return r.smbMemberKey(worker.binding) + "/suspensions/" + worker.owner.Generation + "/" + strconv.FormatInt(revision, 10)
}

func (r *Region) hostedSMBSuspensionPlan(ctx context.Context, worker smbWorkerState, records []smbShareRecord, memberRevision int64) (smb.Plan, error) {
	plan := smb.Plan{Generation: worker.owner.Generation, Revision: max(worker.ownerRevision, memberRevision), Suspension: &smb.SuspensionPlan{}}
	for _, record := range records {
		plan.Suspension.Volumes = append(plan.Suspension.Volumes, record.Volume.ID)
	}
	if volume := worker.binding.Member.StateVolumeID; volume != "" {
		plan.Suspension.Volumes = append(plan.Suspension.Volumes, volume)
	}
	read := worker.read
	receipt := r.smbSuspensionReceiptKey(worker, memberRevision)
	seen, err := r.client.Get(ctx, receipt, clientv3.WithRev(read.Header.Revision))
	if err != nil {
		return smb.Plan{}, err
	}
	if len(seen.Kvs) == 0 || string(seen.Kvs[0].Value) != worker.owner.HostID {
		return plan, nil
	}
	for _, item := range read.Responses[6].GetResponseRange().Kvs {
		volume := strings.TrimPrefix(string(item.Key), r.filePurgeJobKey(worker.owner.HostID, ""))
		decision, err := r.certifyFilePurgeJob(ctx, worker.owner.HostID, worker.pool, volume, string(item.Value), read.Header.Revision)
		if errors.Is(err, identity.ErrHostedPurgeState) {
			continue
		}
		if err != nil {
			return smb.Plan{}, err
		}
		if !isHostedSMBPurge(decision) || purgeScope(decision) != worker.binding.scope() {
			continue
		}
		if _, _, err := r.smbFilePurgeBoundary(ctx, decision, worker, records); errors.Is(err, identity.ErrHostedPurgeState) {
			continue
		} else if err != nil {
			return smb.Plan{}, err
		}
		plan.Suspension.PurgeVolume = volume
		break
	}
	return plan, nil
}

func (r *Region) completeHostedSMBSuspension(ctx context.Context, worker smbWorkerState, records []smbShareRecord, memberRevision int64, receipt smb.Receipt) error {
	if !receipt.Valid() || receipt.Revision != max(worker.ownerRevision, memberRevision) || receipt.Generation != worker.owner.Generation {
		return enrollment.ErrSMBPlanChanged
	}
	binding, read, host := worker.binding, worker.read, worker.owner.HostID
	memberKey := r.smbMemberKey(binding)
	checks := append(worker.placementGuards,
		clientv3.Compare(clientv3.ModRevision(memberKey), "=", memberRevision),
		clientv3.Compare(clientv3.ModRevision(r.smbOwnerKey(binding)), "=", worker.ownerRevision),
		clientv3.Compare(clientv3.ModRevision(r.hostKey("registered", host)), "=", read.Responses[0].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.Version(r.hostKey("live", host)), ">", 0),
	)
	key := r.smbSuspensionReceiptKey(worker, memberRevision)
	if receipt.PurgeVolume == "" {
		audit := r.auditOp(binding.scope(), arm.AuditEvent{Time: time.Now().UTC(), Actor: host, Action: "Ocean.Hosted/offboarding/withdrawSMB",
			Target: "/subscriptions/" + binding.SubscriptionID + "/providers/Ocean.Storage/smbMembers/" + binding.HostID, Outcome: "Suspended"})
		return r.recordHostedWorkerReceipt(ctx, host, key, audit, checks)
	}
	job := r.filePurgeJobKey(host, receipt.PurgeVolume)
	for _, item := range read.Responses[6].GetResponseRange().Kvs {
		if string(item.Key) != job {
			continue
		}
		decision, err := r.certifyFilePurgeJob(ctx, host, worker.pool, receipt.PurgeVolume, string(item.Value), read.Header.Revision)
		if err != nil {
			return err
		}
		if !isHostedSMBPurge(decision) || purgeScope(decision) != binding.scope() {
			return enrollment.ErrSMBPlanChanged
		}
		guards, writes, err := r.smbFilePurgeBoundary(ctx, decision, worker, records)
		if err != nil {
			return err
		}
		checks = append(checks, guards...)
		checks = append(checks, clientv3.Compare(clientv3.Value(key), "=", host),
			clientv3.Compare(clientv3.ModRevision(job), "=", item.ModRevision))
		return r.finishHostedFilePurge(ctx, decision, job, string(item.Value), checks, writes)
	}
	return enrollment.ErrSMBPlanChanged
}

func (r *Region) smbFilePurgeBoundary(ctx context.Context, decision identity.HostedFilePurge, worker smbWorkerState, records []smbShareRecord) ([]clientv3.Cmp, []clientv3.Op, error) {
	scope := worker.binding.scope()
	address, _ := hostedFileShareAddress(scope, decision.ShareID)
	name, _ := smbShareName(address)
	index := slices.IndexFunc(records, func(record smbShareRecord) bool { return record.Name == name })
	inventory, marker := r.inventoryPrefix(scope)+address.Key(), r.smbGroupPrefix(scope, address.Group)+name
	at := worker.read.Header.Revision
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(inventory, clientv3.WithRev(at)), clientv3.OpGet(marker, clientv3.WithRev(at))).Commit()
	if err != nil {
		return nil, nil, err
	}
	view, link := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
	if index < 0 && len(view) == 0 && len(link) == 0 {
		return []clientv3.Cmp{clientv3.Compare(clientv3.Version(inventory), "=", 0), clientv3.Compare(clientv3.Version(marker), "=", 0)}, nil, nil
	}
	if index < 0 || len(view) != 1 || len(link) != 1 || string(link[0].Value) != decision.VolumeID ||
		records[index].Address.Key() != address.Key() || records[index].Volume.ID != decision.VolumeID {
		return nil, nil, identity.ErrHostedPurgeState
	}
	remaining := slices.Delete(slices.Clone(records), index, index+1)
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(inventory), "=", view[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(marker), "=", link[0].ModRevision)}
	writes := []clientv3.Op{putJSON(r.smbMemberKey(worker.binding), remaining), clientv3.OpDelete(inventory), clientv3.OpDelete(marker)}
	return guards, writes, nil
}
