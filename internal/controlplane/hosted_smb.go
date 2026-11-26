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
	"go.etcd.io/etcd/api/v3/mvccpb"
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

func (r *Region) smbOffboardingAudit(binding smbBinding, actor, action, outcome string, now time.Time) clientv3.Op {
	return r.auditOp(binding.scope(), arm.AuditEvent{Time: now, Actor: actor, Action: "Ocean.Hosted/offboarding/" + action,
		Target: "/subscriptions/" + binding.SubscriptionID + "/providers/Ocean.Storage/smbMembers/" + binding.HostID, Outcome: outcome})
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
	job, err := r.hostedSMBPurgeJob(ctx, worker, records, "")
	if err != nil {
		return smb.Plan{}, err
	}
	if job != nil {
		plan.Suspension.PurgeVolume = job.decision.VolumeID
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
		audit := r.smbOffboardingAudit(binding, host, "withdrawSMB", "Suspended", time.Now().UTC())
		return r.recordHostedWorkerReceipt(ctx, host, key, audit, checks)
	}
	job, err := r.hostedSMBPurgeJob(ctx, worker, records, receipt.PurgeVolume)
	if err != nil {
		return err
	}
	if job == nil {
		return enrollment.ErrSMBPlanChanged
	}
	checks = append(checks, job.guards...)
	checks = append(checks, clientv3.Compare(clientv3.Value(key), "=", host),
		clientv3.Compare(clientv3.ModRevision(string(job.row.Key)), "=", job.row.ModRevision))
	return r.finishHostedFilePurge(ctx, job.decision, host, string(job.row.Key), string(job.row.Value), checks, job.writes)
}

type hostedSMBDeletion struct {
	decision identity.HostedFilePurge
	row      *mvccpb.KeyValue
	guards   []clientv3.Cmp
	writes   []clientv3.Op
}

// Approvals stay in the original queue for replay. The current certified
// owner may consume either member's SMB job within the approved pool.
func (r *Region) hostedSMBPurgeJob(ctx context.Context, worker smbWorkerState, records []smbShareRecord, wanted string) (*hostedSMBDeletion, error) {
	at, scope := worker.read.Header.Revision, worker.binding.scope()
	for _, approved := range []string{worker.owner.HostID, otherSMBMember(worker.binding, worker.owner.HostID)} {
		if approved == "" {
			continue
		}
		prefix := r.filePurgeJobKey(approved, "")
		options := []clientv3.OpOption{clientv3.WithRev(at)}
		if wanted == "" {
			options = append(options, clientv3.WithPrefix())
		}
		jobs, err := r.client.Get(ctx, prefix+wanted, options...)
		if err != nil {
			return nil, err
		}
		for _, item := range jobs.Kvs {
			volume := strings.TrimPrefix(string(item.Key), prefix)
			decision, err := r.certifyFilePurgeJob(ctx, approved, worker.pool, volume, string(item.Value), at)
			if errors.Is(err, identity.ErrHostedPurgeState) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !isHostedSMBPurge(decision) || purgeScope(decision) != scope {
				continue
			}
			guards, writes, err := r.smbFilePurgeBoundary(ctx, decision, worker, records)
			if errors.Is(err, identity.ErrHostedPurgeState) {
				continue
			}
			if err != nil {
				return nil, err
			}
			return &hostedSMBDeletion{decision: decision, row: item, guards: guards, writes: writes}, nil
		}
	}
	return nil, nil
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
