package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	putSMBShare     = "PutSMBShare"
	removeSMBShare  = "DeleteSMBShare"
	recoverSMBShare = "RecoverSMBShare"
)

type smbShareRecord struct {
	Address     arm.ResourceAddress `json:"address"`
	Name        string              `json:"name"`
	Policy      smb.Policy          `json:"policy"`
	Volume      storage.Volume      `json:"volume"`
	Envelope    []byte              `json:"envelope"`
	Operation   string              `json:"operation"`
	Ready       bool                `json:"ready"`
	Initialized bool                `json:"initialized,omitempty"`
	Deleting    bool                `json:"deleting"`
	CreatedAt   time.Time           `json:"createdAt"`
}

func (r *Region) smbMemberKey(b smbBinding) string {
	return r.root + "/smb/members/" + b.HostID
}

func (r *Region) smbGroupPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "smb/groups/" + strings.ToLower(group) + "/"
}

func smbShareName(address arm.ResourceAddress) (string, bool) {
	name, ok := strings.CutPrefix(address.Path, smb.ResourceType+"/")
	return name, ok && address.Valid() && smb.ValidName(name)
}

func smbRecords(binding smbBinding, values []*mvccpb.KeyValue) ([]smbShareRecord, int64, error) {
	if len(values) == 0 {
		return nil, 0, nil
	}
	var records []smbShareRecord
	if len(values) != 1 || json.Unmarshal(values[0].Value, &records) != nil || len(records) > smb.MaxShares {
		return nil, 0, errors.New("invalid SMB member state")
	}
	member := binding.Member
	for _, record := range records {
		name, valid := smbShareName(record.Address)
		if !valid || record.Name != name || !record.Policy.Valid() || record.CreatedAt.IsZero() ||
			record.Volume.SizeMiB != smb.VolumeSizeMiB(record.Policy.QuotaGiB) || len(record.Envelope) == 0 ||
			!identifier.MatchString(record.Operation) || record.Ready && record.Deleting {
			return nil, 0, errors.New("invalid SMB share state")
		}
		member.Shares = append(member.Shares, record.Policy.Share(name, record.Volume.ID))
	}
	if err := member.Validate(); err != nil {
		return nil, 0, err
	}
	return records, values[0].ModRevision, nil
}

func smbDirectoryMatches(binding smbBinding, items []*mvccpb.KeyValue) bool {
	var directory identity.ManagedDirectory
	return len(items) == 1 && json.Unmarshal(items[0].Value, &directory) == nil && !directory.ProvisionedAt.IsZero() &&
		directory.TenantID == binding.TenantID && directory.SubscriptionID == binding.SubscriptionID &&
		directory.DomainSID == binding.Member.DomainSID && directory.Spec.DNSName == binding.Member.DNSDomain &&
		directory.Spec.NetBIOSName == binding.Member.NetBIOSDomain
}

func smbPolicyEqual(a, b smb.Policy) bool {
	return a.QuotaGiB == b.QuotaGiB && slices.Equal(a.ReaderSIDs, b.ReaderSIDs) && slices.Equal(a.WriterSIDs, b.WriterSIDs)
}

func smbProjection(b smbBinding, record smbShareRecord, region, state string, now time.Time) arm.InventoryResource {
	properties, _ := json.Marshal(struct {
		smb.Policy
		Endpoint          string `json:"endpoint"`
		ProvisioningState string `json:"provisioningState"`
	}{record.Policy, "//" + strings.ToLower(b.Member.ServerName) + "." + b.Member.DNSDomain + "/" + record.Name, state})
	return arm.InventoryResource{Address: record.Address, APIVersion: smb.APIVersion, Location: region, Properties: properties,
		ProvisioningState: state, CreatedAt: record.CreatedAt, ChangedAt: now}
}

func (r *Region) smbAudit(b smbBinding, record smbShareRecord, op arm.Operation, action string, now time.Time) clientv3.Op {
	return r.auditOp(b.scope(), arm.AuditEvent{Time: now, Actor: op.Actor, Action: smb.ResourceType + "/" + action,
		Target: record.Address.ID(b.scope()), Outcome: op.Status})
}

func (r *Region) smbVolumeLabel(b smbBinding, volume string) []byte {
	return []byte(r.armPrefix(b.scope()) + "smb/volumes/" + volume)
}

func (r *Region) smbShareEncryptionKey(binding smbBinding, record smbShareRecord) ([]byte, error) {
	key, err := r.storage.sealer.Open(nil, nil, record.Envelope, r.smbVolumeLabel(binding, record.Volume.ID))
	if err != nil || len(key) != storage.KeySize {
		clear(key)
		return nil, errors.New("invalid SMB volume key envelope")
	}
	return key, nil
}

func (r *Region) PutSMBShare(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, policy smb.Policy) (arm.InventoryResource, *arm.Operation, bool, error) {
	var empty arm.InventoryResource
	name, valid := smbShareName(address)
	if !valid || !policy.Valid() {
		return empty, nil, false, arm.ErrSMBPolicy
	}
	if r.smb == nil {
		return empty, nil, false, arm.ErrSMBUnavailable
	}
	binding, ok := r.smb.bindings[scope]
	if !ok {
		return empty, nil, false, arm.ErrSMBUnavailable
	}
	canonical := policy.Share(name, "vol-validation")
	policy.ReaderSIDs, policy.WriterSIDs = canonical.ReaderSIDs, canonical.WriterSIDs
	member := binding.Member
	member.Shares = []smb.Share{canonical}
	if member.Validate() != nil {
		return empty, nil, false, arm.ErrSMBPolicy
	}
	memberKey, ownerKey := r.smbMemberKey(binding), r.smbOwnerKey(binding)
	directoryKey, groupKey := r.managedDirectoryKey(scope.TenantID), r.groupPrefix(scope)+strings.ToLower(address.Group)
	inventoryKey := r.inventoryPrefix(scope) + address.Key()
	marker := r.smbGroupPrefix(scope, address.Group) + name
	requests := []clientv3.Op{clientv3.OpGet(memberKey), clientv3.OpGet(groupKey), clientv3.OpGet(directoryKey),
		clientv3.OpGet(ownerKey), clientv3.OpGet(inventoryKey), clientv3.OpGet(r.hostKey("live", binding.HostID))}
	if binding.StandbyHostID != "" {
		requests = append(requests, clientv3.OpGet(r.hostKey("live", binding.StandbyHostID)))
	}
	for range 8 {
		read, err := r.client.Txn(ctx).Then(requests...).Commit()
		if err != nil {
			return empty, nil, false, err
		}
		records, revision, err := smbRecords(binding, read.Responses[0].GetResponseRange().Kvs)
		if err != nil {
			return empty, nil, false, err
		}
		groups, directory := read.Responses[1].GetResponseRange().Kvs, read.Responses[2].GetResponseRange().Kvs
		if len(groups) != 1 {
			return empty, nil, false, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groups[0].Value, strings.ToLower(address.Group))
		if err != nil {
			return empty, nil, false, err
		}
		if group.DeleteOperation != "" {
			return empty, nil, false, arm.ErrGroupDeleting
		}
		index := slices.IndexFunc(records, func(record smbShareRecord) bool { return record.Name == name })
		viewRows := read.Responses[4].GetResponseRange().Kvs
		now, created := time.Now().UTC(), index < 0
		var record smbShareRecord
		if created {
			if len(records) == smb.MaxShares {
				return empty, nil, false, arm.ErrSMBCapacity
			}
			if len(viewRows) != 0 {
				return empty, nil, false, arm.ErrSMBConflict
			}
			address.Group = group.Name
			volume := storage.Volume{ID: "vol-" + operationID(), SizeMiB: smb.VolumeSizeMiB(policy.QuotaGiB)}
			key := make([]byte, storage.KeySize)
			rand.Read(key)
			envelope := r.storage.sealer.Seal(nil, nil, key, r.smbVolumeLabel(binding, volume.ID))
			clear(key)
			record = smbShareRecord{Address: address, Name: name, Volume: volume, Envelope: envelope, CreatedAt: now}
			index = len(records)
			records = append(records, record)
		} else {
			record = records[index]
			if record.Address.Key() != address.Key() || record.Deleting || len(viewRows) != 1 {
				return empty, nil, false, arm.ErrSMBConflict
			}
			if record.Policy.QuotaGiB != policy.QuotaGiB {
				return empty, nil, false, arm.ErrSMBQuota
			}
			if smbPolicyEqual(record.Policy, policy) {
				view, err := decodeInventoryResource(viewRows[0].Value, address.Key())
				if err != nil {
					return empty, nil, false, err
				}
				op, err := r.operationAt(ctx, scope, record.Operation, read.Header.Revision)
				return view, op, false, err
			}
			if !record.Ready {
				return empty, nil, false, arm.ErrSMBConflict
			}
		}
		owner, ownerRevision, err := readSMBOwner(binding, read.Responses[3].GetResponseRange().Kvs)
		if err != nil {
			return empty, nil, false, err
		}
		liveKey := r.hostKey("live", owner.HostID)
		liveIndex := 5
		if owner.HostID == binding.StandbyHostID {
			liveIndex = 6
		}
		live := read.Responses[liveIndex].GetResponseRange().Kvs
		var available enrollment.Availability
		if !smbDirectoryMatches(binding, directory) || len(live) != 1 || live[0].Lease == 0 ||
			json.Unmarshal(live[0].Value, &available) != nil || available.HostID != owner.HostID ||
			!slices.Contains(available.Roles, "compute") {
			return empty, nil, false, arm.ErrSMBUnavailable
		}
		op := arm.Operation{ID: operationID(), Kind: putSMBShare, Group: group.Name, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		record.Initialized = record.Initialized || record.Ready
		record.Policy, record.Operation, record.Ready = policy, op.ID, false
		records[index] = record
		view := smbProjection(binding, record, r.name, arm.OperationInProgress, now)
		opKey := r.operationKey(scope, op.ID)
		applied, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(memberKey), "=", revision),
			clientv3.Compare(clientv3.ModRevision(ownerKey), "=", ownerRevision),
			clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(directoryKey), "=", directory[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(liveKey), "=", live[0].ModRevision),
			clientv3.Compare(clientv3.Version(opKey), "=", 0)).
			Then(putJSON(memberKey, records), putJSON(opKey, op), putJSON(inventoryKey, view),
				clientv3.OpPut(marker, record.Volume.ID), r.smbAudit(binding, record, op, "write", now)).Commit()
		if err != nil || applied.Succeeded {
			return view, &op, created, err
		}
	}
	return empty, nil, false, arm.ErrSMBConflict
}

func (r *Region) DeleteSMBShare(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) (*arm.Operation, error) {
	name, valid := smbShareName(address)
	if !valid {
		return nil, arm.ErrSMBPolicy
	}
	if r.smb == nil {
		return nil, nil
	}
	binding, ok := r.smb.bindings[scope]
	if !ok {
		return nil, nil
	}
	key := r.smbMemberKey(binding)
	for range 8 {
		rows, err := r.client.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		records, revision, err := smbRecords(binding, rows.Kvs)
		if err != nil {
			return nil, err
		}
		index := slices.IndexFunc(records, func(record smbShareRecord) bool { return record.Name == name && record.Address.Key() == address.Key() })
		if index < 0 {
			return nil, nil
		}
		record := records[index]
		if record.Deleting {
			return r.operationAt(ctx, scope, record.Operation, rows.Header.Revision)
		}
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: removeSMBShare, Group: record.Address.Group, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		var superseded *arm.Operation
		if !record.Ready {
			superseded, err = r.operationAt(ctx, scope, record.Operation, rows.Header.Revision)
			if err != nil {
				return nil, err
			}
			if superseded.Status != arm.OperationInProgress || superseded.Kind != putSMBShare && superseded.Kind != recoverSMBShare {
				return nil, errors.New("invalid pending SMB write")
			}
			superseded.Status, superseded.FinishedAt = arm.OperationFailed, &now
			superseded.Error = &arm.OperationError{Code: "SMBShareDeleted", Message: "A delete request superseded the pending write."}
		}
		record.Operation, record.Deleting, record.Ready = op.ID, true, false
		records[index] = record
		opKey := r.operationKey(scope, op.ID)
		view := smbProjection(binding, record, r.name, "Deleting", now)
		writes := []clientv3.Op{putJSON(key, records), putJSON(opKey, op), putJSON(r.inventoryPrefix(scope)+address.Key(), view),
			r.smbAudit(binding, record, op, "delete", now)}
		if superseded != nil {
			writes = append(writes, putJSON(r.operationKey(scope, superseded.ID), superseded),
				r.smbAudit(binding, record, *superseded, "reconcile", now))
		}
		applied, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.Compare(clientv3.Version(opKey), "=", 0)).
			Then(writes...).Commit()
		if err != nil || applied.Succeeded {
			return &op, err
		}
	}
	return nil, arm.ErrSMBConflict
}
