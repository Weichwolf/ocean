package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type smbOwner struct {
	HostID     string `json:"hostId"`
	Generation string `json:"generation"`
}

func (r *Region) smbOwnerKey(binding smbBinding) string {
	return r.smbMemberKey(binding) + "/owner"
}

func readSMBOwner(binding smbBinding, rows []*mvccpb.KeyValue) (smbOwner, int64, error) {
	var owner smbOwner
	if len(rows) != 1 || json.Unmarshal(rows[0].Value, &owner) != nil || !identifier.MatchString(owner.Generation) ||
		(owner.HostID != binding.HostID && (binding.StandbyHostID == "" || owner.HostID != binding.StandbyHostID)) {
		return smbOwner{}, 0, errors.New("invalid SMB writer generation")
	}
	return owner, rows[0].ModRevision, nil
}

func (r *Region) ApplySMBFence(ctx context.Context, signed storage.SignedFence) error {
	if r.smb == nil || r.storage == nil || len(r.storage.fencer) != ed25519.PublicKeySize ||
		len(signed.Attestation) > 2048 || !ed25519.Verify(r.storage.fencer, signed.Attestation, signed.Signature) {
		return arm.ErrStorageAccess
	}
	var proof smb.FenceAttestation
	decoder := json.NewDecoder(bytes.NewReader(signed.Attestation))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.Observation != storage.PoweredOff ||
		proof.ObservedAt.IsZero() || time.Since(proof.ObservedAt) > 2*time.Minute || time.Until(proof.ObservedAt) > 5*time.Second {
		return arm.ErrStorageAccess
	}
	scope := arm.SubscriptionScope{TenantID: proof.TenantID, SubscriptionID: proof.SubscriptionID}
	binding, ok := r.smb.bindings[scope]
	if !ok || binding.StandbyHostID == "" || (proof.HostID != binding.HostID && proof.HostID != binding.StandbyHostID) ||
		!identifier.MatchString(proof.Generation) {
		return arm.ErrStorageAccess
	}
	ownerKey, memberKey := r.smbOwnerKey(binding), r.smbMemberKey(binding)
	liveKey, fenceKey := r.hostKey("live", proof.HostID), memberKey+"/fences/"+proof.Generation
	for range 8 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(ownerKey), clientv3.OpGet(memberKey),
			clientv3.OpGet(liveKey, clientv3.WithCountOnly()), clientv3.OpGet(fenceKey)).Commit()
		if err != nil {
			return err
		}
		previous := read.Responses[3].GetResponseRange().Kvs
		if len(previous) == 1 {
			if bytes.Equal(previous[0].Value, signed.Attestation) {
				return nil
			}
			return arm.ErrStorageAccess
		}
		owner, ownerRevision, err := readSMBOwner(binding, read.Responses[0].GetResponseRange().Kvs)
		if err != nil {
			return err
		}
		if owner.HostID != proof.HostID || owner.Generation != proof.Generation {
			return arm.ErrStorageAccess
		}
		if read.Responses[2].GetResponseRange().Count != 0 {
			return arm.ErrStorageBusy
		}
		records, revision, err := smbRecords(binding, read.Responses[1].GetResponseRange().Kvs)
		if err != nil {
			return err
		}
		replacement := binding.StandbyHostID
		if owner.HostID == replacement {
			replacement = binding.HostID
		}
		target, err := r.hostedHostGuards(ctx, scope, replacement, read.Header.Revision)
		if errors.Is(err, ErrPlacementPolicy) || errors.Is(err, enrollment.ErrHostDenied) {
			return arm.ErrStorageAccess
		}
		if err != nil {
			return err
		}
		next := smbOwner{HostID: replacement, Generation: operationID()}
		now := time.Now().UTC()
		checks := append(target, clientv3.Compare(clientv3.ModRevision(ownerKey), "=", ownerRevision),
			clientv3.Compare(clientv3.ModRevision(memberKey), "=", revision),
			clientv3.Compare(clientv3.Version(liveKey), "=", 0), clientv3.Compare(clientv3.Version(fenceKey), "=", 0))
		writes := []clientv3.Op{clientv3.OpPut(fenceKey, string(signed.Attestation)), putJSON(ownerKey, next)}
		for index, record := range records {
			if !record.Ready {
				continue // The replacement resumes pending publication or withdrawal.
			}
			op := arm.Operation{ID: operationID(), Kind: recoverSMBShare, Group: record.Address.Group,
				Actor: "storage-fencing-authority", Status: arm.OperationInProgress, StartedAt: now}
			record.Ready, record.Initialized, record.Operation = false, true, op.ID
			records[index] = record
			opKey := r.operationKey(scope, op.ID)
			checks = append(checks, clientv3.Compare(clientv3.Version(opKey), "=", 0))
			view := smbProjection(binding, record, r.name, "Updating", now)
			writes = append(writes, putJSON(opKey, op), putJSON(r.inventoryPrefix(scope)+record.Address.Key(), view),
				r.smbAudit(binding, record, op, "fence/action", now))
		}
		writes = append(writes, putJSON(memberKey, records))
		result, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return arm.ErrStorageBusy
}
