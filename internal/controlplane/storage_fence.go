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
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const fenceContainer = "FenceContainerWriter"

func (r *Region) ApplyStorageFence(ctx context.Context, signed storage.SignedFence) error {
	if r.storage == nil || len(r.storage.fencer) != ed25519.PublicKeySize || len(signed.Attestation) > 2048 ||
		!ed25519.Verify(r.storage.fencer, signed.Attestation, signed.Signature) {
		return arm.ErrStorageAccess
	}
	decoder := json.NewDecoder(bytes.NewReader(signed.Attestation))
	decoder.DisallowUnknownFields()
	var proof storage.FenceAttestation
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || proof.Observation != storage.PoweredOff ||
		proof.ObservedAt.IsZero() || time.Since(proof.ObservedAt) > 2*time.Minute || time.Until(proof.ObservedAt) > 5*time.Second {
		return arm.ErrStorageAccess
	}
	scope := arm.SubscriptionScope{TenantID: proof.TenantID, SubscriptionID: proof.SubscriptionID}
	if !validScope(scope) || !identifier.MatchString(proof.PlacementID) || !identifier.MatchString(proof.Generation) ||
		!storage.ValidID(proof.VolumeID) || !identifier.MatchString(proof.HostID) {
		return arm.ErrStorageAccess
	}
	writerKey, liveKey := r.writerKey(scope, proof.VolumeID), r.hostKey("live", proof.HostID)
	fenceKey := r.armPrefix(scope) + "storage/fenced/" + proof.VolumeID + "/" + proof.Generation
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(writerKey), clientv3.OpGet(liveKey, clientv3.WithCountOnly()), clientv3.OpGet(fenceKey)).Commit()
	if err != nil {
		return err
	}
	if prior := read.Responses[2].GetResponseRange().Kvs; len(prior) == 1 {
		var observed storage.FenceAttestation
		if json.Unmarshal(prior[0].Value, &observed) == nil && observed.VolumeID == proof.VolumeID && observed.HostID == proof.HostID &&
			observed.Generation == proof.Generation && observed.PlacementID == proof.PlacementID {
			return nil
		}
		return errors.New("invalid recorded storage fence")
	}
	items := read.Responses[0].GetResponseRange().Kvs
	var writer volumeWriter
	if len(items) != 1 || json.Unmarshal(items[0].Value, &writer) != nil || writer.Host != proof.HostID ||
		writer.PlacementID != proof.PlacementID || writer.Generation != proof.Generation {
		return arm.ErrStorageAccess
	}
	if read.Responses[1].GetResponseRange().Count != 0 {
		return arm.ErrStorageBusy
	}
	_, record, previous, revision, err := r.readContainer(ctx, scope, writer.Resource)
	if err != nil {
		return err
	}
	if previous == nil || record.Volume == nil || record.Volume.ID != proof.VolumeID || writerFor(record) != writer {
		return arm.ErrStorageAccess
	}
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: fenceContainer, Group: record.Address.Group, Actor: "storage-fencing-authority",
		Status: arm.OperationInProgress, StartedAt: now}
	assignmentKey := r.hostContainerKey(scope, proof.HostID, proof.PlacementID)
	recordKey := r.containerKey(scope, record.Address)
	checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(writerKey), "=", items[0].ModRevision),
		clientv3.Compare(clientv3.Version(liveKey), "=", 0), clientv3.Compare(clientv3.Value(assignmentKey), "=", recordKey),
		clientv3.Compare(clientv3.ModRevision(recordKey), "=", revision), clientv3.Compare(clientv3.Version(fenceKey), "=", 0),
		clientv3.Compare(clientv3.Version(r.operationKey(scope, op.ID)), "=", 0)}
	audit := arm.AuditEvent{Time: now, Actor: op.Actor, Action: "Ocean.Storage/volumeWriters/fence/action",
		Target: record.Volume.Share.ID(scope), Outcome: arm.OperationSucceeded}
	writes := []clientv3.Op{putJSON(fenceKey, proof), r.auditOp(scope, audit)}
	if previous.Status == arm.OperationInProgress {
		previous.Status, previous.FinishedAt = arm.OperationFailed, &now
		writes = append(writes, putJSON(r.operationKey(scope, previous.ID), previous))
	}
	return r.finishContainerDeletion(ctx, scope, record, op, assignmentKey, checks, writes, true)
}
