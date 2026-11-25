package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type directoryReplicaRepair struct {
	Fence                 identity.DirectoryReplicaFence `json:"fence"`
	SignedFence           identity.SignedDirectoryFence  `json:"signedFence"`
	PrimaryGeneration     string                         `json:"primaryGeneration"`
	MetadataRemoved       bool                           `json:"metadataRemoved"`
	ReplacementGeneration string                         `json:"replacementGeneration,omitempty"`
}

func (r *Region) bootstrapDirectoryFencing(ctx context.Context) error {
	key := r.root + "/managed-directory-fencing/key"
	if r.directoryFencer == nil {
		current, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && current.Count != 0 {
			return errors.New("the region requires its configured directory fencing authority")
		}
		return err
	}
	expected := hex.EncodeToString(r.directoryFencer)
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, expected)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	current := result.Responses[0].GetResponseRange().Kvs
	if len(current) != 1 || string(current[0].Value) != expected {
		return errors.New("directory fencing authority differs from the regional record")
	}
	return nil
}

func (r *Region) directoryReplicaRepairKey(tenant, generation string) string {
	return r.root + "/managed-directory-replacements/" + tenant + "/" + generation
}

func (r *Region) RequestDirectoryReplicaReplacement(ctx context.Context, tenant identity.TenantReservation, signed identity.SignedDirectoryFence) error {
	return r.requestDirectoryReplacement(ctx, tenant, signed, identity.ReplaceDirectoryReplica)
}

func (r *Region) RequestDirectoryPrimaryReplacement(ctx context.Context, tenant identity.TenantReservation, signed identity.SignedDirectoryFence) error {
	return r.requestDirectoryReplacement(ctx, tenant, signed, identity.ReplaceDirectoryPrimary)
}

func (r *Region) requestDirectoryReplacement(ctx context.Context, tenant identity.TenantReservation, signed identity.SignedDirectoryFence, action string) error {
	denied := identity.ErrDirectoryFenceDenied
	if len(r.directoryFencer) != ed25519.PublicKeySize || len(signed.Attestation) > 2048 ||
		!ed25519.Verify(r.directoryFencer, signed.Attestation, signed.Signature) {
		return denied
	}
	var fence identity.DirectoryReplicaFence
	decoder := json.NewDecoder(bytes.NewReader(signed.Attestation))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fence) != nil || decoder.Decode(new(any)) != io.EOF || fence.Action != action ||
		fence.TenantID != tenant.TenantID || fence.SubscriptionID != tenant.SubscriptionID || fence.Observation != "PoweredOff" ||
		fence.ObservedAt.IsZero() || !identifier.MatchString(fence.HostID) || !identifier.MatchString(fence.Generation) ||
		!identifier.MatchString(fence.PlacementID) {
		return denied
	}
	directory, guards, revision, err := r.managedDirectorySnapshot(ctx, tenant)
	if err != nil {
		return err
	}
	if directory == nil || directory.ID != fence.DirectoryID || directory.ProvisionedAt.IsZero() {
		return denied
	}
	receipt := r.directoryReplicaRepairKey(tenant.TenantID, fence.Generation)
	key := r.managedDirectoryPlacementKey(tenant.TenantID)
	result, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(receipt, clientv3.WithRev(revision)),
		clientv3.OpGet(key, clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("registered", fence.HostID), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("live", fence.HostID), clientv3.WithRev(revision), clientv3.WithCountOnly())).Commit()
	if err != nil {
		return err
	}
	if entries := result.Responses[0].GetResponseRange().Kvs; len(entries) == 1 {
		var repair directoryReplicaRepair
		if json.Unmarshal(entries[0].Value, &repair) == nil && bytes.Equal(repair.SignedFence.Attestation, signed.Attestation) {
			return nil
		}
		return denied
	}
	if time.Since(fence.ObservedAt) > 2*time.Minute || time.Until(fence.ObservedAt) > 5*time.Second {
		return denied
	}
	placements := result.Responses[1].GetResponseRange().Kvs
	var placement directoryPlacement
	if len(placements) != 1 || json.Unmarshal(placements[0].Value, &placement) != nil || placement.DirectoryID != directory.ID {
		return denied
	}
	survivorSlot := placement.writerSlot()
	promotion := action == identity.ReplaceDirectoryPrimary
	if promotion {
		survivorSlot = 1 - survivorSlot
	}
	survivor, failed := placement.Controllers[survivorSlot], placement.Controllers[1-survivorSlot]
	if failed.HostID != fence.HostID || failed.ID != fence.PlacementID || failed.Generation != fence.Generation {
		return denied
	}
	if placement.Repair != "" || result.Responses[3].GetResponseRange().Count != 0 {
		return identity.ErrDirectoryFencePending
	}
	hosts := result.Responses[2].GetResponseRange().Kvs
	var host enrollment.Host
	if len(hosts) != 1 || json.Unmarshal(hosts[0].Value, &host) != nil || host.HostID != failed.HostID {
		return denied
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	assignmentKey := r.hostReservationKey(scope, survivor.HostID, survivor.ID)
	assignmentRow, err := r.client.Get(ctx, assignmentKey, clientv3.WithRev(revision))
	if err != nil {
		return err
	}
	var assignment enrollment.Assignment
	if len(assignmentRow.Kvs) != 1 || !directoryAssignmentMatches(assignmentRow.Kvs[0].Value, *directory, survivor, survivorSlot) ||
		json.Unmarshal(assignmentRow.Kvs[0].Value, &assignment) != nil || assignment.Directory.RetireReplica != "" ||
		assignment.Directory.PromoteFrom != "" || assignment.Directory.IsWriter() == promotion {
		return identity.ErrDirectoryFencePending
	}
	now := time.Now().UTC()
	placement.Repair = failed.Generation
	audit := "Ocean.Identity/directories/fenceReplica/action"
	var writes []clientv3.Op
	if promotion {
		sid, healthGuards, err := r.directoryControllerHealth(ctx, *directory, scope, survivor, survivorSlot, revision)
		if err != nil {
			return err
		}
		if sid == "" {
			return identity.ErrDirectoryFencePending
		}
		guards = append(guards, healthGuards...)
		// A replica's observation cannot serve as proof that the promoted
		// controller has restarted and begun serving the writer role.
		writes = append(writes, clientv3.OpDelete(r.directoryObservationKey(tenant.TenantID, survivor.Generation)))
		placement.WriterIndex, placement.Promoting = survivorSlot+1, true
		assignment.Directory.WriterIndex, assignment.Directory.PromoteFrom = placement.WriterIndex, failed.Generation
		audit = "Ocean.Identity/directories/fencePrimary/action"
	} else {
		assignment.Directory.RetireReplica = failed.Generation
	}
	if host.RevokedAt == nil {
		host.RevokedAt = &now
	}
	repair := directoryReplicaRepair{Fence: fence, SignedFence: signed, PrimaryGeneration: survivor.Generation}
	guards = append(guards,
		clientv3.Compare(clientv3.Version(receipt), "=", 0),
		clientv3.Compare(clientv3.ModRevision(key), "=", placements[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(string(hosts[0].Key)), "=", hosts[0].ModRevision),
		clientv3.Compare(clientv3.Version(r.hostKey("live", failed.HostID)), "=", 0),
		clientv3.Compare(clientv3.ModRevision(assignmentKey), "=", assignmentRow.Kvs[0].ModRevision))
	writes = append(writes,
		putJSON(receipt, repair), putJSON(key, placement), putJSON(string(hosts[0].Key), host), putJSON(assignmentKey, assignment),
		r.auditOp(scope, arm.AuditEvent{Time: now, Actor: tenant.Administrator, Action: audit, Target: directory.ID, Outcome: "Accepted"}))
	committed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err != nil {
		return err
	}
	if committed.Succeeded {
		return nil
	}
	recorded, err := r.client.Get(ctx, receipt)
	if err == nil && recorded.Count == 1 {
		var prior directoryReplicaRepair
		if json.Unmarshal(recorded.Kvs[0].Value, &prior) == nil && bytes.Equal(prior.SignedFence.Attestation, signed.Attestation) {
			return nil
		}
	}
	if err != nil {
		return err
	}
	return identity.ErrDirectoryFencePending
}

// ConfirmDirectoryReplicaRetirement is called by the surviving controller
// after it removes the failed replica's Samba directory and DNS records.
func (r *Region) ConfirmDirectoryReplicaRetirement(ctx context.Context, host string, certificate []byte,
	tenant, generation, retired string) error {
	if !identifier.MatchString(retired) {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	if binding.index != binding.placement.writerSlot() {
		return enrollment.ErrHostDenied
	}
	receipt := r.directoryReplicaRepairKey(tenant, retired)
	rows, err := r.client.Get(ctx, receipt)
	if err != nil {
		return err
	}
	var repair directoryReplicaRepair
	if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &repair) != nil ||
		repair.PrimaryGeneration != generation || repair.Fence.DirectoryID != binding.directory.ID || repair.Fence.Generation != retired {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	if repair.MetadataRemoved {
		return nil
	}
	if binding.placement.Repair != retired {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	repair.MetadataRemoved = true
	guards := append(binding.guards, clientv3.Compare(clientv3.ModRevision(receipt), "=", rows.Kvs[0].ModRevision))
	writes := []clientv3.Op{putJSON(receipt, repair)}
	if repair.Fence.Action == identity.ReplaceDirectoryPrimary {
		scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: binding.directory.SubscriptionID}
		survivor := binding.placement.Controllers[binding.index]
		sid, healthGuards, err := r.directoryControllerHealth(ctx, binding.directory, scope, survivor, binding.index, binding.revision)
		if err != nil {
			return err
		}
		if !binding.placement.Promoting || sid == "" {
			return enrollment.ErrDirectoryAssignmentChanged
		}
		guards = append(guards, healthGuards...)
		binding.placement.Promoting = false
		writes = append(writes, putJSON(r.managedDirectoryPlacementKey(tenant), binding.placement),
			r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: host,
				Action: "Ocean.Identity/directories/promoteReplica/action", Target: binding.directory.ID, Outcome: "Succeeded"}))
	}
	result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err == nil && !result.Succeeded {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	return err
}
