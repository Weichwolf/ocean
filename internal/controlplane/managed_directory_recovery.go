package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type directoryRecoveryRecord struct {
	identity.DirectoryRecovery
	Signed identity.SignedDirectoryFence `json:"signedFence"`
}

func (r *Region) directoryRecoveryKey(tenant, id string) string {
	return r.root + "/managed-directory-recoveries/" + tenant + "/" + id
}

func (r *Region) LookupDirectoryRecovery(ctx context.Context, tenant identity.TenantReservation, id string) (*identity.DirectoryRecovery, error) {
	if !enrollment.ValidDirectoryJoinID(id) {
		return nil, nil
	}
	directory, _, rev, err := r.managedDirectorySnapshot(ctx, tenant)
	if err != nil || directory == nil {
		return nil, err
	}
	record, _, err := r.readDirectoryRecovery(ctx, tenant.TenantID, id, rev)
	if err != nil || record == nil {
		return nil, err
	}
	return &record.DirectoryRecovery, nil
}

func (r *Region) readDirectoryRecovery(ctx context.Context, tenant, id string, rev int64) (*directoryRecoveryRecord, int64, error) {
	current, err := r.client.Get(ctx, r.directoryRecoveryKey(tenant, id), clientv3.WithRev(rev))
	if err != nil || len(current.Kvs) == 0 {
		return nil, 0, err
	}
	var record directoryRecoveryRecord
	if json.Unmarshal(current.Kvs[0].Value, &record) != nil || record.ID != id {
		return nil, 0, errors.New("invalid directory recovery record")
	}
	return &record, current.Kvs[0].ModRevision, nil
}

func (r *Region) RequestDirectoryRecovery(ctx context.Context, tenant identity.TenantReservation, id string,
	signed identity.SignedDirectoryFence) (*identity.DirectoryRecovery, error) {
	denied, pending := identity.ErrDirectoryFenceDenied, identity.ErrDirectoryFencePending
	if r.workloads == nil || len(r.directoryFencer) != ed25519.PublicKeySize || len(signed.Attestation) > 2700 ||
		!ed25519.Verify(r.directoryFencer, signed.Attestation, signed.Signature) {
		return nil, denied
	}
	var fence identity.DirectoryRecoveryFence
	decoder := json.NewDecoder(bytes.NewReader(signed.Attestation))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fence) != nil || decoder.Decode(new(any)) != io.EOF || !fence.Valid(tenant, id) {
		return nil, denied
	}
	for _, controller := range fence.Controllers {
		if !identifier.MatchString(controller.HostID) || !identifier.MatchString(controller.PlacementID) ||
			!identifier.MatchString(controller.Generation) {
			return nil, denied
		}
	}
	for range 6 {
		directory, guards, rev, err := r.managedDirectorySnapshot(ctx, tenant)
		if err != nil {
			return nil, err
		}
		if directory == nil || directory.ID != fence.DirectoryID || directory.ProvisionedAt.IsZero() || directory.DomainSID == "" {
			return nil, denied
		}
		prior, _, err := r.readDirectoryRecovery(ctx, tenant.TenantID, id, rev)
		if err != nil {
			return nil, err
		}
		if prior != nil {
			if !bytes.Equal(prior.Signed.Attestation, signed.Attestation) {
				return nil, denied
			}
			return &prior.DirectoryRecovery, nil
		}
		if time.Since(fence.ObservedAt) > 2*time.Minute || time.Until(fence.ObservedAt) > 5*time.Second {
			return nil, denied
		}
		placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
		rows, err := r.client.Get(ctx, placementKey, clientv3.WithRev(rev))
		if err != nil {
			return nil, err
		}
		var placement directoryPlacement
		if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placement) != nil || placement.DirectoryID != directory.ID {
			return nil, denied
		}
		if placement.Recovery != "" {
			return nil, pending
		}
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(placementKey), "=", rows.Kvs[0].ModRevision))
		scope := arm.SubscriptionScope{TenantID: directory.TenantID, SubscriptionID: directory.SubscriptionID}
		now := time.Now().UTC()
		var writes []clientv3.Op
		for i, old := range placement.Controllers {
			if old.HostID != fence.Controllers[i].HostID || old.ID != fence.Controllers[i].PlacementID ||
				old.Generation != fence.Controllers[i].Generation {
				return nil, denied
			}
			hostKey, liveKey := r.hostKey("registered", old.HostID), r.hostKey("live", old.HostID)
			snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(hostKey, clientv3.WithRev(rev)),
				clientv3.OpGet(liveKey, clientv3.WithRev(rev), clientv3.WithCountOnly())).Commit()
			if err != nil {
				return nil, err
			}
			if snapshot.Responses[1].GetResponseRange().Count != 0 {
				return nil, pending
			}
			hosts := snapshot.Responses[0].GetResponseRange().Kvs
			var host enrollment.Host
			if len(hosts) != 1 || json.Unmarshal(hosts[0].Value, &host) != nil || host.HostID != old.HostID {
				return nil, denied
			}
			if host.RevokedAt == nil {
				host.RevokedAt = &now
			}
			guards = append(guards, clientv3.Compare(clientv3.ModRevision(hostKey), "=", hosts[0].ModRevision),
				clientv3.Compare(clientv3.Version(liveKey), "=", 0))
			writes = append(writes, putJSON(hostKey, host), clientv3.OpDelete(r.directoryObservationKey(tenant.TenantID, old.Generation)))
		}
		placement.Repair, placement.Promoting = "", false
		placement.Recovery, directory.RecoveryEpoch = id, id
		record := directoryRecoveryRecord{DirectoryRecovery: identity.DirectoryRecovery{
			ID: id, State: identity.DirectoryRecoveryFenced, BackupSHA: fence.BackupSHA256,
		}, Signed: signed}
		receipt := r.directoryRecoveryKey(tenant.TenantID, id)
		guards = append(guards, clientv3.Compare(clientv3.Version(receipt), "=", 0))
		writes = append(writes, putJSON(receipt, record), putJSON(placementKey, placement),
			putJSON(r.managedDirectoryKey(tenant.TenantID), directory), clientv3.OpDelete(r.directoryJoinKey(*directory, "pending")),
			clientv3.OpDelete(r.directoryGraphTaskKey(*directory)),
			r.auditOp(scope, arm.AuditEvent{Time: now, Actor: tenant.Administrator, Action: "Ocean.Identity/directories/recover/action",
				Target: directory.ID, Outcome: record.State}))
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil {
			return nil, err
		}
		if result.Succeeded {
			return &record.DirectoryRecovery, nil
		}
	}
	return nil, pending
}

func (r *Region) reconcileDirectoryRecovery(ctx context.Context, tenantID, id string) error {
	tenant, err := r.LookupTenant(ctx, tenantID)
	if err != nil || tenant == nil {
		return err
	}
	directory, guards, rev, err := r.managedDirectorySnapshot(ctx, *tenant)
	if err != nil || directory == nil || directory.RecoveryEpoch != id {
		return err
	}
	key := r.managedDirectoryPlacementKey(tenantID)
	current, err := r.client.Get(ctx, key, clientv3.WithRev(rev))
	if err != nil {
		return err
	}
	var placement directoryPlacement
	if len(current.Kvs) != 1 || json.Unmarshal(current.Kvs[0].Value, &placement) != nil || placement.DirectoryID != directory.ID {
		return errors.New("invalid recovery placement")
	}
	if placement.Recovery != id {
		return nil
	}
	record, mod, err := r.readDirectoryRecovery(ctx, tenantID, id, rev)
	if err != nil {
		return err
	}
	if record == nil {
		return errors.New("missing directory recovery receipt")
	}
	receipt := r.directoryRecoveryKey(tenantID, id)
	guards = append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", current.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(receipt), "=", mod))
	var writes []clientv3.Op
	scope := arm.SubscriptionScope{TenantID: tenantID, SubscriptionID: tenant.SubscriptionID}
	switch record.State {
	case identity.DirectoryRecoveryFenced:
		var err error
		guards, writes, err = r.allocateDirectoryRecovery(ctx, *directory, scope, rev, placement, record, guards)
		if err != nil {
			return err
		}
	case identity.DirectoryRecoveryStaged:
		sid, health, err := r.readManagedDirectoryHealth(ctx, directory, rev)
		if err != nil || sid == "" || sid != directory.DomainSID {
			return err
		}
		guards = append(guards, health...)
		writer := placement.Controllers[0]
		assignmentKey := r.hostReservationKey(scope, writer.HostID, writer.ID)
		rows, err := r.client.Get(ctx, assignmentKey, clientv3.WithRev(rev))
		if err != nil {
			return err
		}
		var assigned enrollment.Assignment
		if len(rows.Kvs) != 1 || !directoryAssignmentMatches(rows.Kvs[0].Value, *directory, writer, 0) ||
			json.Unmarshal(rows.Kvs[0].Value, &assigned) != nil ||
			assigned.Directory.RecoveryID != id || assigned.Directory.RecoverySHA256 != record.BackupSHA {
			return errors.New("invalid recovered writer assignment")
		}
		record.State, placement.Recovery = identity.DirectoryRecoveryReady, ""
		assigned.Directory.RecoveryID, assigned.Directory.RecoverySHA256 = "", ""
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(assignmentKey), "=", rows.Kvs[0].ModRevision))
		writes = append(writes, putJSON(key, placement), putJSON(assignmentKey, assigned))
	default:
		return errors.New("invalid active directory recovery state")
	}
	writes = append(writes, putJSON(receipt, record), r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(),
		Actor: "managed-directory-controller", Action: "Ocean.Identity/directories/recover/action", Target: placement.DirectoryID, Outcome: record.State}))
	_, err = r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	return err
}

func (r *Region) allocateDirectoryRecovery(ctx context.Context, directory identity.ManagedDirectory, scope arm.SubscriptionScope, rev int64,
	placement directoryPlacement, record *directoryRecoveryRecord, guards []clientv3.Cmp) ([]clientv3.Cmp, []clientv3.Op, error) {
	base := r.armPrefix(scope)
	policyKey := base + "placement-policy"
	policy, policyRev, err := r.placementPolicy(ctx, policyKey, true)
	if err != nil {
		return nil, nil, err
	}
	targets, err := r.chooseHosts(ctx, scope, placement.Controllers[0].PlacementRequest, policy.Pools, 2)
	if err != nil {
		return nil, nil, err
	}
	key := r.managedDirectoryPlacementKey(directory.TenantID)
	updated := placement
	updated.WriterIndex = 1
	updated.Bootstrap = r.workloads.sealer.Seal(nil, nil, []byte("Ocn9-"+rand.Text()), updated.bootstrapLabel(key))
	guards = append(guards, clientv3.Compare(clientv3.ModRevision(policyKey), "=", policyRev))
	var writes []clientv3.Op
	addresses := [2]netip.Addr{placement.Controllers[0].PrivateIPv4, placement.Controllers[1].PrivateIPv4}
	for i := range updated.Names {
		updated.Names[i] = "oc" + strings.ReplaceAll(operationID(), "-", "")[:13]
	}
	for i, old := range placement.Controllers {
		target := targets[i]
		remaining, err := r.counter(ctx, r.hostKey("placement-usage", old.HostID))
		if err != nil {
			return nil, nil, err
		}
		parent, subnet, valid := arm.SubnetParent(scope, old.SubnetID)
		if !valid || !validCapacity(old.Resources) || !fits(remaining.used, enrollment.Capacity{}, old.Resources) {
			return nil, nil, errors.New("invalid retired recovery reservation")
		}
		current := old
		current.Generation, current.HostID, current.Pool = operationID(), target.host.HostID, target.host.Pool
		request := base + "placement-requests/" + old.ID
		cell := r.reservationKey(scope, old.Cell, old.ID)
		previous := r.hostReservationKey(scope, old.HostID, old.ID)
		next := r.hostReservationKey(scope, current.HostID, old.ID)
		indexes, err := r.client.Txn(ctx).Then(clientv3.OpGet(request, clientv3.WithRev(rev)),
			clientv3.OpGet(cell, clientv3.WithRev(rev)), clientv3.OpGet(previous, clientv3.WithRev(rev))).Commit()
		if err != nil {
			return nil, nil, err
		}
		for n, part := range indexes.Responses {
			rows := part.GetResponseRange().Kvs
			var cached Reservation
			if len(rows) != 1 || n < 2 && (json.Unmarshal(rows[0].Value, &cached) != nil || cached != old) ||
				n == 2 && !directoryAssignmentMatches(rows[0].Value, directory, old, i) {
				return nil, nil, errors.New("missing or inconsistent recovery reservation index")
			}
			guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(rows[0].Key)), "=", rows[0].ModRevision))
		}
		dc := &enrollment.DirectoryAssignment{DirectoryID: directory.ID, DNSName: directory.Spec.DNSName,
			NetBIOSName: directory.Spec.NetBIOSName, ControllerIndex: i + 1, ControllerIPv4: addresses,
			WriterIndex: 1, ControllerNames: updated.Names}
		if i == 0 {
			dc.RecoveryID, dc.RecoverySHA256 = record.ID, record.BackupSHA
		}
		assignment := enrollment.Assignment{ID: current.ID, Generation: current.Generation, Cell: current.Cell,
			TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Role: current.Role, Resources: current.Resources,
			SubnetID: current.SubnetID, PrivateIPv4: current.PrivateIPv4, Directory: dc}
		allocation := r.subnetNetworkPlacements(scope, parent, subnet) + old.PrivateIPv4.String()
		oldSpread, newSpread := r.spreadHostKey(scope, old.SpreadSet, old.HostID), r.spreadHostKey(scope, old.SpreadSet, current.HostID)
		guards = append(guards, target.guards...)
		guards = append(guards, remaining.compare(), clientv3.Compare(clientv3.Version(next), "=", 0),
			clientv3.Compare(clientv3.Version(r.hostKey("live", old.HostID)), "=", 0),
			clientv3.Compare(clientv3.Value(oldSpread), "=", old.Generation),
			clientv3.Compare(clientv3.Value(allocation), "=", old.Generation))
		delta := enrollment.Capacity{CPUMillis: -old.Resources.CPUMillis, MemoryMiB: -old.Resources.MemoryMiB}
		writes = append(writes, putJSON(request, current), putJSON(cell, current), clientv3.OpDelete(previous),
			putJSON(next, assignment), clientv3.OpDelete(oldSpread), clientv3.OpPut(newSpread, current.Generation),
			clientv3.OpPut(allocation, current.Generation), remaining.write(delta), target.usage.write(current.Resources))
		updated.Controllers[i] = current
	}
	record.State, record.Writer = identity.DirectoryRecoveryStaged, updated.Controllers[0].HostID
	return guards, append(writes, putJSON(key, updated)), nil
}
