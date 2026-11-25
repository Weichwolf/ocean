package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) placeDirectoryReplicaReplacement(ctx context.Context, tenantID, retired string) error {
	tenant, err := r.LookupTenant(ctx, tenantID)
	if err != nil || tenant == nil {
		return err
	}
	directory, guards, revision, err := r.managedDirectorySnapshot(ctx, *tenant)
	if err != nil || directory == nil {
		return err
	}
	key, receipt := r.managedDirectoryPlacementKey(tenantID), r.directoryReplicaRepairKey(tenantID, retired)
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(key, clientv3.WithRev(revision)),
		clientv3.OpGet(receipt, clientv3.WithRev(revision))).Commit()
	if err != nil {
		return err
	}
	rows, receipts := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	var placement directoryPlacement
	var repair directoryReplicaRepair
	if len(rows) != 1 || json.Unmarshal(rows[0].Value, &placement) != nil || placement.DirectoryID != directory.ID {
		return errors.New("invalid managed directory placement during replacement")
	}
	if placement.Repair != retired {
		return nil
	}
	writerSlot := placement.writerSlot()
	replicaSlot := 1 - writerSlot
	old, primary := placement.Controllers[replicaSlot], placement.Controllers[writerSlot]
	if len(receipts) != 1 || json.Unmarshal(receipts[0].Value, &repair) != nil || repair.Fence.HostID != old.HostID ||
		repair.Fence.PlacementID != old.ID ||
		repair.Fence.Generation != retired || old.Generation != retired || repair.PrimaryGeneration != primary.Generation ||
		repair.ReplacementGeneration != "" || repair.Fence.DirectoryID != directory.ID {
		return errors.New("invalid managed directory replacement receipt")
	}
	if !repair.MetadataRemoved || placement.Promoting {
		return nil
	}
	scope := arm.SubscriptionScope{TenantID: tenantID, SubscriptionID: tenant.SubscriptionID}
	if !validScope(scope) || !validCapacity(old.Resources) || !old.PrivateIPv4.Is4() {
		return errors.New("invalid managed directory reservation for replacement")
	}
	sid, healthGuards, err := r.directoryControllerHealth(ctx, *directory, scope, primary, writerSlot, revision)
	if err != nil || sid == "" {
		return err
	}
	guards = append(guards, healthGuards...)
	base := r.armPrefix(scope)
	policy, policyRevision, err := r.placementPolicy(ctx, base+"placement-policy", true)
	if err != nil {
		return err
	}
	candidates, err := r.chooseHosts(ctx, scope, old.PlacementRequest, policy.Pools, 1)
	if err != nil {
		return err
	}
	target := candidates[0]
	if target.host.HostID == primary.HostID || target.host.HostID == old.HostID {
		return errors.New("the replacement host must be distinct from both original placements")
	}
	oldUsage, err := r.counter(ctx, r.hostKey("placement-usage", old.HostID))
	if err != nil {
		return err
	}
	if !fits(oldUsage.used, enrollment.Capacity{}, old.Resources) {
		return errors.New("missing directory capacity reservation on the retired host")
	}
	parent, subnet, ok := arm.SubnetParent(scope, old.SubnetID)
	if !ok {
		return errors.New("invalid directory subnet for replacement")
	}
	requestKey := base + "placement-requests/" + old.ID
	cellKey := r.reservationKey(scope, old.Cell, old.ID)
	previousKey := r.hostReservationKey(scope, old.HostID, old.ID)
	primaryKey := r.hostReservationKey(scope, primary.HostID, primary.ID)
	existing, err := r.client.Txn(ctx).Then(clientv3.OpGet(requestKey, clientv3.WithRev(revision)),
		clientv3.OpGet(cellKey, clientv3.WithRev(revision)), clientv3.OpGet(previousKey, clientv3.WithRev(revision)),
		clientv3.OpGet(primaryKey, clientv3.WithRev(revision))).Commit()
	if err != nil {
		return err
	}
	for n, response := range existing.Responses {
		items := response.GetResponseRange().Kvs
		if len(items) != 1 {
			return errors.New("missing directory placement index during replacement")
		}
		item := items[0]
		var reservation Reservation
		if n < 2 && (json.Unmarshal(item.Value, &reservation) != nil || reservation != old) ||
			n == 2 && !directoryAssignmentMatches(item.Value, *directory, old, replicaSlot) {
			return errors.New("inconsistent directory placement index during replacement")
		}
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(item.Key)), "=", item.ModRevision))
	}
	var primaryAssignment enrollment.Assignment
	primaryRaw := existing.Responses[3].GetResponseRange().Kvs[0].Value
	action, audit := identity.ReplaceDirectoryReplica, "Ocean.Identity/directories/replaceReplica/action"
	if repair.Fence.Action == identity.ReplaceDirectoryPrimary {
		action, audit = identity.ReplaceDirectoryPrimary, "Ocean.Identity/directories/replacePrimary/action"
	}
	if !directoryAssignmentMatches(primaryRaw, *directory, primary, writerSlot) ||
		json.Unmarshal(primaryRaw, &primaryAssignment) != nil || repair.Fence.Action != action || !primaryAssignment.Directory.IsWriter() ||
		action == identity.ReplaceDirectoryPrimary && primaryAssignment.Directory.PromoteFrom != retired ||
		action == identity.ReplaceDirectoryReplica && primaryAssignment.Directory.RetireReplica != retired {
		return errors.New("invalid surviving directory assignment during replacement")
	}
	primaryAssignment.Directory.RetireReplica = ""
	primaryAssignment.Directory.PromoteFrom = ""
	current := old
	current.HostID, current.Pool, current.Generation = target.host.HostID, target.host.Pool, operationID()
	placement.Controllers[replicaSlot], placement.Repair = current, ""
	repair.ReplacementGeneration = current.Generation
	nextKey := r.hostReservationKey(scope, current.HostID, current.ID)
	assignment := enrollment.Assignment{ID: current.ID, Generation: current.Generation, Cell: current.Cell,
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Role: current.Role, Resources: current.Resources,
		SubnetID: current.SubnetID, PrivateIPv4: current.PrivateIPv4,
		Directory: &enrollment.DirectoryAssignment{DirectoryID: directory.ID, DNSName: directory.Spec.DNSName, NetBIOSName: directory.Spec.NetBIOSName,
			ControllerIndex: replicaSlot + 1, WriterIndex: placement.WriterIndex,
			ControllerNames: placement.Names,
			ControllerIPv4:  [2]netip.Addr{placement.Controllers[0].PrivateIPv4, placement.Controllers[1].PrivateIPv4}}}
	allocation := r.subnetNetworkPlacements(scope, parent, subnet) + current.PrivateIPv4.String()
	oldSpread, newSpread := r.spreadHostKey(scope, old.SpreadSet, old.HostID), r.spreadHostKey(scope, old.SpreadSet, current.HostID)
	guards = append(guards, target.guards...)
	guards = append(guards, oldUsage.compare(),
		clientv3.Compare(clientv3.ModRevision(key), "=", rows[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(receipt), "=", receipts[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(base+"placement-policy"), "=", policyRevision),
		clientv3.Compare(clientv3.Version(nextKey), "=", 0),
		clientv3.Compare(clientv3.Version(r.hostKey("live", old.HostID)), "=", 0),
		clientv3.Compare(clientv3.Value(oldSpread), "=", retired),
		clientv3.Compare(clientv3.Value(allocation), "=", retired))
	delta := enrollment.Capacity{CPUMillis: -old.Resources.CPUMillis, MemoryMiB: -old.Resources.MemoryMiB}
	_, err = r.client.Txn(ctx).If(guards...).Then(putJSON(key, placement), putJSON(receipt, repair),
		putJSON(requestKey, current), putJSON(cellKey, current), putJSON(primaryKey, primaryAssignment),
		clientv3.OpDelete(previousKey), putJSON(nextKey, assignment), clientv3.OpDelete(oldSpread),
		clientv3.OpPut(newSpread, current.Generation), clientv3.OpPut(allocation, current.Generation),
		oldUsage.write(delta), target.usage.write(current.Resources),
		r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: "managed-directory-controller",
			Action: audit, Target: directory.ID, Outcome: "Reserved"})).Commit()
	return err
}
