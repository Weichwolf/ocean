package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type vmFenceTicket struct {
	Address arm.ResourceAddress      `json:"address"`
	Proof   storage.FenceAttestation `json:"proof"`
}

func (r *Region) vmFencePrefix() string { return r.root + "/virtual-machines/fences/" }

func (r *Region) vmFenceKey(scope arm.SubscriptionScope, disk string) string {
	return r.vmFencePrefix() + scope.TenantID + "/" + scope.SubscriptionID + "/" + disk
}

// queueVMFence persists authenticated power-off evidence and withdraws the old
// host task even when all eligible replacement hosts are currently full.
func (r *Region) queueVMFence(ctx context.Context, scope arm.SubscriptionScope, writer volumeWriter, proof storage.FenceAttestation,
	writerRevision int64, fenceKey string) error {
	if r.vms == nil {
		return arm.ErrStorageAccess
	}
	view, vm, prior, revision, _, err := r.readVM(ctx, scope, writer.Resource)
	if err != nil {
		return err
	}
	if prior == nil || vm.Disk.ID != proof.VolumeID || vm.writer() != writer || vm.Fenced {
		return arm.ErrStorageAccess
	}
	key := r.vmKey(scope, vm.Address)
	queueKey := r.vmFenceKey(scope, vm.Disk.ID)
	hostTask := r.hostVMKey(scope, vm.Reservation)
	now := time.Now().UTC()
	vm.Fenced, vm.Observed = true, ""
	guards := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(r.writerKey(scope, vm.Disk.ID)), "=", writerRevision),
		clientv3.Compare(clientv3.ModRevision(key), "=", revision),
		clientv3.Compare(clientv3.Version(r.hostKey("live", proof.HostID)), "=", 0),
		clientv3.Compare(clientv3.Value(hostTask), "=", key),
		clientv3.Compare(clientv3.Version(fenceKey), "=", 0), clientv3.Compare(clientv3.Version(queueKey), "=", 0),
	}
	projection := projectVM(scope, vm, "Updating", view.CreatedAt, now)
	writes := []clientv3.Op{putJSON(fenceKey, proof), putJSON(queueKey, vmFenceTicket{Address: vm.Address, Proof: proof}),
		putJSON(key, vm), putJSON(r.inventoryPrefix(scope)+vm.Address.Key(), projection), clientv3.OpDelete(hostTask),
		r.vmAudit(scope, "storage-fencing-authority", vm.Address, "fence/action", arm.OperationSucceeded, now)}
	result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err != nil {
		return err
	}
	if !result.Succeeded {
		return arm.ErrStorageBusy
	}
	return nil
}

func (r *Region) reconcileVMFences(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var cursor string
	for ctx.Err() == nil {
		run, cancel := context.WithTimeout(ctx, 4*time.Second)
		next, err := r.reconcileVMFencePage(run, cursor)
		cancel()
		cursor = next
		if err != nil && ctx.Err() == nil {
			logger.Warn("VM recovery will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

func (r *Region) reconcileVMFencePage(ctx context.Context, after string) (string, error) {
	prefix := r.vmFencePrefix()
	start := prefix
	if after != "" {
		start = after + "\x00"
	}
	entries, err := r.client.Get(ctx, start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(16))
	if err != nil {
		return "", err
	}
	var failures error
	for _, item := range entries.Kvs {
		if ctx.Err() != nil {
			return after, errors.Join(failures, ctx.Err())
		}
		after = string(item.Key)
		var ticket vmFenceTicket
		if json.Unmarshal(item.Value, &ticket) != nil {
			failures = errors.Join(failures, errors.New("invalid queued VM fence evidence"))
			continue
		}
		if err := r.relocateFencedVM(ctx, ticket, after, item.ModRevision); err != nil && !errors.Is(err, ErrNoEligibleHost) {
			failures = errors.Join(failures, err)
		}
	}
	if !entries.More {
		after = ""
	}
	return after, failures
}

func (r *Region) relocateFencedVM(ctx context.Context, ticket vmFenceTicket, queueKey string, queueRevision int64) error {
	proof := ticket.Proof
	scope := arm.SubscriptionScope{TenantID: proof.TenantID, SubscriptionID: proof.SubscriptionID}
	if !validScope(scope) || !storage.ValidID(proof.VolumeID) || !ticket.Address.Valid() || queueKey != r.vmFenceKey(scope, proof.VolumeID) {
		return errors.New("queued VM fence has an invalid scope")
	}
	view, vm, current, revision, _, err := r.readVM(ctx, scope, ticket.Address)
	if err != nil {
		return err
	}
	if current == nil || !vm.Fenced || vm.Disk.ID != proof.VolumeID || vm.Reservation.HostID != proof.HostID ||
		vm.Reservation.Generation != proof.Generation || vm.Reservation.ID != proof.PlacementID {
		return nil // A competing regional reconciler can complete this ticket first.
	}
	old := vm.Reservation
	base := r.armPrefix(scope)
	policyKey := base + "placement-policy"
	policy, policyRevision, err := r.placementPolicy(ctx, policyKey, true)
	if err != nil {
		return err
	}
	candidates, err := r.chooseHosts(ctx, scope, old.PlacementRequest, policy.Pools, 1, old.HostID)
	if err != nil {
		return err
	}
	candidate := candidates[0]
	priorUsage, err := r.counter(ctx, r.hostKey("placement-usage", old.HostID))
	if err != nil {
		return err
	}
	if !fits(priorUsage.used, enrollment.Capacity{}, old.Resources) {
		return errors.New("fenced VM has inconsistent prior host capacity")
	}
	writerKey := r.writerKey(scope, vm.Disk.ID)
	writer := vm.writer()
	encodedWriter, err := json.Marshal(writer)
	if err != nil {
		return err
	}
	encodedPlacement, err := json.Marshal(old)
	if err != nil {
		return err
	}
	key := r.vmKey(scope, vm.Address)
	vm.Reservation.HostID, vm.Reservation.Pool = candidate.host.HostID, candidate.host.Pool
	vm.Reservation.Generation = operationID()
	vm.Fenced = false
	newAssignment := r.hostReservationKey(scope, vm.Reservation.HostID, old.ID)
	newTask := r.hostVMKey(scope, vm.Reservation)
	oldAssignment := r.hostReservationKey(scope, old.HostID, old.ID)
	placementKey := base + "placement-requests/" + old.ID
	cellKey := r.reservationKey(scope, old.Cell, old.ID)
	guards := append(candidate.guards, priorUsage.compare(), clientv3.Compare(clientv3.ModRevision(policyKey), "=", policyRevision),
		clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.Compare(clientv3.ModRevision(queueKey), "=", queueRevision),
		clientv3.Compare(clientv3.Value(writerKey), "=", string(encodedWriter)),
		clientv3.Compare(clientv3.Value(placementKey), "=", string(encodedPlacement)), clientv3.Compare(clientv3.Value(cellKey), "=", string(encodedPlacement)),
		clientv3.Compare(clientv3.Version(newAssignment), "=", 0), clientv3.Compare(clientv3.Version(newTask), "=", 0))
	delta := enrollment.Capacity{CPUMillis: -old.Resources.CPUMillis, MemoryMiB: -old.Resources.MemoryMiB}
	now := time.Now().UTC()
	writes := []clientv3.Op{clientv3.OpDelete(queueKey), clientv3.OpDelete(oldAssignment), clientv3.OpPut(newTask, key),
		putJSON(newAssignment, placementAssignment(scope, vm.Reservation, nil)), putJSON(writerKey, vm.writer()),
		putJSON(placementKey, vm.Reservation), putJSON(cellKey, vm.Reservation), priorUsage.write(delta), candidate.usage.write(old.Resources),
		r.vmAudit(scope, "storage-fencing-authority", vm.Address, "recover/action", arm.OperationInProgress, now)}
	if current.Status != arm.OperationInProgress {
		op := arm.Operation{ID: operationID(), Kind: recoverVM, Group: vm.Address.Group, Actor: "storage-fencing-authority",
			Status: arm.OperationInProgress, StartedAt: now}
		vm.Operation = op.ID
		opKey := r.operationKey(scope, op.ID)
		guards = append(guards, clientv3.Compare(clientv3.Version(opKey), "=", 0))
		writes = append(writes, putJSON(opKey, op))
	}
	status := "Updating"
	if vm.Desired == workload.Removed {
		status = "Deleting"
	}
	writes = append(writes, putJSON(key, vm), putJSON(r.inventoryPrefix(scope)+vm.Address.Key(), projectVM(scope, vm, status, view.CreatedAt, now)))
	_, err = r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	return err
}
