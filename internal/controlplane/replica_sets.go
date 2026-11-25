package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type replicaSlot struct {
	address  arm.ResourceAddress
	record   *containerRecord
	revision int64
	eligible bool
}

func (slot replicaSlot) ready() bool {
	return slot.eligible && slot.record != nil && slot.record.Desired == workload.Running && slot.record.Observed == workload.Running
}

func (r *Region) reconcileReplicaSets(ctx context.Context, logger *slog.Logger) {
	root := r.replicaSetsRoot()
	stop := clientv3.GetPrefixRangeEnd(root)
	cursor := root
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		read, cancel := context.WithTimeout(ctx, 2*time.Second)
		page, err := r.client.Get(read, cursor, clientv3.WithRange(stop), clientv3.WithLimit(16))
		cancel()
		if err == nil {
			for _, row := range page.Kvs {
				if ctx.Err() != nil {
					return
				}
				run, cancel := context.WithTimeout(ctx, 6*time.Second)
				err := r.reconcileReplicaSet(run, string(row.Key), row.Value, row.ModRevision)
				cancel()
				if err != nil && ctx.Err() == nil {
					logger.Warn("replica set reconciliation will retry", "error", err)
				}
			}
			cursor = root
			if page.More {
				cursor = string(page.Kvs[len(page.Kvs)-1].Key) + "\x00"
			}
		} else if ctx.Err() == nil {
			logger.Warn("read replica sets", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Region) readReplicaSlots(ctx context.Context, set replicaSetRecord) ([]replicaSlot, error) {
	slots := make([]replicaSlot, set.Slots)
	policyKey := r.armPrefix(set.Scope) + "placement-policy"
	requests := []clientv3.Op{clientv3.OpGet(policyKey)}
	for index := range slots {
		slots[index].address = replicaAddress(set, index)
		requests = append(requests, clientv3.OpGet(r.containerKey(set.Scope, slots[index].address)))
	}
	snapshot, err := r.client.Txn(ctx).Then(requests...).Commit()
	if err != nil {
		return nil, err
	}
	pools := r.workloads.defaultPlacement.Pools
	if policyItems := snapshot.Responses[0].GetResponseRange().Kvs; len(policyItems) != 0 {
		var policy PlacementPolicy
		if json.Unmarshal(policyItems[0].Value, &policy) != nil {
			return nil, ErrPlacementPolicy
		}
		pools = policy.Pools
	}
	for index := range slots {
		slot := &slots[index]
		items := snapshot.Responses[index+1].GetResponseRange().Kvs
		if len(items) == 0 {
			continue
		}
		var record containerRecord
		if json.Unmarshal(items[0].Value, &record) != nil || record.Address.Key() != slot.address.Key() ||
			record.Reservation.SpreadSet != set.ID || record.Volume != nil || !record.Reservation.PrivateIPv4.Is4() {
			return nil, errors.New("invalid managed replica")
		}
		slot.record, slot.revision = &record, items[0].ModRevision
		if !slices.Contains(pools, record.Reservation.Pool) {
			continue
		}
		host := record.Reservation.HostID
		live, err := r.client.Get(ctx, r.hostKey("live", host), clientv3.WithRev(snapshot.Header.Revision), clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		drain, err := r.client.Get(ctx, r.hostKey("drain", host), clientv3.WithRev(snapshot.Header.Revision), clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		slot.eligible = live.Count == 1 && drain.Count == 0
	}
	return slots, nil
}

func (r *Region) reconcileReplicaSet(ctx context.Context, key string, data []byte, revision int64) error {
	set, err := r.decodeReplicaSet(key, data)
	if err != nil {
		return err
	}
	binding := replicaAdmission{spreadSet: set.ID, key: key, revision: revision}
	op, err := r.GetOperation(ctx, set.Scope, set.Operation)
	if err != nil || op == nil {
		return errors.Join(errors.New("replica set operation is unavailable"), err)
	}
	template, err := r.replicaTemplate(key, set)
	if err != nil {
		return err
	}
	slots, err := r.readReplicaSlots(ctx, set)
	if err != nil {
		return err
	}
	if set.Deleting || set.Failure != "" {
		return r.removeReplicaSlots(ctx, binding, set, *op, template, slots)
	}
	spec := workload.ReplicaSetSpec{Location: r.name, Properties: workload.ReplicaSetProperties{
		AvailabilityTier: set.Tier, SubnetID: set.Subnet, Container: template, Policy: set.Policy,
	}}
	admitting := false
	for _, slot := range slots {
		if slot.record != nil {
			continue
		}
		admitting = true
		name := slot.address.Path[strings.LastIndexByte(slot.address.Path, '/')+1:]
		group := spec.ContainerGroup(name)
		if err := group.Validate(name); err != nil {
			return err
		}
		_, _, _, err := r.createContainerGroup(ctx, set.Scope, replicaControllerActor, slot.address, group, binding)
		switch {
		case err == nil:
		case errors.Is(err, arm.ErrContainerQuota):
			return r.failReplicaAdmission(ctx, binding, set, "QuotaExceeded")
		case errors.Is(err, arm.ErrLinkedResourceMissing), errors.Is(err, arm.ErrContainerDelegationRequired):
			return r.failReplicaAdmission(ctx, binding, set, "SubnetUnavailable")
		case errors.Is(err, arm.ErrContainerCapacity), errors.Is(err, arm.ErrContainerBusy):
			return nil
		default:
			return err
		}
	}
	if admitting {
		return nil
	}
	selected := selectReplicaSlots(slots, set.Target)
	started := 0
	for index, slot := range slots {
		if !selected[index] || slot.record.Desired == workload.Running && slot.record.Observed != workload.Failed {
			continue
		}
		_, err := r.mutateContainerGroup(ctx, set.Scope, replicaControllerActor, slot.address, "start", binding)
		if err != nil && !errors.Is(err, arm.ErrContainerBusy) {
			return err
		}
		started++
	}
	if started == 0 && countReadySelected(slots, selected) == set.Target {
		for index, slot := range slots {
			if selected[index] || slot.record.Desired != workload.Running {
				continue
			}
			_, err := r.mutateContainerGroup(ctx, set.Scope, replicaControllerActor, slot.address, "stop", binding)
			if err != nil && !errors.Is(err, arm.ErrContainerBusy) {
				return err
			}
		}
	}
	members, ready := replicaMembers(set.Scope, slots)
	status := "Updating"
	if ready == set.Target && started == 0 {
		status = arm.OperationSucceeded
	} else if op.Status == arm.OperationSucceeded {
		status = "Degraded"
	}
	if err := r.publishReplicaState(ctx, binding, set, *op, template, slots, members, ready, status); err != nil {
		return err
	}
	if op.Status == arm.OperationSucceeded && status == arm.OperationSucceeded {
		return r.autoscaleReplicas(ctx, binding, set, template, slots)
	}
	return nil
}

func selectReplicaSlots(slots []replicaSlot, target int) []bool {
	selected := make([]bool, len(slots))
	remaining := target
	// Keep healthy active replicas first, then any in-flight start. Use cold
	// reservations before retrying a failed placement.
	candidates := []func(replicaSlot) bool{
		func(slot replicaSlot) bool { return slot.ready() },
		func(slot replicaSlot) bool {
			return slot.record.Desired == workload.Running && slot.record.Observed != workload.Failed
		},
		func(slot replicaSlot) bool { return slot.record.Desired == workload.Stopped },
		func(slot replicaSlot) bool { return slot.record.Observed == workload.Failed },
	}
	for _, matches := range candidates {
		for index, slot := range slots {
			if remaining == 0 {
				return selected
			}
			if slot.record != nil && slot.eligible && !selected[index] && matches(slot) {
				selected[index] = true
				remaining--
			}
		}
	}
	return selected
}

func countReadySelected(slots []replicaSlot, selected []bool) int {
	ready := 0
	for index, slot := range slots {
		if selected[index] && slot.ready() {
			ready++
		}
	}
	return ready
}

func replicaMembers(scope arm.SubscriptionScope, slots []replicaSlot) ([]replicaMemberView, int) {
	members := make([]replicaMemberView, 0, len(slots))
	ready := 0
	for _, slot := range slots {
		if slot.record == nil {
			continue
		}
		record := slot.record
		state := "Starting"
		switch {
		case slot.ready():
			state = "Ready"
			ready++
		case !slot.eligible:
			state = "Unavailable"
		case record.Desired == workload.Removed:
			state = "Deleting"
		case record.Observed == workload.Failed:
			state = "Failed"
		case record.Observed == workload.Stopped && record.Desired == workload.Stopped:
			state = "Standby"
		case record.Desired == workload.Stopped:
			state = "Stopping"
		}
		members = append(members, replicaMemberView{ID: slot.address.ID(scope), Host: record.Reservation.HostID,
			PrivateIP: record.Reservation.PrivateIPv4, State: state})
	}
	return members, ready
}

func (r *Region) failReplicaAdmission(ctx context.Context, binding replicaAdmission, set replicaSetRecord, reason string) error {
	set.Failure = reason
	_, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(binding.key), "=", binding.revision)).
		Then(putJSON(binding.key, set)).Commit()
	return err
}

func (r *Region) removeReplicaSlots(ctx context.Context, binding replicaAdmission, set replicaSetRecord, op arm.Operation,
	template workload.ContainerProperties, slots []replicaSlot) error {
	empty := true
	for _, slot := range slots {
		if slot.record == nil {
			continue
		}
		empty = false
		_, err := r.mutateContainerGroup(ctx, set.Scope, replicaControllerActor, slot.address, "delete", binding)
		if err != nil && !errors.Is(err, arm.ErrContainerBusy) {
			return err
		}
	}
	if empty && set.Deleting {
		now := time.Now().UTC()
		op.Status, op.FinishedAt = arm.OperationSucceeded, &now
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(binding.key), "=", binding.revision)}
		for _, slot := range slots {
			guards = append(guards, clientv3.Compare(clientv3.Version(r.containerKey(set.Scope, slot.address)), "=", 0))
		}
		_, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpDelete(binding.key),
			clientv3.OpDelete(r.inventoryPrefix(set.Scope)+set.Address.Key()), putJSON(r.operationKey(set.Scope, op.ID), op),
			r.replicaAudit(set.Scope, set, op, "delete", now)).Commit()
		return err
	}
	status := "Deleting"
	if !set.Deleting {
		status = "Updating"
		if empty {
			status = arm.OperationFailed
		}
	}
	members, ready := replicaMembers(set.Scope, slots)
	return r.publishReplicaState(ctx, binding, set, op, template, slots, members, ready, status)
}

func (r *Region) publishReplicaState(ctx context.Context, binding replicaAdmission, set replicaSetRecord, op arm.Operation,
	template workload.ContainerProperties, slots []replicaSlot, members []replicaMemberView, ready int, status string) error {
	inventoryKey := r.inventoryPrefix(set.Scope) + set.Address.Key()
	now := time.Now().UTC()
	view := projectReplicaSet(r.name, set, template, status, members, ready, now)
	current, err := r.client.Get(ctx, inventoryKey)
	if err != nil || len(current.Kvs) != 1 {
		return err
	}
	previous, err := decodeInventoryResource(current.Kvs[0].Value, set.Address.Key())
	if err != nil {
		return err
	}
	changes := []clientv3.Op{}
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(binding.key), "=", binding.revision),
		clientv3.Compare(clientv3.ModRevision(inventoryKey), "=", current.Kvs[0].ModRevision)}
	if op.Status == arm.OperationInProgress && (status == arm.OperationSucceeded || status == arm.OperationFailed) {
		before, _ := json.Marshal(op)
		opKey := r.operationKey(set.Scope, op.ID)
		guards = append(guards, clientv3.Compare(clientv3.Value(opKey), "=", string(before)))
		op.Status, op.FinishedAt = status, &now
		if set.Failure != "" {
			op.Error = &arm.OperationError{Code: set.Failure, Message: "The replica set could not reserve all requested slots."}
		}
		changes = append(changes, putJSON(opKey, op), r.replicaAudit(set.Scope, set, op, "reconcile", now))
	}
	if !bytes.Equal(previous.Properties, view.Properties) {
		changes = append(changes, putJSON(inventoryKey, view))
	}
	if len(changes) == 0 {
		return nil
	}
	for _, slot := range slots {
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(r.containerKey(set.Scope, slot.address)), "=", slot.revision))
	}
	_, err = r.client.Txn(ctx).If(guards...).Then(changes...).Commit()
	return err
}

func (r *Region) autoscaleReplicas(ctx context.Context, binding replicaAdmission, set replicaSetRecord,
	template workload.ContainerProperties, slots []replicaSlot) error {
	policy := set.Policy.CPU
	now := time.Now().UTC()
	if set.Policy.Mode != workload.ScalingLocal || policy == nil || r.telemetry == nil ||
		now.Sub(set.LastScale) < time.Duration(policy.CooldownSeconds)*time.Second {
		return nil
	}
	limit, _, _ := template.Resources.Requests.Limits()
	if limit <= 0 {
		return errors.New("invalid replica CPU limit")
	}
	start := now.Add(-time.Duration(policy.WindowSeconds) * time.Second)
	utilization, count := 0.0, 0
	for _, slot := range slots {
		if !slot.ready() {
			continue
		}
		samples, err := r.TelemetrySamples(ctx, set.Scope, "", slot.address, start, now, 512)
		if err != nil {
			return nil // Hold the last useful target through a metrics outage.
		}
		sum, observed := 0.0, 0
		var latest time.Time
		for _, sample := range samples {
			if sample.Usage != nil {
				sum += sample.Usage.CPUMillis
				observed++
				if sample.Time.After(latest) {
					latest = sample.Time
				}
			}
		}
		if observed < 2 || now.Sub(latest) > 4*time.Second {
			return nil
		}
		utilization += 100 * sum / float64(observed) / float64(limit)
		count++
	}
	if count < set.Target || count == 0 {
		return nil
	}
	target := set.Target
	average := utilization / float64(count)
	switch {
	case average > policy.ScaleOutAbove && target < set.Policy.Maximum:
		target++
	case average < policy.ScaleInBelow && target > set.Policy.Minimum:
		target--
	default:
		return nil
	}
	set.Target, set.LastScale = target, now
	event := arm.AuditEvent{Time: now, Actor: replicaControllerActor, Action: workload.ReplicaSetType + "/scale",
		Target: set.Address.ID(set.Scope), Outcome: arm.OperationSucceeded}
	_, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(binding.key), "=", binding.revision)).
		Then(putJSON(binding.key, set), r.auditOp(set.Scope, event)).Commit()
	return err
}
