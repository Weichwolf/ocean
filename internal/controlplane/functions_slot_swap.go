package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	swapFunctionSlot     = "SwapFunctionSlot"
	rollbackFunctionSwap = "RollbackFunctionSlotSwap"
)

type functionSlotSwap struct {
	Sites    [2]arm.ResourceAddress `json:"sites"`
	Previous [2][]byte              `json:"previous,omitempty"`
	Ready    [2]bool                `json:"ready"`
}

func (r *Region) functionSlotSwapKey(scope arm.SubscriptionScope, id string) string {
	return r.armPrefix(scope) + "function-slot-swaps/" + id
}

func functionSwapRequests(slotKey string) string { return slotKey + "/function-swap-requests/" }

func (r *Region) SwapFunctionSlot(ctx context.Context, scope arm.SubscriptionScope, actor string, slot arm.ResourceAddress, request string) (*arm.Operation, error) {
	parent, ok := functionSlotParent(slot)
	if !ok || request != "" && !identifier.MatchString(request) {
		return nil, functions.ErrInvalidSite
	}
	slotKey := r.containerKey(scope, slot)
	replayKey := functionSwapRequests(slotKey) + request
	for range 8 {
		if request != "" {
			prior, err := r.client.Get(ctx, replayKey)
			if err != nil {
				return nil, err
			}
			if len(prior.Kvs) == 1 {
				id := string(prior.Kvs[0].Value)
				if !identifier.MatchString(id) {
					return nil, errors.New("invalid Functions swap operation reference")
				}
				op, err := r.operationAt(ctx, scope, id, prior.Header.Revision)
				if err == nil && op == nil {
					err = errors.New("missing Functions swap operation")
				}
				return op, err
			}
		}
		production, err := r.functionSlotState(ctx, scope, parent)
		if err != nil {
			return nil, err
		}
		source, err := r.functionSlotState(ctx, scope, slot)
		if err != nil {
			return nil, err
		}
		if source.op.ID == production.op.ID && source.op.Status == arm.OperationInProgress && source.op.Kind == swapFunctionSlot {
			if request == "" {
				return source.op, nil
			}
			// Recheck the request mapping before distinguishing a racing retry
			// from a second swap while the first one is still activating.
			mapped, err := r.client.Get(ctx, replayKey)
			if err != nil {
				return nil, err
			}
			if len(mapped.Kvs) == 1 {
				continue
			}
			return nil, arm.ErrContainerBusy
		}
		now := time.Now().UTC()
		for _, candidate := range []slotParticipant{production, source} {
			admin := candidate.config.Function.Runtime.Request
			if candidate.op.Status != arm.OperationSucceeded || candidate.record.Desired != workload.Running ||
				candidate.record.Observed != workload.Running || admin != nil && now.Before(admin.ExpiresAt) {
				return nil, arm.ErrContainerBusy
			}
			if ref := candidate.config.Function.Runtime.Package; ref == nil || !ref.Valid() {
				return nil, functions.ErrInvalidSite
			}
		}
		if production.config.Properties.Containers[0].Properties.Image != source.config.Properties.Containers[0].Properties.Image {
			return nil, functions.ErrInvalidSite
		}
		settingsKey := functionSlotSettingsKey(r.containerKey(scope, parent))
		settings, err := r.client.Get(ctx, settingsKey)
		if err != nil {
			return nil, err
		}
		var names []string
		guard := clientv3.Compare(clientv3.Version(settingsKey), "=", 0)
		if len(settings.Kvs) == 1 {
			if json.Unmarshal(settings.Kvs[0].Value, &names) != nil || !functions.ValidStickySettings(names) {
				return nil, errors.New("invalid stored Functions sticky settings")
			}
			guard = keyUnchanged(settings.Kvs[0])
		}
		op := arm.Operation{ID: operationID(), Kind: swapFunctionSlot, Group: production.record.Address.Group,
			Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		swap := functionSlotSwap{Sites: [2]arm.ResourceAddress{production.record.Address, source.record.Address},
			Previous: [2][]byte{production.record.Config, source.record.Config}}
		first, second := production.config.Function, source.config.Function
		first.Settings, second.Settings = swappedFunctionSettings(first.Settings, second.Settings, names)
		if !functions.ValidSettings(first.Settings) || !functions.ValidSettings(second.Settings) {
			return nil, functions.ErrInvalidSite
		}
		first.Runtime.Package, second.Runtime.Package = second.Runtime.Package, first.Runtime.Package
		key := r.functionSlotSwapKey(scope, op.ID)
		opKey := r.operationKey(scope, op.ID)
		checks := []clientv3.Cmp{guard, clientv3.Compare(clientv3.Version(key), "=", 0),
			clientv3.Compare(clientv3.Version(opKey), "=", 0)}
		writes := []clientv3.Op{putJSON(key, swap), putJSON(opKey, op)}
		for _, participant := range []slotParticipant{production, source} {
			condition, updates, err := r.stageFunctionSwap(scope, participant, op, now)
			if err != nil {
				return nil, err
			}
			checks, writes = append(checks, condition), append(writes, updates...)
		}
		if request != "" {
			checks = append(checks, clientv3.Compare(clientv3.Version(replayKey), "=", 0))
			writes = append(writes, clientv3.OpPut(replayKey, op.ID))
		}
		committed, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || committed.Succeeded {
			return &op, err
		}
	}
	return nil, arm.ErrContainerBusy
}

func swappedFunctionSettings(production, slot map[string]string, sticky []string) (map[string]string, map[string]string) {
	first := make(map[string]string, len(production)+len(slot))
	second := make(map[string]string, len(production)+len(slot))
	for name, value := range production {
		if slices.Contains(sticky, name) {
			first[name] = value
		} else {
			second[name] = value
		}
	}
	for name, value := range slot {
		if slices.Contains(sticky, name) {
			second[name] = value
		} else {
			first[name] = value
		}
	}
	return first, second
}

func (r *Region) stageFunctionSwap(scope arm.SubscriptionScope, participant slotParticipant, op arm.Operation,
	now time.Time) (clientv3.Cmp, []clientv3.Op, error) {
	record, config := participant.record, participant.config
	record.Operation, record.Restart = op.ID, false
	config.Function.Runtime.Configuration, config.Function.Runtime.Request = op.ID, nil
	config = functionEnvironment(config)
	if err := r.sealFunctionConfig(scope, &record, config); err != nil {
		return clientv3.Cmp{}, nil, err
	}
	key := r.containerKey(scope, record.Address)
	projected := projectContainer(config, record, participant.resource.CreatedAt, now, arm.OperationInProgress)
	return clientv3.Compare(clientv3.ModRevision(key), "=", participant.revision),
		[]clientv3.Op{putJSON(key, record), putJSON(r.inventoryPrefix(scope)+record.Address.Key(), projected),
			r.containerAudit(scope, record, op, "swap", now)}, nil
}

func (r *Region) reportFunctionSlotSwap(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress,
	operation arm.Operation, state string, checks []clientv3.Cmp, writes []clientv3.Op, now time.Time) error {
	key := r.functionSlotSwapKey(scope, operation.ID)
	items, err := r.client.Get(ctx, key)
	if err != nil {
		return err
	}
	var swap functionSlotSwap
	if len(items.Kvs) != 1 || json.Unmarshal(items.Kvs[0].Value, &swap) != nil {
		return enrollment.ErrWorkloadChanged
	}
	parent, valid := functionSlotParent(swap.Sites[1])
	reporter := slices.Index(swap.Sites[:], address)
	if !valid || parent.Key() != swap.Sites[0].Key() || reporter == -1 {
		return enrollment.ErrWorkloadChanged
	}
	checks = append(checks, keyUnchanged(items.Kvs[0]))
	if state == workload.Running {
		swap.Ready[reporter] = true
		if !swap.Ready[0] || !swap.Ready[1] {
			// The workload is still part of an in-flight swap until both
			// workers acknowledge their new native configuration.
			writes = append(writes, putJSON(key, swap))
			return r.commitFunctionSwapReport(ctx, checks, writes)
		}
	}
	var current [2]slotParticipant
	for index, site := range swap.Sites {
		participant, err := r.functionSlotState(ctx, scope, site)
		if err != nil {
			return err
		}
		if participant.record.Operation != operation.ID || participant.op.Status != arm.OperationInProgress {
			return enrollment.ErrWorkloadChanged
		}
		current[index] = participant
	}
	operation.Status, operation.FinishedAt = arm.OperationSucceeded, &now
	if state == workload.Failed {
		operation.Status = arm.OperationFailed
		operation.Error = &arm.OperationError{Code: "FunctionSlotActivationFailed", Message: "A Functions worker could not activate its slot configuration."}
	}
	writes = append(writes, putJSON(r.operationKey(scope, operation.ID), operation), clientv3.OpDelete(key))
	if operation.Status == arm.OperationFailed && operation.Kind == swapFunctionSlot {
		conditions, updates, err := r.restoreFunctionSlotSwap(scope, operation, swap, current, now)
		if err != nil {
			return err
		}
		return r.commitFunctionSwapReport(ctx, append(checks, conditions...), append(writes, updates...))
	}
	for index, participant := range current {
		record := participant.record
		if swap.Ready[index] {
			record.Observed = workload.Running
		}
		if index == reporter {
			record.Observed = state
		}
		recordKey := r.containerKey(scope, record.Address)
		checks = append(checks, clientv3.Compare(clientv3.ModRevision(recordKey), "=", participant.revision))
		view := projectContainer(participant.config, record, participant.resource.CreatedAt, now, operation.Status)
		writes = append(writes, putJSON(recordKey, record), putJSON(r.inventoryPrefix(scope)+record.Address.Key(), view),
			r.containerAudit(scope, record, operation, "reconcile", now))
	}
	return r.commitFunctionSwapReport(ctx, checks, writes)
}

func (r *Region) restoreFunctionSlotSwap(scope arm.SubscriptionScope, failed arm.Operation, swap functionSlotSwap,
	current [2]slotParticipant, now time.Time) ([]clientv3.Cmp, []clientv3.Op, error) {
	recovery := arm.Operation{ID: operationID(), Kind: rollbackFunctionSwap, Group: failed.Group, Actor: failed.Actor,
		Status: arm.OperationInProgress, StartedAt: now}
	key, opKey := r.functionSlotSwapKey(scope, recovery.ID), r.operationKey(scope, recovery.ID)
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(opKey), "=", 0)}
	writes := []clientv3.Op{putJSON(key, functionSlotSwap{Sites: swap.Sites}), putJSON(opKey, recovery)}
	for index, participant := range current {
		participant.record.Config = swap.Previous[index]
		previous, err := r.decryptContainer(scope, participant.record)
		if err != nil {
			return nil, nil, err
		}
		if previous.Function == nil {
			return nil, nil, errors.New("invalid Functions slot rollback configuration")
		}
		participant.config = previous
		condition, updates, err := r.stageFunctionSwap(scope, participant, recovery, now)
		if err != nil {
			return nil, nil, err
		}
		guards, writes = append(guards, condition), append(writes, updates...)
	}
	return guards, writes, nil
}

func (r *Region) commitFunctionSwapReport(ctx context.Context, checks []clientv3.Cmp, writes []clientv3.Op) error {
	committed, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
	if err == nil && !committed.Succeeded {
		err = enrollment.ErrWorkloadChanged
	}
	return err
}
