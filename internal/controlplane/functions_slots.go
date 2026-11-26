package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func functionSlotParent(slot arm.ResourceAddress) (arm.ResourceAddress, bool) {
	app, _, ok := functions.SlotNames(slot.Path)
	return arm.ResourceAddress{Group: slot.Group, Path: functions.SiteType + "/" + app}, ok
}

func functionSlotSettingsKey(containerKey string) string {
	return containerKey + "/function-slot-settings"
}

func (r *Region) CreateFunctionSlot(ctx context.Context, scope arm.SubscriptionScope, actor string, slot arm.ResourceAddress,
	planID, host string) (arm.InventoryResource, *arm.Operation, error) {
	var empty arm.InventoryResource
	parent, ok := functionSlotParent(slot)
	if !ok {
		return empty, nil, functions.ErrInvalidSite
	}
	current, err := r.functionSlotState(ctx, scope, slot)
	if err == nil {
		if !strings.EqualFold(planID, current.config.Function.PlanID) || host != current.config.Function.PublicHost {
			return empty, nil, arm.ErrContainerChanged
		}
		if current.op.Kind == createContainer && current.op.Status != arm.OperationSucceeded {
			return current.resource, current.op, nil
		}
		return current.resource, nil, nil
	}
	if !errors.Is(err, arm.ErrContainerMissing) {
		return empty, nil, err
	}
	source, err := r.functionSlotState(ctx, scope, parent)
	if err != nil {
		return empty, nil, err
	}
	if source.op.Status != arm.OperationSucceeded {
		return empty, nil, arm.ErrContainerBusy
	}
	app := source.config.Function
	plan, valid := arm.NetworkResourceAddress(scope, app.PlanID, functions.PlanType)
	if !valid || !strings.EqualFold(planID, app.PlanID) {
		return empty, nil, functions.ErrInvalidSite
	}
	site := functions.Site{Location: source.resource.Location, Properties: functions.SiteProperties{
		HTTPSOnly: true, VirtualNetworkSubnetID: source.record.Reservation.SubnetID,
		Config: functions.SiteConfig{LinuxFxVersion: "DOCKER|" + source.config.Properties.Containers[0].Properties.Image},
	}}
	guard := clientv3.Compare(clientv3.ModRevision(r.containerKey(scope, parent)), "=", source.revision)
	resource, op, _, err := r.createFunctionSite(ctx, scope, actor, slot, plan, site, app.Runtime.Account, app.Runtime.StorageKey, host, guard)
	return resource, op, err
}

func (r *Region) ListFunctionSlots(ctx context.Context, scope arm.SubscriptionScope, reader string, parent arm.ResourceAddress,
	after string, limit int) ([]arm.InventoryResource, error) {
	if parentResource, err := r.GetInventoryResource(ctx, scope, reader, parent); err != nil || parentResource == nil {
		if err == nil {
			err = arm.ErrContainerMissing
		}
		return nil, err
	}
	root := r.inventoryPrefix(scope)
	prefix := root + parent.Key() + "/slots/"
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	rows, err := r.readForGroup(ctx, scope, reader, parent.Group,
		clientv3.OpGet(start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(int64(limit))))
	if err != nil {
		return nil, err
	}
	resources := make([]arm.InventoryResource, 0, len(rows.Kvs))
	for _, item := range rows.Kvs {
		resource, err := decodeInventoryResource(item.Value, strings.TrimPrefix(string(item.Key), root))
		if err != nil {
			return nil, err
		}
		actual, ok := functionSlotParent(resource.Address)
		if !ok || actual.Key() != parent.Key() || resource.Kind != functions.SiteKind {
			return nil, errors.New("invalid Functions slot inventory")
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (r *Region) FunctionSlotSettings(ctx context.Context, scope arm.SubscriptionScope, reader string, app arm.ResourceAddress) ([]string, error) {
	key := functionSlotSettingsKey(r.containerKey(scope, app))
	rows, err := r.readForGroup(ctx, scope, reader, app.Group, clientv3.OpGet(key))
	if err != nil {
		return nil, err
	}
	names := []string{}
	if len(rows.Kvs) == 1 && (json.Unmarshal(rows.Kvs[0].Value, &names) != nil || !functions.ValidStickySettings(names)) {
		return nil, errors.New("invalid Functions sticky settings configuration")
	}
	return names, nil
}

func (r *Region) SetFunctionSlotSettings(ctx context.Context, scope arm.SubscriptionScope, actor string, app arm.ResourceAddress, names []string) error {
	if !functions.ValidStickySettings(names) {
		return functions.ErrInvalidSite
	}
	canonical := slices.Clone(names)
	if canonical == nil {
		canonical = []string{}
	}
	slices.Sort(canonical)
	key := r.containerKey(scope, app)
	for range 8 {
		parent, err := r.functionSlotState(ctx, scope, app)
		if err != nil {
			return err
		}
		if parent.op.Status == arm.OperationInProgress {
			return arm.ErrContainerBusy
		}
		writes, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", parent.revision)).
			Then(putJSON(functionSlotSettingsKey(key), canonical), r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(),
				Actor: actor, Action: functions.SiteType + "/config/slotConfigNames/write", Target: app.ID(scope), Outcome: "Succeeded"})).Commit()
		if err != nil || writes.Succeeded {
			return err
		}
	}
	return arm.ErrContainerBusy
}

type slotParticipant struct {
	resource arm.InventoryResource
	record   containerRecord
	config   workload.ContainerGroup
	op       *arm.Operation
	revision int64
}

func (r *Region) functionSlotState(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (slotParticipant, error) {
	resource, record, op, revision, err := r.readContainer(ctx, scope, address)
	if err != nil {
		return slotParticipant{}, err
	}
	if op == nil || record.Desired == workload.Removed || resource.Kind != functions.SiteKind {
		return slotParticipant{}, arm.ErrContainerMissing
	}
	config, err := r.decryptContainer(scope, record)
	if err != nil {
		return slotParticipant{}, err
	}
	if config.Function == nil || len(config.Properties.Containers) != 1 {
		return slotParticipant{}, errors.New("invalid Functions workload configuration")
	}
	return slotParticipant{resource, record, config, op, revision}, nil
}
