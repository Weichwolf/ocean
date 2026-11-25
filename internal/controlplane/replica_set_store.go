package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	configureReplicaSet = "ConfigureReplicaSet"
	deleteReplicaSet    = "DeleteReplicaSet"
)

type replicaSetRecord struct {
	Scope     arm.SubscriptionScope  `json:"scope"`
	Address   arm.ResourceAddress    `json:"address"`
	ID        string                 `json:"id"`
	Operation string                 `json:"operation"`
	Tier      string                 `json:"availabilityTier"`
	Subnet    string                 `json:"subnetId"`
	Template  []byte                 `json:"template"`
	Policy    workload.ReplicaPolicy `json:"policy"`
	Target    int                    `json:"target"`
	Slots     int                    `json:"slots"`
	Deleting  bool                   `json:"deleting,omitempty"`
	Failure   string                 `json:"failure,omitempty"`
	LastScale time.Time              `json:"lastScale,omitzero"`
	Created   time.Time              `json:"created"`
}

type replicaMemberView struct {
	ID        string     `json:"id"`
	Host      string     `json:"host"`
	PrivateIP netip.Addr `json:"privateIpAddress"`
	State     string     `json:"state"`
}

func (r *Region) replicaSetsRoot() string { return r.root + "/replica-sets/" }

func (r *Region) replicaSetsPrefix(scope arm.SubscriptionScope, group string) string {
	return r.replicaSetsRoot() + scope.TenantID + "/" + scope.SubscriptionID + "/" + strings.ToLower(group) + "/"
}

func (r *Region) replicaSetKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	path := strings.ToLower(address.Path)
	return r.replicaSetsPrefix(scope, address.Group) + path
}

func replicaAddress(set replicaSetRecord, index int) arm.ResourceAddress {
	return arm.ResourceAddress{Group: set.Address.Group, Path: workload.ContainerGroupType + "/" +
		fmt.Sprintf("ocean-rs-%s-%d", set.ID[:16], index+1)}
}

func (r *Region) decodeReplicaSet(key string, data []byte) (replicaSetRecord, error) {
	var record replicaSetRecord
	if json.Unmarshal(data, &record) != nil || !validScope(record.Scope) || !record.Address.Valid() ||
		r.replicaSetKey(record.Scope, record.Address) != key || !identifier.MatchString(record.ID) || len(record.ID) < 16 ||
		record.Operation == "" || record.Slots < 1 || record.Slots > workload.MaximumReplicaSlots ||
		record.Target < record.Policy.Minimum || record.Target > record.Policy.Maximum || record.Created.IsZero() {
		return record, errors.New("invalid replica set record")
	}
	return record, nil
}

func (r *Region) replicaTemplate(key string, set replicaSetRecord) (workload.ContainerProperties, error) {
	var template workload.ContainerProperties
	data, err := r.workloads.sealer.Open(nil, nil, set.Template, []byte(key+"/"+set.ID))
	if err != nil {
		return template, errors.New("cannot decrypt replica set template")
	}
	defer clear(data)
	if json.Unmarshal(data, &template) != nil {
		return template, errors.New("cannot decode replica set template")
	}
	return template, nil
}

func projectReplicaSet(location string, set replicaSetRecord, template workload.ContainerProperties, status string,
	members []replicaMemberView, ready int, changed time.Time) arm.InventoryResource {
	if members == nil {
		members = []replicaMemberView{}
	}
	properties, _ := json.Marshal(map[string]any{
		"provisioningState": status, "availabilityTier": set.Tier, "subnetId": set.Subnet, "policy": set.Policy,
		"image": template.Image, "port": template.Ports[0].Port, "desiredReplicas": set.Target,
		"readyReplicas": ready, "reservedSlots": set.Slots, "members": members, "reconcileError": set.Failure,
	})
	return arm.InventoryResource{Address: set.Address, APIVersion: workload.ReplicaSetAPIVersion, Location: location,
		ProvisioningState: status, Properties: properties, CreatedAt: set.Created, ChangedAt: changed}
}

func (r *Region) PutReplicaSet(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	spec workload.ReplicaSetSpec) (arm.InventoryResource, *arm.Operation, bool, error) {
	var empty arm.InventoryResource
	if r.workloads == nil {
		return empty, nil, false, arm.ErrContainerCapacity
	}
	properties := spec.Properties
	parent, subnetName, valid := arm.SubnetParent(scope, properties.SubnetID)
	if !valid {
		return empty, nil, false, workload.ErrInvalidReplicaSet
	}
	key := r.replicaSetKey(scope, address)
	inventoryKey := r.inventoryPrefix(scope) + address.Key()
	groupKey := r.groupPrefix(scope) + strings.ToLower(address.Group)
	vnetKey := r.inventoryPrefix(scope) + parent.Key()
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(key), clientv3.OpGet(groupKey),
			clientv3.OpGet(vnetKey), clientv3.OpGet(inventoryKey)).Commit()
		if err != nil {
			return empty, nil, false, err
		}
		groups, virtualNetworks := snapshot.Responses[1].GetResponseRange().Kvs, snapshot.Responses[2].GetResponseRange().Kvs
		if len(groups) == 0 {
			return empty, nil, false, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groups[0].Value, strings.ToLower(address.Group))
		if err != nil || group.DeleteOperation != "" {
			return empty, nil, false, errors.Join(arm.ErrGroupDeleting, err)
		}
		if len(virtualNetworks) == 0 {
			return empty, nil, false, arm.ErrLinkedResourceMissing
		}
		_, subnet, err := decodeSubnet(virtualNetworks[0].Value, parent.Key(), subnetName)
		if err != nil {
			return empty, nil, false, arm.ErrLinkedResourceMissing
		}
		if !subnet.Properties.HasDelegation(network.ContainerDelegationService) {
			return empty, nil, false, arm.ErrContainerDelegationRequired
		}
		now := time.Now().UTC()
		address.Group = group.Name
		set := replicaSetRecord{Scope: scope, Address: address, ID: operationID(), Created: now}
		var revision int64
		var oldOperation *arm.Operation
		items := snapshot.Responses[0].GetResponseRange().Kvs
		created := len(items) == 0
		if created {
			body, err := json.Marshal(properties.Container)
			if err != nil {
				return empty, nil, false, err
			}
			set.Template = r.workloads.sealer.Seal(nil, nil, body, []byte(key+"/"+set.ID))
			clear(body)
			set.Tier, set.Subnet, set.Slots = properties.AvailabilityTier, properties.SubnetID, properties.Slots()
		} else {
			set, err = r.decodeReplicaSet(key, items[0].Value)
			if err != nil {
				return empty, nil, false, err
			}
			if set.Deleting {
				return empty, nil, false, arm.ErrContainerBusy
			}
			template, err := r.replicaTemplate(key, set)
			if err != nil {
				return empty, nil, false, err
			}
			if set.Tier != properties.AvailabilityTier || !strings.EqualFold(set.Subnet, properties.SubnetID) ||
				set.Policy.Maximum != properties.Policy.Maximum || !reflect.DeepEqual(template, properties.Container) {
				return empty, nil, false, arm.ErrReplicaSetChanged
			}
			oldOperation, err = r.operationAt(ctx, scope, set.Operation, snapshot.Header.Revision)
			if err != nil {
				return empty, nil, false, err
			}
			if reflect.DeepEqual(set.Policy, properties.Policy) && set.Failure == "" {
				views := snapshot.Responses[3].GetResponseRange().Kvs
				if len(views) != 1 {
					return empty, nil, false, errors.New("replica set has no inventory projection")
				}
				view, err := decodeInventoryResource(views[0].Value, address.Key())
				return view, oldOperation, false, err
			}
			revision = items[0].ModRevision
		}
		op := arm.Operation{ID: operationID(), Kind: configureReplicaSet, Group: group.Name, Actor: actor,
			Status: arm.OperationInProgress, StartedAt: now}
		set.Policy, set.Target, set.Operation = properties.Policy, properties.Policy.Desired, op.ID
		set.Failure, set.LastScale = "", now
		view := projectReplicaSet(spec.Location, set, properties.Container, "Updating", nil, 0, now)
		opKey := r.operationKey(scope, op.ID)
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(vnetKey), "=", virtualNetworks[0].ModRevision),
			clientv3.Compare(clientv3.Version(opKey), "=", 0)}
		changes := []clientv3.Op{putJSON(key, set), putJSON(inventoryKey, view), putJSON(opKey, op), r.replicaAudit(scope, set, op, "write", now)}
		if created {
			quotaGuards, err := r.replicaQuotaFit(ctx, scope, properties)
			if err != nil {
				return empty, nil, false, err
			}
			guards = append(guards, quotaGuards...)
		}
		if oldOperation != nil && oldOperation.Status == arm.OperationInProgress {
			oldOperation.Status, oldOperation.FinishedAt = arm.OperationFailed, &now
			changes = append(changes, putJSON(r.operationKey(scope, oldOperation.ID), oldOperation))
		}
		result, err := r.client.Txn(ctx).If(guards...).Then(changes...).Commit()
		if err != nil || result.Succeeded {
			return view, &op, created, err
		}
	}
	return empty, nil, false, arm.ErrContainerBusy
}

func (r *Region) replicaQuotaFit(ctx context.Context, scope arm.SubscriptionScope, properties workload.ReplicaSetProperties) ([]clientv3.Cmp, error) {
	base := r.armPrefix(scope)
	key := base + "placement-policy"
	row, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	quota, revision := r.workloads.defaultPlacement, int64(0)
	if len(row.Kvs) == 1 {
		if json.Unmarshal(row.Kvs[0].Value, &quota) != nil {
			return nil, ErrPlacementPolicy
		}
		revision = row.Kvs[0].ModRevision
	}
	used, err := r.counter(ctx, base+"placement-usage")
	if err != nil {
		return nil, err
	}
	cpu, memory, valid := properties.Container.Resources.Requests.Limits()
	if !valid {
		return nil, workload.ErrInvalidReplicaSet
	}
	slots := int64(properties.Slots())
	if !fits(quota.Quota, used.used, enrollment.Capacity{CPUMillis: slots * cpu, MemoryMiB: slots * memory}) {
		return nil, arm.ErrContainerQuota
	}
	return []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", revision), used.compare()}, nil
}

func (r *Region) DeleteReplicaSet(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress) (*arm.Operation, error) {
	key := r.replicaSetKey(scope, address)
	for range 8 {
		row, err := r.client.Get(ctx, key)
		if err != nil || len(row.Kvs) == 0 {
			return nil, err
		}
		set, err := r.decodeReplicaSet(key, row.Kvs[0].Value)
		if err != nil {
			return nil, err
		}
		current, err := r.operationAt(ctx, scope, set.Operation, row.Header.Revision)
		if err != nil || set.Deleting {
			return current, err
		}
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: deleteReplicaSet, Group: set.Address.Group, Actor: actor,
			Status: arm.OperationInProgress, StartedAt: now}
		set.Operation, set.Deleting = op.ID, true
		changes := []clientv3.Op{putJSON(key, set), putJSON(r.operationKey(scope, op.ID), op), r.replicaAudit(scope, set, op, "delete", now)}
		if current.Status == arm.OperationInProgress {
			current.Status, current.FinishedAt = arm.OperationFailed, &now
			changes = append(changes, putJSON(r.operationKey(scope, current.ID), current))
		}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", row.Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(r.operationKey(scope, op.ID)), "=", 0)).Then(changes...).Commit()
		if err != nil || result.Succeeded {
			return &op, err
		}
	}
	return nil, arm.ErrContainerBusy
}

func (r *Region) replicaAudit(scope arm.SubscriptionScope, set replicaSetRecord, op arm.Operation, action string, now time.Time) clientv3.Op {
	return r.auditOp(scope, arm.AuditEvent{Time: now, Actor: op.Actor, Action: workload.ReplicaSetType + "/" + action,
		Target: set.Address.ID(scope), Outcome: op.Status})
}
