package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) DeleteVPNResource(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress) (*arm.Operation, error) {
	if r.ipsec == nil {
		return nil, arm.ErrGatewayExecutionUnavailable
	}
	switch {
	case strings.HasPrefix(strings.ToLower(address.Path), strings.ToLower(arm.VPNLocalGatewayType)+"/"):
		_, _, err := r.ChangeInventoryResource(ctx, scope, address, actor, arm.VPNLocalGatewayType+"/delete", "",
			func(_ *arm.InventoryResource, _ arm.ResourceAddress) (*arm.InventoryResource, error) { return nil, nil })
		if errors.Is(err, arm.ErrGroupMissing) {
			return nil, nil
		}
		return nil, err
	case strings.HasPrefix(strings.ToLower(address.Path), strings.ToLower(arm.VPNVirtualGatewayType)+"/"):
		return r.requestIPsecDeletion(ctx, scope, actor, address, deleteIPsecGateway)
	case strings.HasPrefix(strings.ToLower(address.Path), strings.ToLower(arm.VPNConnectionType)+"/"):
		return r.requestIPsecDeletion(ctx, scope, actor, address, deleteIPsecConnection)
	default:
		return nil, arm.ErrLinkedResourceMissing
	}
}

func (r *Region) requestIPsecDeletion(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress, kind string) (*arm.Operation, error) {
	resourceKey := r.inventoryPrefix(scope) + address.Key()
	for range 8 {
		items, err := r.client.Get(ctx, resourceKey)
		if err != nil || len(items.Kvs) == 0 {
			return nil, err
		}
		entry := items.Kvs[0]
		resource, err := decodeInventoryResource(entry.Value, address.Key())
		if err != nil {
			return nil, err
		}
		gateway := resource.Address
		if kind == deleteIPsecConnection {
			if len(resource.References) != 2 {
				return nil, errors.New("IPsec connection is missing its gateway references")
			}
			gateway = resource.References[0]
		}
		recordKey := r.vpnKey(scope, gateway)
		groupKey := r.groupPrefix(scope) + strings.ToLower(resource.Address.Group)
		refs := r.dependentsPrefix(scope, resource.Address)
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(recordKey, clientv3.WithRev(items.Header.Revision)),
			clientv3.OpGet(groupKey, clientv3.WithRev(items.Header.Revision)),
			clientv3.OpGet(refs, clientv3.WithRev(items.Header.Revision), clientv3.WithPrefix(), clientv3.WithCountOnly())).Commit()
		if err != nil {
			return nil, err
		}
		records, groups := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
		if len(records) != 1 || len(groups) != 1 {
			return nil, errors.New("IPsec deletion is missing its gateway or group")
		}
		record, err := r.decodeIPsecGateway(records[0], recordKey)
		if err != nil {
			return nil, err
		}
		group, err := decodeGroup(groups[0].Value, strings.ToLower(resource.Address.Group))
		if err != nil {
			return nil, err
		}
		if group.DeleteOperation != "" {
			return nil, arm.ErrGroupDeleting
		}
		if kind == deleteIPsecConnection && (record.Connection == nil || record.Connection.Resource != resource.Address) {
			return nil, errors.New("IPsec connection has no matching reservation")
		}
		if record.Kind == kind {
			return r.ipsecOperationAt(ctx, scope, record.Generation, items.Header.Revision)
		}
		if read.Responses[2].GetResponseRange().Count != 0 || kind == deleteIPsecGateway && record.Connection != nil {
			return nil, arm.ErrLinkedResourceInUse
		}
		op := newIPsecOperation(kind, resource.Address.Group, actor)
		opKey := r.operationKey(scope, op.ID)
		resource, err = projectIPsecState(resource, "Deleting", "NotConnected")
		if err != nil {
			return nil, err
		}
		guards := []clientv3.Cmp{keyUnchanged(entry), keyUnchanged(records[0]), keyUnchanged(groups[0]),
			clientv3.Compare(clientv3.Version(refs), "=", 0).WithPrefix(), clientv3.Compare(clientv3.Version(opKey), "=", 0)}
		writes := []clientv3.Op{putIPsecOperation(opKey, op), inventoryPut(resourceKey, &resource, &resource, op.StartedAt),
			clientv3.OpDelete(r.vpnObservationKey(record.Slot)), r.ipsecAudit(scope, op, resource.Address, "Accepted")}
		priorGuards, priorWrites, err := r.cancelIPsecCreation(ctx, record, resource, op.StartedAt, items.Header.Revision)
		if err != nil {
			return nil, err
		}
		if record.Connection != nil {
			record.Connection.KeyEnvelope = nil
		}
		record.Generation, record.Kind = op.ID, kind
		writes = append(writes, putIPsecRecord(recordKey, record))
		committed, err := r.client.Txn(ctx).If(append(guards, priorGuards...)...).Then(append(writes, priorWrites...)...).Commit()
		if err != nil {
			return nil, err
		}
		if committed.Succeeded {
			return &op, nil
		}
	}
	return nil, arm.ErrGatewayExecutionUnavailable
}

func projectIPsecState(resource arm.InventoryResource, state, connectionStatus string) (arm.InventoryResource, error) {
	var properties map[string]any
	if err := json.Unmarshal(resource.Properties, &properties); err != nil || properties == nil {
		return arm.InventoryResource{}, errors.New("invalid IPsec inventory projection")
	}
	properties["provisioningState"] = state
	if _, hasConnectionStatus := properties["connectionStatus"]; hasConnectionStatus {
		properties["connectionStatus"] = connectionStatus
	}
	resource.ProvisioningState = state
	resource.Properties, _ = json.Marshal(properties)
	return resource, nil
}

func (r *Region) cancelIPsecCreation(ctx context.Context, record vpnGatewayRecord, resource arm.InventoryResource,
	now time.Time, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	priorKey := r.operationKey(record.Scope, record.Generation)
	entries, err := r.client.Get(ctx, priorKey, clientv3.WithRev(revision))
	if err != nil {
		return nil, nil, err
	}
	if len(entries.Kvs) != 1 {
		return nil, nil, errors.New("IPsec deletion is missing the prior operation")
	}
	entry := entries.Kvs[0]
	prior, err := decodeOperation(entry.Value, record.Generation)
	if err != nil || prior.Status != arm.OperationInProgress {
		return nil, nil, err
	}
	prior.Status, prior.FinishedAt = arm.OperationFailed, &now
	prior.Error = &arm.OperationError{Code: "ResourceBeingDeleted", Message: "The IPsec resource was deleted before provisioning completed."}
	guards := []clientv3.Cmp{keyUnchanged(entry)}
	writes := []clientv3.Op{putIPsecOperation(priorKey, *prior), r.ipsecAudit(record.Scope, *prior, resource.Address, "Failed")}
	if prior.Kind == createIPsecConnection && record.Connection != nil {
		refGuards, refWrites, err := r.ipsecDeploymentCompletion(ctx, record, resource, prior.Status, nil, now, revision)
		return append(guards, refGuards...), append(writes, refWrites...), err
	}
	return guards, writes, nil
}

func (r *Region) ipsecDeleteChanges(ctx context.Context, recordKey string, record vpnGatewayRecord, resource arm.InventoryResource,
	entry *mvccpb.KeyValue, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	scope := record.Scope
	guards, writes, err := r.inventoryReferenceChanges(ctx, scope, resource.Address, &resource, nil, revision, nil)
	if err != nil {
		return nil, nil, err
	}
	guards = append(guards, clientv3.Compare(clientv3.Version(r.dependentsPrefix(scope, resource.Address)), "=", 0).WithPrefix())
	writes = append(writes, clientv3.OpDelete(string(entry.Key)))
	if record.Kind == deleteIPsecConnection {
		record.Kind, record.Connection = createIPsecGateway, nil
		writes = append(writes, putIPsecRecord(recordKey, record))
		return guards, writes, nil
	}
	if record.Connection != nil || len(record.SubnetLocks) != 2 {
		return nil, nil, enrollment.ErrGatewayAssignmentChanged
	}
	keys := []string{r.vpnTaskKey(record.Host, record.Slot), r.vpnSlotKey(record.Slot), record.SubnetLocks[0], record.SubnetLocks[1]}
	for _, key := range keys {
		guards = append(guards, clientv3.Compare(clientv3.Value(key), "=", recordKey))
		writes = append(writes, clientv3.OpDelete(key))
	}
	writes = append(writes, clientv3.OpDelete(recordKey), clientv3.OpDelete(r.vpnObservationKey(record.Slot)))
	return guards, writes, nil
}
