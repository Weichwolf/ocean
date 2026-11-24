package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) DeleteApplicationGateway(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress) (*arm.Operation, error) {
	return r.requestGatewayDeletion(ctx, scope, actor, address, deleteApplicationGateway, "Microsoft.Network/applicationGateways/delete")
}

func (r *Region) DeleteSiteConnection(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress) (*arm.Operation, error) {
	return r.requestGatewayDeletion(ctx, scope, actor, address, deleteSiteConnection, network.SiteConnectionType+"/delete")
}

func (r *Region) requestGatewayDeletion(ctx context.Context, scope arm.SubscriptionScope, actor string,
	address arm.ResourceAddress, kind, action string) (*arm.Operation, error) {
	key := r.gatewayRecordKey(scope, address)
	gatewayKey := r.inventoryPrefix(scope) + address.Key()
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(key), clientv3.OpGet(gatewayKey)).Commit()
		if err != nil {
			return nil, err
		}
		records := snapshot.Responses[0].GetResponseRange().Kvs
		if len(records) == 0 {
			return nil, nil
		}
		var saved gatewayRecord
		if err := json.Unmarshal(records[0].Value, &saved); err != nil || saved.Scope != scope || saved.Resource.Key() != address.Key() {
			return nil, errors.New("invalid Application Gateway desired state")
		}
		if (saved.Site != nil) != (kind == deleteSiteConnection) {
			return nil, errors.New("the gateway resource has an unexpected role")
		}
		if saved.DeleteOperation != "" {
			return r.GetOperation(ctx, scope, saved.DeleteOperation)
		}
		gateways := snapshot.Responses[1].GetResponseRange().Kvs
		if len(gateways) != 1 {
			return nil, errors.New("Application Gateway deletion has no inventory record")
		}
		gateway, err := decodeInventoryResource(gateways[0].Value, address.Key())
		if err != nil {
			return nil, err
		}
		var properties map[string]any
		if err := json.Unmarshal(gateway.Properties, &properties); err != nil || properties == nil {
			return nil, errors.New("invalid Application Gateway inventory projection")
		}
		properties["provisioningState"] = "Deleting"
		gateway.Properties, _ = json.Marshal(properties)
		gateway.ProvisioningState = "Deleting"
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: kind, Group: saved.Resource.Group,
			Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		saved.DeleteOperation = op.ID
		recordData, _ := json.Marshal(saved)
		opData, _ := json.Marshal(op)
		opKey := r.operationKey(scope, op.ID)
		committed, err := r.client.Txn(ctx).If(
			clientv3.Compare(clientv3.ModRevision(key), "=", records[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(gatewayKey), "=", gateways[0].ModRevision),
			clientv3.Compare(clientv3.Version(opKey), "=", 0),
		).Then(clientv3.OpPut(key, string(recordData)), clientv3.OpPut(opKey, string(opData)),
			inventoryPut(gatewayKey, &gateway, &gateway, now),
			r.auditOp(scope, arm.AuditEvent{Time: now, Actor: actor, Action: action,
				Target: address.ID(scope), Outcome: "Accepted"})).Commit()
		if err != nil {
			return nil, err
		}
		if committed.Succeeded {
			return &op, nil
		}
	}
	return nil, arm.ErrGatewayExecutionUnavailable
}

func (r *Region) completeGatewayDeletion(ctx context.Context, desired gatewayRecord) error {
	if len(desired.Hosts) != 2 {
		return errors.New("invalid HTTPS gateway deletion targets")
	}
	deleteKey := r.operationKey(desired.Scope, desired.DeleteOperation)
	createKey := r.operationKey(desired.Scope, desired.OperationID)
	inventory := r.inventoryPrefix(desired.Scope)
	gatewayKey, deploymentKey := inventory+desired.Resource.Key(), inventory+desired.Deployment.Key()
	recordKey := r.gatewayRecordKey(desired.Scope, desired.Resource)
	reads := []clientv3.Op{clientv3.OpGet(deleteKey), clientv3.OpGet(createKey), clientv3.OpGet(gatewayKey),
		clientv3.OpGet(deploymentKey), clientv3.OpGet(recordKey)}
	for _, host := range desired.Hosts {
		reads = append(reads, clientv3.OpGet(r.gatewayStatusKey(host, desired.Slot)), clientv3.OpGet(r.hostKey("live", host)))
	}
	snapshot, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return err
	}
	deletions, creations := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	gateways, deployments := snapshot.Responses[2].GetResponseRange().Kvs, snapshot.Responses[3].GetResponseRange().Kvs
	records := snapshot.Responses[4].GetResponseRange().Kvs
	if len(records) == 0 {
		return nil
	}
	isSite := desired.Site != nil
	if len(deletions) != 1 || len(creations) != 1 || len(gateways) != 1 || !isSite && len(deployments) != 1 {
		return errors.New("HTTPS gateway deletion is missing its inventory or operation records")
	}
	var current gatewayRecord
	if err := json.Unmarshal(records[0].Value, &current); err != nil || current.DeleteOperation != desired.DeleteOperation ||
		current.OperationID != desired.OperationID {
		return enrollment.ErrGatewayAssignmentChanged
	}
	operation, err := decodeOperation(deletions[0].Value, desired.DeleteOperation)
	if err != nil {
		return err
	}
	kind, action := deleteApplicationGateway, "Microsoft.Network/applicationGateways/delete"
	if isSite {
		kind, action = deleteSiteConnection, network.SiteConnectionType+"/delete"
	}
	if operation.Status != arm.OperationInProgress || operation.Kind != kind {
		return nil
	}
	slotKey := r.gatewaySlotKey(desired.Slot)
	guards := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(deleteKey), "=", deletions[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(createKey), "=", creations[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(gatewayKey), "=", gateways[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(recordKey), "=", records[0].ModRevision),
		clientv3.Compare(clientv3.Value(slotKey), "=", recordKey),
		clientv3.Compare(clientv3.Value(desired.SubnetLock), "=", recordKey),
	}
	if !isSite {
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(deploymentKey), "=", deployments[0].ModRevision))
	}
	mutations := []clientv3.Op{clientv3.OpDelete(recordKey), clientv3.OpDelete(gatewayKey),
		clientv3.OpDelete(desired.SubnetLock), clientv3.OpDelete(slotKey)}
	for index, host := range desired.Hosts {
		observations := snapshot.Responses[5+2*index].GetResponseRange().Kvs
		live := snapshot.Responses[6+2*index].GetResponseRange().Kvs
		if len(observations) != 1 || len(live) != 1 || live[0].Lease == 0 || live[0].Lease != observations[0].Lease {
			return nil
		}
		var status enrollment.GatewayStatus
		if err := json.Unmarshal(observations[0].Value, &status); err != nil {
			return err
		}
		if status.Generation != desired.DeleteOperation || !status.Removed {
			return nil
		}
		taskKey := r.gatewayTaskKey(host, desired.Slot)
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(observations[0].Key)), "=", observations[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(string(live[0].Key)), "=", live[0].ModRevision),
			clientv3.Compare(clientv3.Value(taskKey), "=", recordKey))
		mutations = append(mutations, clientv3.OpDelete(taskKey), clientv3.OpDelete(string(observations[0].Key)))
	}
	gateway, err := decodeInventoryResource(gateways[0].Value, desired.Resource.Key())
	if err != nil {
		return err
	}
	refGuards, refWrites, err := r.inventoryReferenceChanges(ctx, desired.Scope, desired.Resource, &gateway, nil, snapshot.Header.Revision, nil)
	if err != nil {
		return err
	}
	guards = append(guards, refGuards...)
	mutations = append(mutations, refWrites...)
	creation, err := decodeOperation(creations[0].Value, desired.OperationID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if creation.Status == arm.OperationInProgress {
		creation.Status, creation.FinishedAt = arm.OperationFailed, &now
		canceled, _ := json.Marshal(creation)
		mutations = append(mutations, clientv3.OpPut(createKey, string(canceled)))
		if !isSite {
			deployment, err := decodeInventoryResource(deployments[0].Value, desired.Deployment.Key())
			if err != nil {
				return err
			}
			deployment.ProvisioningState = arm.OperationFailed
			deployment.Properties = json.RawMessage(`{"provisioningState":"Failed","mode":"Incremental"}`)
			mutations = append(mutations, inventoryPut(deploymentKey, &deployment, &deployment, now))
		}
	}
	operation.Status, operation.FinishedAt = arm.OperationSucceeded, &now
	completed, _ := json.Marshal(operation)
	mutations = append(mutations, clientv3.OpPut(deleteKey, string(completed)), r.auditOp(desired.Scope, arm.AuditEvent{
		Time: now, Actor: operation.Actor, Action: action,
		Target: desired.Resource.ID(desired.Scope), Outcome: "Succeeded"}))
	_, err = r.client.Txn(ctx).If(guards...).Then(mutations...).Commit()
	return err
}
