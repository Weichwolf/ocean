package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) gatewayStatusKey(host, slot string) string {
	return r.root + "/application-gateways/status/" + host + "/" + slot
}

func (r *Region) ReportHTTPSGatewayStatus(ctx context.Context, id string, certificate []byte, slot string,
	status enrollment.GatewayStatus) error {
	return r.reportGatewayStatus(ctx, id, certificate, slot, status, false)
}

func (r *Region) ReportWireGuardGatewayStatus(ctx context.Context, id string, certificate []byte, slot string,
	status enrollment.GatewayStatus) error {
	return r.reportGatewayStatus(ctx, id, certificate, slot, status, true)
}

func (r *Region) reportGatewayStatus(ctx context.Context, id string, certificate []byte, slot string,
	status enrollment.GatewayStatus, wireGuard bool) error {
	taskKey := r.gatewayTaskKey(id, slot)
	snapshot, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(r.hostKey("registered", id)),
		clientv3.OpGet(r.hostKey("live", id)),
		clientv3.OpGet(taskKey),
	).Commit()
	if err != nil {
		return err
	}
	if err := r.gatewayHostAuthorized(id, certificate, snapshot); err != nil {
		return err
	}
	task := snapshot.Responses[2].GetResponseRange().Kvs
	if len(task) != 1 {
		return enrollment.ErrGatewayAssignmentChanged
	}
	recordKey := string(task[0].Value)
	records, err := r.client.Get(ctx, recordKey, clientv3.WithRev(snapshot.Header.Revision))
	if err != nil {
		return err
	}
	if len(records.Kvs) != 1 {
		return enrollment.ErrGatewayAssignmentChanged
	}
	var desired gatewayRecord
	if err := json.Unmarshal(records.Kvs[0].Value, &desired); err != nil {
		return err
	}
	if r.gatewayRecordKey(desired.Scope, desired.Resource) != recordKey || desired.Slot != slot ||
		(desired.Site != nil) != wireGuard || desired.generation() != status.Generation || status.Removed && desired.DeleteOperation == "" ||
		(status.Ready || status.OwnsAddress) && desired.DeleteOperation != "" || !slices.Contains(desired.Hosts, id) {
		return enrollment.ErrGatewayAssignmentChanged
	}
	registered := snapshot.Responses[0].GetResponseRange().Kvs[0]
	live := snapshot.Responses[1].GetResponseRange().Kvs[0]
	payload, _ := json.Marshal(status)
	committed, err := r.client.Txn(ctx).If(
		clientv3.Compare(clientv3.ModRevision(string(registered.Key)), "=", registered.ModRevision),
		clientv3.Compare(clientv3.ModRevision(string(live.Key)), "=", live.ModRevision),
		clientv3.Compare(clientv3.ModRevision(taskKey), "=", task[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(recordKey), "=", records.Kvs[0].ModRevision),
	).Then(clientv3.OpPut(r.gatewayStatusKey(id, slot), string(payload), clientv3.WithLease(clientv3.LeaseID(live.Lease)))).Commit()
	if err != nil {
		return err
	}
	if !committed.Succeeded {
		return enrollment.ErrGatewayAssignmentChanged
	}
	if desired.DeleteOperation != "" {
		return r.completeGatewayDeletion(ctx, desired)
	}
	return r.completeGatewayCreation(ctx, desired)
}

// Completion binds the two healthy gateway reports, the public address owner,
// and the ARM result to one transaction. Repeated reports can finish a race.
func (r *Region) completeGatewayCreation(ctx context.Context, desired gatewayRecord) error {
	opKey := r.operationKey(desired.Scope, desired.OperationID)
	inventory := r.inventoryPrefix(desired.Scope)
	gatewayKey, deploymentKey := inventory+desired.Resource.Key(), inventory+desired.Deployment.Key()
	recordKey := r.gatewayRecordKey(desired.Scope, desired.Resource)
	reads := []clientv3.Op{clientv3.OpGet(opKey), clientv3.OpGet(gatewayKey), clientv3.OpGet(deploymentKey), clientv3.OpGet(recordKey)}
	for _, host := range desired.Hosts {
		reads = append(reads, clientv3.OpGet(r.gatewayStatusKey(host, desired.Slot)), clientv3.OpGet(r.hostKey("live", host)))
	}
	snapshot, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return err
	}
	operations, gateways := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	deployments, records := snapshot.Responses[2].GetResponseRange().Kvs, snapshot.Responses[3].GetResponseRange().Kvs
	isSite := desired.Site != nil
	if len(operations) != 1 || len(records) != 1 || len(gateways) != 1 || !isSite && len(deployments) != 1 {
		return enrollment.ErrGatewayAssignmentChanged
	}
	op, err := decodeOperation(operations[0].Value, desired.OperationID)
	kind, action := createApplicationGateway, "Microsoft.Network/applicationGateways/write"
	if isSite {
		kind, action = createSiteConnection, network.SiteConnectionType+"/write"
	}
	if err != nil || op.Kind != kind || op.Status != arm.OperationInProgress {
		return err
	}
	var current gatewayRecord
	if err := json.Unmarshal(records[0].Value, &current); err != nil || current.OperationID != desired.OperationID || current.DeleteOperation != "" {
		return enrollment.ErrGatewayAssignmentChanged
	}
	owners := 0
	guards := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(opKey), "=", operations[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(gatewayKey), "=", gateways[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(recordKey), "=", records[0].ModRevision),
	}
	if !isSite {
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(deploymentKey), "=", deployments[0].ModRevision))
	}
	for index := range desired.Hosts {
		observations := snapshot.Responses[4+2*index].GetResponseRange().Kvs
		live := snapshot.Responses[5+2*index].GetResponseRange().Kvs
		if len(observations) != 1 || len(live) != 1 || live[0].Lease == 0 || live[0].Lease != observations[0].Lease {
			return nil
		}
		var status enrollment.GatewayStatus
		if err := json.Unmarshal(observations[0].Value, &status); err != nil {
			return err
		}
		if status.Generation != desired.OperationID || !status.Ready {
			return nil
		}
		if status.OwnsAddress {
			owners++
		}
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(observations[0].Key)), "=", observations[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(string(live[0].Key)), "=", live[0].ModRevision))
	}
	if owners != 1 || len(desired.Hosts) != 2 {
		return nil
	}
	gateway, err := decodeInventoryResource(gateways[0].Value, desired.Resource.Key())
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var writes []clientv3.Op
	if isSite {
		var properties map[string]any
		if err := json.Unmarshal(gateway.Properties, &properties); err != nil || properties == nil {
			return errors.New("invalid WireGuard site connection projection")
		}
		properties["provisioningState"] = arm.OperationSucceeded
		gateway.Properties, _ = json.Marshal(properties)
		gateway.ProvisioningState = arm.OperationSucceeded
	} else {
		deployment, err := decodeInventoryResource(deployments[0].Value, desired.Deployment.Key())
		if err != nil {
			return err
		}
		if err := finishApplicationGateway(&gateway, &deployment, desired.Scope); err != nil {
			return err
		}
		writes = append(writes, inventoryPut(deploymentKey, &deployment, &deployment, now))
	}
	op.Status, op.FinishedAt = arm.OperationSucceeded, &now
	newOperation, _ := json.Marshal(op)
	writes = append(writes, clientv3.OpPut(opKey, string(newOperation)), inventoryPut(gatewayKey, &gateway, &gateway, now),
		r.auditOp(desired.Scope, arm.AuditEvent{Time: now, Actor: op.Actor, Action: action,
			Target: desired.Resource.ID(desired.Scope), Outcome: "Succeeded"}))
	_, err = r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	return err
}

func finishApplicationGateway(gateway, deployment *arm.InventoryResource, scope arm.SubscriptionScope) error {
	var properties map[string]any
	if err := json.Unmarshal(gateway.Properties, &properties); err != nil || properties == nil {
		return errors.New("invalid Application Gateway inventory projection")
	}
	properties["provisioningState"], properties["operationalState"] = "Succeeded", "Running"
	gateway.Properties, _ = json.Marshal(properties)
	gateway.ProvisioningState = arm.OperationSucceeded
	model := map[string]any{"id": gateway.Address.ID(scope), "name": gateway.Address.Path[strings.LastIndexByte(gateway.Address.Path, '/')+1:],
		"type": "Microsoft.Network/applicationGateways", "location": gateway.Location, "tags": gateway.Tags,
		"properties": gateway.Properties}
	deployment.Properties, _ = json.Marshal(map[string]any{
		"provisioningState": "Succeeded", "mode": "Incremental",
		"outputs":         map[string]any{"applicationGateway": map[string]any{"type": "Object", "value": model}},
		"outputResources": []map[string]string{{"id": gateway.Address.ID(scope)}},
	})
	deployment.ProvisioningState = arm.OperationSucceeded
	return nil
}
