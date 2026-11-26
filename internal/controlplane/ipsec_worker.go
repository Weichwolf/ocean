package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type ipsecObservation struct {
	Status               enrollment.IPsecStatus
	RegistrationRevision int64
	Received             time.Time
}

func (r *Region) IPsecAssignments(ctx context.Context, id string, certificate []byte) ([]enrollment.IPsecAssignment, error) {
	result := make([]enrollment.IPsecAssignment, 0)
	if r.ipsec == nil {
		return result, nil
	}
	prefix := r.vpnTaskKey(id, "")
	snapshot, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(r.hostKey("registered", id)), clientv3.OpGet(r.hostKey("live", id)),
		clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithLimit(65)),
	).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.authorizeHostRole(id, certificate, "gateway", snapshot); err != nil {
		return nil, err
	}
	tasks := snapshot.Responses[2].GetResponseRange().Kvs
	if len(tasks) > 64 {
		return nil, errors.New("too many assigned IPsec slots")
	}
	var leases []clientv3.Cmp
	registered, live := snapshot.Responses[0].GetResponseRange().Kvs[0], snapshot.Responses[1].GetResponseRange().Kvs[0]
	leases = append(leases, keyUnchanged(registered), keyUnchanged(live))
	for _, task := range tasks {
		assignment, guards, err := r.ipsecAssignmentAt(ctx, task, id, strings.TrimPrefix(string(task.Key), prefix), snapshot.Header.Revision)
		if err != nil {
			for _, item := range result {
				clear(item.SharedKey)
			}
			return nil, err
		}
		result = append(result, assignment)
		leases = append(leases, guards...)
	}
	check, err := r.client.Txn(ctx).If(leases...).Then(clientv3.OpGet(r.hostKey("registered", id), clientv3.WithCountOnly())).Commit()
	if err != nil || !check.Succeeded {
		for _, item := range result {
			clear(item.SharedKey)
		}
		if err == nil {
			err = enrollment.ErrGatewayAssignmentChanged
		}
		return nil, err
	}
	return result, nil
}

func (r *Region) ipsecAssignmentAt(ctx context.Context, task *mvccpb.KeyValue, id, slot string, revision int64) (enrollment.IPsecAssignment, []clientv3.Cmp, error) {
	var result enrollment.IPsecAssignment
	key := string(task.Value)
	if !strings.HasPrefix(key, r.root+"/tenants/") {
		return result, nil, errors.New("invalid IPsec assignment key")
	}
	items, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return result, nil, err
	}
	if len(items.Kvs) != 1 {
		return result, nil, enrollment.ErrGatewayAssignmentChanged
	}
	record, err := r.decodeIPsecGateway(items.Kvs[0], key)
	if err != nil {
		return result, nil, err
	}
	if record.Host != id || record.Slot != slot {
		return result, nil, enrollment.ErrGatewayAssignmentChanged
	}
	result = enrollment.IPsecAssignment{Slot: record.Slot, Generation: record.Generation, PublicIPv4: record.PublicIPv4,
		InsideIPv4: record.InsideIPv4, ProtectedPrefixes: r.ipsec.protected,
		Remove:         record.Kind == deleteIPsecGateway || record.Kind == deleteIPsecConnection,
		ReleaseAddress: record.Kind == deleteIPsecGateway}
	if !result.Remove && record.Connection != nil {
		secret, err := r.ipsec.sealer.Open(nil, nil, record.Connection.KeyEnvelope, ipsecEnvelopeContext(key, record.Connection.Resource))
		if err != nil {
			return enrollment.IPsecAssignment{}, nil, errors.New("the IPsec shared key envelope could not be opened")
		}
		result.Peer, result.SharedKey = &record.Connection.Peer, secret
	}
	return result, []clientv3.Cmp{keyUnchanged(task), keyUnchanged(items.Kvs[0])}, nil
}

func (r *Region) ReportIPsecStatus(ctx context.Context, id string, certificate []byte, slot string, status enrollment.IPsecStatus) error {
	if r.ipsec == nil {
		return enrollment.ErrGatewayAssignmentChanged
	}
	taskKey := r.vpnTaskKey(id, slot)
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", id)), clientv3.OpGet(r.hostKey("live", id)),
		clientv3.OpGet(taskKey)).Commit()
	if err != nil {
		return err
	}
	if err := r.authorizeHostRole(id, certificate, "gateway", snapshot); err != nil {
		return err
	}
	tasks := snapshot.Responses[2].GetResponseRange().Kvs
	if len(tasks) != 1 {
		return enrollment.ErrGatewayAssignmentChanged
	}
	recordKey := string(tasks[0].Value)
	if !strings.HasPrefix(recordKey, r.root+"/tenants/") {
		return enrollment.ErrGatewayAssignmentChanged
	}
	entries, err := r.client.Get(ctx, recordKey, clientv3.WithRev(snapshot.Header.Revision))
	if err != nil {
		return err
	}
	if len(entries.Kvs) != 1 {
		return enrollment.ErrGatewayAssignmentChanged
	}
	record, err := r.decodeIPsecGateway(entries.Kvs[0], recordKey)
	if err != nil {
		return err
	}
	deleting := record.Kind == deleteIPsecGateway || record.Kind == deleteIPsecConnection
	if record.Host != id || record.Slot != slot || record.Generation != status.Generation ||
		status.Removed && (!deleting || status.Ready) || status.Ready && deleting ||
		status.Connected && (!status.Ready || record.Connection == nil) {
		return enrollment.ErrGatewayAssignmentChanged
	}
	registered, live := snapshot.Responses[0].GetResponseRange().Kvs[0], snapshot.Responses[1].GetResponseRange().Kvs[0]
	now := time.Now().UTC()
	observed, _ := json.Marshal(ipsecObservation{status, registered.ModRevision, now})
	guards := []clientv3.Cmp{keyUnchanged(registered), keyUnchanged(live), keyUnchanged(tasks[0]), keyUnchanged(entries.Kvs[0])}
	writes := []clientv3.Op{clientv3.OpPut(r.vpnObservationKey(slot), string(observed), clientv3.WithLease(clientv3.LeaseID(live.Lease)))}
	if status.Ready || status.Removed {
		opGuards, opWrites, err := r.ipsecCompletion(ctx, recordKey, record, status, now, snapshot.Header.Revision)
		if err != nil {
			return err
		}
		guards, writes = append(guards, opGuards...), append(writes, opWrites...)
	}
	if status.Removed && record.Kind == deleteIPsecGateway {
		writes = writes[1:] // Final teardown deletes the observation with the task.
	}
	written, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err != nil {
		return err
	}
	if !written.Succeeded {
		return enrollment.ErrGatewayAssignmentChanged
	}
	return nil
}

func (r *Region) ipsecCompletion(ctx context.Context, key string, record vpnGatewayRecord, status enrollment.IPsecStatus,
	now time.Time, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	target := record.Gateway
	if record.Connection != nil {
		target = record.Connection.Resource
	}
	opKey, inventoryKey := r.operationKey(record.Scope, record.Generation), r.inventoryPrefix(record.Scope)+target.Key()
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(opKey, clientv3.WithRev(revision)),
		clientv3.OpGet(inventoryKey, clientv3.WithRev(revision))).Commit()
	if err != nil {
		return nil, nil, err
	}
	operations, entries := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	if len(operations) != 1 || len(entries) != 1 {
		return nil, nil, enrollment.ErrGatewayAssignmentChanged
	}
	op, err := decodeOperation(operations[0].Value, record.Generation)
	if err != nil || op.Status != arm.OperationInProgress {
		return nil, nil, err
	}
	if op.Kind != record.Kind {
		return nil, nil, errors.New("IPsec operation and assignment do not match")
	}
	resource, err := decodeInventoryResource(entries[0].Value, target.Key())
	if err != nil {
		return nil, nil, err
	}
	op.Status, op.FinishedAt = arm.OperationSucceeded, &now
	guards := []clientv3.Cmp{keyUnchanged(operations[0]), keyUnchanged(entries[0])}
	writes := []clientv3.Op{putIPsecOperation(opKey, *op), r.ipsecAudit(record.Scope, *op, target, "Succeeded")}
	if status.Removed {
		refGuards, refWrites, err := r.ipsecDeleteChanges(ctx, key, record, resource, entries[0], revision)
		return append(guards, refGuards...), append(writes, refWrites...), err
	}
	resource, err = projectIPsecState(resource, arm.OperationSucceeded, "NotConnected")
	if err != nil {
		return nil, nil, err
	}
	writes = append(writes, inventoryPut(inventoryKey, &resource, &resource, now))
	if record.Connection == nil {
		return guards, writes, nil
	}
	output := resource
	if status.Connected {
		output, err = projectIPsecState(resource, arm.OperationSucceeded, "Connected")
		if err != nil {
			return nil, nil, err
		}
	}
	deployGuards, deployWrites, err := r.ipsecDeploymentCompletion(ctx, record, resource, arm.OperationSucceeded, &output, now, revision)
	return append(guards, deployGuards...), append(writes, deployWrites...), err
}

func (r *Region) ipsecDeploymentCompletion(ctx context.Context, record vpnGatewayRecord, connection arm.InventoryResource,
	state string, output *arm.InventoryResource, now time.Time, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	var guards []clientv3.Cmp
	var writes []clientv3.Op
	for _, address := range record.Connection.Deployments {
		key := r.inventoryPrefix(record.Scope) + address.Key()
		entries, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
		if err != nil {
			return nil, nil, err
		}
		if len(entries.Kvs) != 1 {
			return nil, nil, errors.New("IPsec connection deployment is missing")
		}
		deployment := ipsecDeploymentResource(record.Scope, address, connection.Address, connection.Location, state, output)
		guard, write, err := ipsecDeploymentWrite(key, entries.Kvs, &deployment, now)
		if err != nil {
			return nil, nil, err
		}
		guards, writes = append(guards, guard), append(writes, write)
	}
	return guards, writes, nil
}

func (r *Region) GetVPNResource(ctx context.Context, scope arm.SubscriptionScope, reader string, address arm.ResourceAddress) (*arm.InventoryResource, error) {
	key := r.inventoryPrefix(scope) + address.Key()
	read, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(key))
	if err != nil || len(read.Kvs) == 0 {
		return nil, err
	}
	resource, err := decodeInventoryResource(read.Kvs[0].Value, address.Key())
	if err != nil {
		return nil, err
	}
	if r.ipsec == nil || !strings.HasPrefix(strings.ToLower(address.Path), strings.ToLower(arm.VPNConnectionType)+"/") ||
		resource.ProvisioningState != arm.OperationSucceeded || len(resource.References) != 2 {
		return &resource, nil
	}
	gatewayKey := r.vpnKey(scope, resource.References[0])
	entries, err := r.client.Get(ctx, gatewayKey, clientv3.WithRev(read.Header.Revision))
	if err != nil {
		return nil, err
	}
	if len(entries.Kvs) != 1 {
		return nil, errors.New("IPsec connection has no regional gateway reservation")
	}
	record, err := r.decodeIPsecGateway(entries.Kvs[0], gatewayKey)
	if err != nil {
		return nil, err
	}
	if record.Kind != createIPsecConnection || record.Connection == nil || record.Connection.Resource != resource.Address {
		return nil, errors.New("IPsec connection has a mismatched regional reservation")
	}
	online, err := r.ipsecObservedConnected(ctx, record, read.Header.Revision)
	if err != nil || !online {
		return &resource, err
	}
	resource, err = projectIPsecState(resource, arm.OperationSucceeded, "Connected")
	return &resource, err
}

func (r *Region) ipsecObservedConnected(ctx context.Context, record vpnGatewayRecord, revision int64) (bool, error) {
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.vpnObservationKey(record.Slot), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("registered", record.Host), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("live", record.Host), clientv3.WithRev(revision))).Commit()
	if err != nil {
		return false, err
	}
	items, registered, live := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs,
		read.Responses[2].GetResponseRange().Kvs
	if len(items) != 1 || len(registered) != 1 || len(live) != 1 || items[0].Lease == 0 || items[0].Lease != live[0].Lease {
		return false, nil
	}
	var observation ipsecObservation
	if err := json.Unmarshal(items[0].Value, &observation); err != nil {
		return false, fmt.Errorf("invalid IPsec status observation: %w", err)
	}
	age := time.Since(observation.Received)
	return observation.Status.Connected && observation.Status.Generation == record.Generation && age >= 0 && age < 4*time.Second &&
		observation.RegistrationRevision == registered[0].ModRevision, nil
}
