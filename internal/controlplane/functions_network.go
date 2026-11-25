package controlplane

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const integrateFunction = "IntegrateFunctionAppNetwork"

func (r *Region) IntegrateFunction(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	subnet string) (*arm.Operation, error) {
	key := r.containerKey(scope, address)
	for range 8 {
		prior, record, op, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return nil, err
		}
		if op == nil || record.Desired == workload.Removed {
			return nil, arm.ErrContainerMissing
		}
		reservation := record.Reservation
		if reservation.SubnetID != "" {
			if !strings.EqualFold(reservation.SubnetID, subnet) {
				return nil, arm.ErrContainerChanged
			}
			if op.Kind == integrateFunction && op.Status != arm.OperationSucceeded {
				return op, nil
			}
			return nil, nil
		}
		if op.Status != arm.OperationSucceeded {
			return nil, arm.ErrContainerBusy
		}
		config, err := r.decryptContainer(scope, record)
		if err != nil {
			return nil, err
		}
		if config.Function == nil || !record.PublicIP.IsValid() {
			return nil, arm.ErrContainerChanged
		}
		if request := config.Function.Runtime.Request; request != nil && time.Now().Before(request.ExpiresAt) {
			return nil, arm.ErrContainerBusy
		}
		allocation, err := r.allocateSubnet(ctx, scope, subnet)
		if err != nil {
			return nil, err
		}
		conditions, writes, err := r.claimContainerNetwork(ctx, scope, key, subnet, network.FunctionDelegationService)
		if err != nil {
			return nil, err
		}
		requestKey := r.armPrefix(scope) + "placement-requests/" + reservation.ID
		cellKey := r.reservationKey(scope, reservation.Cell, reservation.ID)
		hostKey := r.hostReservationKey(scope, reservation.HostID, reservation.ID)
		previous, _ := json.Marshal(reservation)
		conditions = append(conditions, allocation.guards...)
		conditions = append(conditions, clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.Value(requestKey), "=", string(previous)), clientv3.Compare(clientv3.Value(cellKey), "=", string(previous)),
			clientv3.Compare(clientv3.Version(hostKey), ">", 0))
		reservation.SubnetID, reservation.PrivateIPv4 = subnet, allocation.address
		assignment := enrollment.Assignment{ID: reservation.ID, Generation: reservation.Generation, Cell: reservation.Cell,
			TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Role: reservation.Role, Resources: reservation.Resources,
			SubnetID: subnet, PrivateIPv4: allocation.address}
		config.Properties.IPAddress.Type = "Private"
		config.Properties.SubnetIDs = []workload.Subnet{{ID: subnet}}
		config.Function.Runtime.Configuration = operationID()
		config.Function.Runtime.Request = nil
		record.Reservation = reservation
		now := time.Now().UTC()
		job := arm.Operation{ID: operationID(), Kind: integrateFunction, Group: record.Address.Group, Actor: actor,
			Status: arm.OperationInProgress, StartedAt: now}
		record.Operation = job.ID
		if err := r.sealFunctionConfig(scope, &record, config); err != nil {
			return nil, err
		}
		projection := projectContainer(config, record, prior.CreatedAt, now, arm.OperationInProgress)
		opKey := r.operationKey(scope, job.ID)
		conditions = append(conditions, clientv3.Compare(clientv3.Version(opKey), "=", 0))
		writes = append(writes, putJSON(requestKey, reservation), putJSON(cellKey, reservation), putJSON(hostKey, assignment),
			clientv3.OpPut(allocation.key, reservation.Generation), putJSON(key, record), putJSON(opKey, job),
			putJSON(r.inventoryPrefix(scope)+address.Key(), projection), r.containerAudit(scope, record, job, "virtualNetworkConnections/write", now))
		result, err := r.client.Txn(ctx).If(conditions...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return &job, err
		}
	}
	return nil, arm.ErrContainerBusy
}

func (r *Region) releaseFunctionPublicAddress(ctx context.Context, scope arm.SubscriptionScope, record *containerRecord) (clientv3.Cmp, clientv3.Op, error) {
	pool, revision, err := r.readPublicIPPool(ctx, 0)
	if err != nil {
		return clientv3.Cmp{}, clientv3.Op{}, err
	}
	key := r.containerKey(scope, record.Address)
	if pool.Allocations[key] != record.PublicIP {
		return clientv3.Cmp{}, clientv3.Op{}, enrollment.ErrWorkloadChanged
	}
	delete(pool.Allocations, key)
	record.PublicIP = netip.Addr{}
	check, write := r.publicIPPoolUpdate(pool, revision)
	return check, write, nil
}

func workloadDelegation(config workload.ContainerGroup) string {
	if config.Function != nil {
		return network.FunctionDelegationService
	}
	return network.ContainerDelegationService
}

func isFunctionRecord(record containerRecord) bool {
	return strings.HasPrefix(strings.ToLower(record.Address.Path), strings.ToLower(functions.SiteType)+"/")
}
