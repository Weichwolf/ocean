package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) RunFunctionAdmin(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	request functions.AdminRequest) (functions.AdminResult, error) {
	var result functions.AdminResult
	key := r.containerKey(scope, address)
	request.ID, request.ExpiresAt = operationID(), time.Now().Add(18*time.Second)
	admitted := false
	for range 8 {
		_, record, operation, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return result, err
		}
		if operation == nil || record.Desired == workload.Removed {
			return result, arm.ErrContainerMissing
		}
		if record.Observed != workload.Running || operation.Status != arm.OperationSucceeded {
			return result, arm.ErrContainerBusy
		}
		config, err := r.decryptContainer(scope, record)
		if err != nil {
			return result, err
		}
		if config.Function == nil {
			return result, arm.ErrContainerMissing
		}
		prior := config.Function.Runtime.Request
		if prior != nil && time.Now().Before(prior.ExpiresAt) {
			return result, arm.ErrContainerBusy
		}
		config.Function.Runtime.Request = &request
		if err := r.sealFunctionConfig(scope, &record, config); err != nil {
			return result, err
		}
		action := functions.SiteType + "/functions/read"
		if request.Function != "" {
			action = functions.SiteType + "/functions/listKeys/action"
		}
		if request.Name != "" {
			action = functions.SiteType + "/functions/keys/write"
		}
		event := arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: action, Target: address.ID(scope), Outcome: arm.OperationInProgress}
		txn, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision)).
			Then(putJSON(key, record), r.auditOp(scope, event), clientv3.OpPut(key+"/function-admin-actor", actor)).Commit()
		if err != nil {
			return result, err
		}
		if txn.Succeeded {
			admitted = true
			break
		}
	}
	if !admitted {
		return result, arm.ErrContainerBusy
	}
	return r.awaitFunctionAdmin(ctx, scope, key+"/function-admin/"+request.ID, request.ID)
}

func (r *Region) sealFunctionConfig(scope arm.SubscriptionScope, record *containerRecord, config workload.ContainerGroup) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	defer clear(data)
	record.Config = r.workloads.sealer.Seal(nil, nil, data, r.containerBinding(scope, *record))
	return nil
}

func (r *Region) awaitFunctionAdmin(ctx context.Context, scope arm.SubscriptionScope, key, id string) (functions.AdminResult, error) {
	var result functions.AdminResult
	ticker := time.NewTicker(160 * time.Millisecond)
	defer ticker.Stop()
	for {
		rows, err := r.client.Get(ctx, key)
		if err != nil {
			return result, err
		}
		if len(rows.Kvs) == 1 {
			data, err := r.workloads.sealer.Open(nil, nil, rows.Kvs[0].Value, []byte(key))
			if err != nil {
				return result, errors.New("cannot open the Function host response")
			}
			defer clear(data)
			if json.Unmarshal(data, &result) != nil || result.ID != id {
				return result, errors.New("invalid persisted Function host response")
			}
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Region) finishFunctionAdmin(ctx context.Context, scope arm.SubscriptionScope, record *containerRecord, config workload.ContainerGroup,
	result functions.AdminResult) ([]clientv3.Cmp, []clientv3.Op, error) {
	if config.Function == nil || config.Function.Runtime.Request == nil || result.ID != config.Function.Runtime.Request.ID ||
		result.Status < 100 || result.Status > 599 || len(result.Body) > 48<<10 ||
		time.Now().After(config.Function.Runtime.Request.ExpiresAt) {
		return nil, nil, enrollment.ErrWorkloadChanged
	}
	key := r.containerKey(scope, record.Address)
	actorKey := key + "/function-admin-actor"
	actors, err := r.client.Get(ctx, actorKey)
	if err != nil {
		return nil, nil, err
	}
	if len(actors.Kvs) != 1 {
		return nil, nil, enrollment.ErrWorkloadChanged
	}
	lease, err := r.client.Grant(ctx, 35)
	if err != nil {
		return nil, nil, err
	}
	resultKey := key + "/function-admin/" + result.ID
	body, err := json.Marshal(result)
	if err != nil {
		return nil, nil, err
	}
	defer clear(body)
	data := r.workloads.sealer.Seal(nil, nil, body, []byte(resultKey))
	request := config.Function.Runtime.Request
	action := functions.SiteType + "/functions/read"
	if request.Function != "" {
		action = functions.SiteType + "/functions/listKeys/action"
	}
	if request.Name != "" {
		action = functions.SiteType + "/functions/keys/write"
	}
	outcome := arm.OperationSucceeded
	if result.Status < 200 || result.Status >= 300 {
		outcome = arm.OperationFailed
	}
	config.Function.Runtime.Request = nil
	if err := r.sealFunctionConfig(scope, record, config); err != nil {
		return nil, nil, err
	}
	event := arm.AuditEvent{Time: time.Now().UTC(), Actor: string(actors.Kvs[0].Value), Action: action, Target: record.Address.ID(scope), Outcome: outcome}
	return []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(actorKey), "=", actors.Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(resultKey), "=", 0)},
		[]clientv3.Op{clientv3.OpPut(resultKey, string(data), clientv3.WithLease(lease.ID)), clientv3.OpDelete(actorKey), r.auditOp(scope, event)}, nil
}
