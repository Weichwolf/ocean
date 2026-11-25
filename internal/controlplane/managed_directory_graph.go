package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type directoryGraphQueue struct {
	ID         string `json:"id"`
	Generation string `json:"generation"`
	Operation  string `json:"operation"`
	ExpiresAt  int64  `json:"expiresAt"`
	Actor      string `json:"actor"`
	Sealed     []byte `json:"sealed"`
}

func (p directoryGraphQueue) label(queue string) []byte {
	return []byte(queue + "/" + p.Generation + "/" + p.ID + "/" + p.Operation)
}

func (r *Region) directoryGraphTaskKey(d identity.ManagedDirectory) string {
	return r.root + "/managed-directory-graph/" + d.TenantID + "/" + d.ID
}

func directoryGraphAudit(actor, operation, id, outcome string) arm.AuditEvent {
	return arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: "Ocean.Identity/directories/graph/" + operation,
		Target: id, Outcome: outcome}
}

func (r *Region) RunDirectoryGraph(ctx context.Context, tenant identity.TenantReservation, input enrollment.DirectoryGraphInput) (enrollment.DirectoryGraphResult, error) {
	var empty enrollment.DirectoryGraphResult
	if r.workloads == nil || !input.Valid() {
		return empty, errors.New("invalid directory Graph operation")
	}
	for range 6 {
		directory, guards, revision, err := r.managedDirectorySnapshot(ctx, tenant)
		if err != nil {
			return empty, err
		}
		if directory == nil || directory.ProvisionedAt.IsZero() {
			return empty, identity.ErrDirectoryJoinUnavailable
		}
		writer, writerGuards, err := r.readyDirectoryWriter(ctx, *directory, revision)
		if err != nil {
			return empty, err
		}
		scope := arm.SubscriptionScope{TenantID: directory.TenantID, SubscriptionID: directory.SubscriptionID}
		key := r.directoryGraphTaskKey(*directory)
		active, err := r.client.Get(ctx, key, clientv3.WithRev(revision), clientv3.WithCountOnly())
		if err != nil {
			return empty, err
		}
		if active.Count != 0 {
			return empty, identity.ErrDirectoryGraphBusy
		}
		lease, err := r.client.Grant(ctx, 20)
		if err != nil {
			return empty, err
		}
		queued := directoryGraphQueue{ID: operationID(), Generation: writer.Generation, Operation: input.Operation,
			ExpiresAt: time.Now().Unix() + 18, Actor: tenant.Administrator}
		data, _ := json.Marshal(input)
		queued.Sealed = r.workloads.sealer.Seal(nil, nil, data, queued.label(key))
		clear(data)
		serialized, _ := json.Marshal(queued)
		writes := []clientv3.Op{clientv3.OpPut(key, string(serialized), clientv3.WithLease(lease.ID))}
		if input.Mutates() {
			writes = append(writes, r.auditOp(scope, directoryGraphAudit(tenant.Administrator, input.Operation, queued.ID, arm.OperationInProgress)))
		}
		guards = append(guards, writerGuards...)
		guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil {
			return empty, err
		}
		if result.Succeeded {
			return r.waitDirectoryGraph(ctx, key+"/results/"+queued.ID, queued)
		}
		_, _ = r.client.Revoke(ctx, lease.ID)
	}
	return empty, identity.ErrDirectoryGraphBusy
}

func (r *Region) waitDirectoryGraph(ctx context.Context, key string, queued directoryGraphQueue) (enrollment.DirectoryGraphResult, error) {
	var result enrollment.DirectoryGraphResult
	ctx, cancel := context.WithDeadline(ctx, time.Unix(queued.ExpiresAt, 0))
	defer cancel()
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		rows, err := r.client.Get(ctx, key)
		if err != nil {
			return result, err
		}
		if len(rows.Kvs) == 1 {
			decoded, err := r.workloads.sealer.Open(nil, nil, rows.Kvs[0].Value, []byte(key))
			if err != nil {
				return result, err
			}
			defer clear(decoded)
			if json.Unmarshal(decoded, &result) != nil || result.ID != queued.ID || !result.Valid(queued.Operation) {
				return result, errors.New("invalid directory Graph result")
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

type activeDirectoryGraphTask struct {
	binding  *authorizedDirectoryController
	key      string
	queued   directoryGraphQueue
	revision int64
}

func (r *Region) readHostDirectoryGraphTask(ctx context.Context, host string, certificate []byte, tenant, generation string) (*activeDirectoryGraphTask, error) {
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return nil, err
	}
	if binding.index != 0 {
		return nil, enrollment.ErrHostDenied
	}
	if binding.directory.ProvisionedAt.IsZero() {
		return nil, nil
	}
	key := r.directoryGraphTaskKey(binding.directory)
	rows, err := r.client.Txn(ctx).If(binding.guards...).Then(clientv3.OpGet(key)).Commit()
	if err != nil {
		return nil, err
	}
	if !rows.Succeeded {
		return nil, enrollment.ErrDirectoryAssignmentChanged
	}
	items := rows.Responses[0].GetResponseRange().Kvs
	if len(items) == 0 {
		return nil, nil
	}
	var queued directoryGraphQueue
	if json.Unmarshal(items[0].Value, &queued) != nil || !enrollment.ValidDirectoryJoinID(queued.ID) || queued.Generation != generation {
		return nil, enrollment.ErrDirectoryAssignmentChanged
	}
	if time.Now().Unix() >= queued.ExpiresAt {
		return nil, nil
	}
	return &activeDirectoryGraphTask{binding: binding, key: key, queued: queued, revision: items[0].ModRevision}, nil
}

func (r *Region) HostDirectoryGraphTask(ctx context.Context, host string, certificate []byte, tenant, generation string) (*enrollment.DirectoryGraphTask, error) {
	task, err := r.readHostDirectoryGraphTask(ctx, host, certificate, tenant, generation)
	if err != nil || task == nil {
		return nil, err
	}
	data, err := r.workloads.sealer.Open(nil, nil, task.queued.Sealed, task.queued.label(task.key))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	result := enrollment.DirectoryGraphTask{ID: task.queued.ID, ExpiresAt: task.queued.ExpiresAt}
	if json.Unmarshal(data, &result.DirectoryGraphInput) != nil || !result.Valid() || result.Operation != task.queued.Operation {
		return nil, errors.New("invalid queued directory Graph task")
	}
	return &result, nil
}

func (r *Region) FinishDirectoryGraphTask(ctx context.Context, host string, certificate []byte, tenant, generation string, result enrollment.DirectoryGraphResult) error {
	task, err := r.readHostDirectoryGraphTask(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	if task == nil || task.queued.ID != result.ID || !result.Valid(task.queued.Operation) {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	lease, err := r.client.Grant(ctx, 10)
	if err != nil {
		return err
	}
	key := task.key + "/results/" + result.ID
	data, _ := json.Marshal(result)
	sealed := r.workloads.sealer.Seal(nil, nil, data, []byte(key))
	clear(data)
	writes := []clientv3.Op{clientv3.OpPut(key, string(sealed), clientv3.WithLease(lease.ID)), clientv3.OpDelete(task.key)}
	if (enrollment.DirectoryGraphInput{Operation: task.queued.Operation}).Mutates() {
		outcome := arm.OperationSucceeded
		if result.Status >= http.StatusBadRequest {
			outcome = arm.OperationFailed
		}
		scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: task.binding.directory.SubscriptionID}
		writes = append(writes, r.auditOp(scope, directoryGraphAudit(task.queued.Actor, task.queued.Operation, task.queued.ID, outcome)))
	}
	guards := append(task.binding.guards, clientv3.Compare(clientv3.ModRevision(task.key), "=", task.revision))
	completed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err == nil && !completed.Succeeded {
		_, _ = r.client.Revoke(ctx, lease.ID)
		return enrollment.ErrDirectoryAssignmentChanged
	}
	return err
}
