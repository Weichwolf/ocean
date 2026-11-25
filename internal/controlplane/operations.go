package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const deleteResourceGroup = "DeleteResourceGroup"

func (r *Region) operationKey(scope arm.SubscriptionScope, id string) string {
	return r.root + "/operations/records/" + scope.TenantID + "/" + scope.SubscriptionID + "/" + id
}

func (r *Region) pendingPrefix() string { return r.root + "/operations/pending/" }

func (r *Region) deletionKey(scope arm.SubscriptionScope, name string) string {
	return r.armPrefix(scope) + "group-deletions/" + strings.ToLower(name)
}

func (r *Region) GetOperation(ctx context.Context, scope arm.SubscriptionScope, id string) (*arm.Operation, error) {
	result, err := r.client.Get(ctx, r.operationKey(scope, id))
	if err != nil || len(result.Kvs) == 0 {
		return nil, err
	}
	return decodeOperation(result.Kvs[0].Value, id)
}

func (r *Region) DeleteGroup(ctx context.Context, scope arm.SubscriptionScope, name, actor string) (*arm.Operation, error) {
	name = strings.ToLower(name)
	groupKey := r.groupPrefix(scope) + name
	deletionKey := r.deletionKey(scope, name)
	bindings := r.groupNetworkPlacements(scope, name)
	containers := r.containerPrefix(scope, name)
	accounts := r.storageAccountsPrefix(scope, name)
	replicaSets := r.replicaSetsPrefix(scope, name)
	vms := r.vmPrefix(scope, name)
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(deletionKey),
			clientv3.OpGet(bindings, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly()),
			clientv3.OpGet(containers, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly()),
			clientv3.OpGet(accounts, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly()),
			clientv3.OpGet(replicaSets, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly()),
			clientv3.OpGet(vms, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())).Commit()
		if err != nil {
			return nil, err
		}
		groups := snapshot.Responses[0].GetResponseRange().Kvs
		deletions := snapshot.Responses[1].GetResponseRange().Kvs
		if len(deletions) == 1 {
			id := string(deletions[0].Value)
			op, err := r.GetOperation(ctx, scope, id)
			if err != nil {
				return nil, err
			}
			if op == nil || !strings.EqualFold(op.Group, name) || op.Kind != deleteResourceGroup {
				return nil, errors.New("invalid group deletion reference")
			}
			return op, nil
		}
		if len(groups) == 0 {
			return nil, nil
		}
		if len(snapshot.Responses[2].GetResponseRange().Kvs) != 0 || len(snapshot.Responses[3].GetResponseRange().Kvs) != 0 ||
			len(snapshot.Responses[4].GetResponseRange().Kvs) != 0 || len(snapshot.Responses[5].GetResponseRange().Kvs) != 0 ||
			len(snapshot.Responses[6].GetResponseRange().Kvs) != 0 {
			return nil, arm.ErrGroupInUse
		}
		item := groups[0]
		group, err := decodeGroup(item.Value, name)
		if err != nil {
			return nil, err
		}
		if group.DeleteOperation != "" {
			return nil, errors.New("resource group deletion has no operation reference")
		}
		op := arm.Operation{ID: operationID(), Kind: deleteResourceGroup, Group: group.Name, Actor: actor,
			Status: arm.OperationInProgress, StartedAt: time.Now().UTC()}
		group.DeleteOperation = op.ID
		groupData, _ := json.Marshal(group)
		opData, _ := json.Marshal(op)
		queueData, _ := json.Marshal(scope)
		opKey := r.operationKey(scope, op.ID)
		queueKey := r.pendingPrefix() + op.ID
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(groupKey), "=", item.ModRevision),
			clientv3.Compare(clientv3.Version(bindings), "=", 0).WithPrefix(), clientv3.Compare(clientv3.Version(containers), "=", 0).WithPrefix(),
			clientv3.Compare(clientv3.Version(accounts), "=", 0).WithPrefix(), clientv3.Compare(clientv3.Version(replicaSets), "=", 0).WithPrefix(),
			clientv3.Compare(clientv3.Version(vms), "=", 0).WithPrefix(),
			clientv3.Compare(clientv3.Version(deletionKey), "=", 0), clientv3.Compare(clientv3.Version(opKey), "=", 0),
			clientv3.Compare(clientv3.Version(queueKey), "=", 0)).Then(clientv3.OpPut(groupKey, string(groupData)),
			clientv3.OpPut(deletionKey, op.ID), clientv3.OpPut(opKey, string(opData)), clientv3.OpPut(queueKey, string(queueData))).Commit()
		if err != nil || result.Succeeded {
			return &op, err
		}
	}
	return nil, errors.New("resource group deletion changed concurrently")
}

func (r *Region) reconcileOperations(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		run, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := r.reconcilePending(run)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("Operation reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Region) reconcilePending(ctx context.Context) error {
	prefix := r.pendingPrefix()
	entries, err := r.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithLimit(32), clientv3.WithSort(clientv3.SortByCreateRevision, clientv3.SortAscend))
	if err != nil {
		return err
	}
	var failure error
	for _, entry := range entries.Kvs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		key := string(entry.Key)
		id := strings.TrimPrefix(key, prefix)
		var scope arm.SubscriptionScope
		if err := json.Unmarshal(entry.Value, &scope); err != nil || scope.TenantID == "" || scope.SubscriptionID == "" {
			failure = errors.Join(failure, errors.New("invalid pending operation scope"))
			continue
		}
		err := r.completeGroupDeletion(ctx, scope, key, id, entry.ModRevision)
		failure = errors.Join(failure, err)
	}
	return failure
}

func (r *Region) completeGroupDeletion(ctx context.Context, scope arm.SubscriptionScope, queueKey, id string, revision int64) error {
	key := r.operationKey(scope, id)
	record, err := r.client.Get(ctx, key)
	if err != nil {
		return err
	}
	if len(record.Kvs) != 1 {
		return errors.New("pending operation has no status record")
	}
	item := record.Kvs[0]
	op, err := decodeOperation(item.Value, id)
	if err != nil || op.Status != arm.OperationInProgress {
		return err
	}
	groupKey := r.groupPrefix(scope) + strings.ToLower(op.Group)
	groupRecord, err := r.client.Get(ctx, groupKey)
	if err != nil {
		return err
	}
	conditions := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(queueKey), "=", revision),
		clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision)}
	mutations := []clientv3.Op{clientv3.OpDelete(queueKey)}
	now := time.Now().UTC()
	op.FinishedAt = &now
	op.Status = arm.OperationFailed
	if len(groupRecord.Kvs) == 1 {
		groupEntry := groupRecord.Kvs[0]
		group, err := decodeGroup(groupEntry.Value, strings.ToLower(op.Group))
		if err != nil {
			return err
		}
		conditions = append(conditions, clientv3.Compare(clientv3.ModRevision(groupKey), "=", groupEntry.ModRevision))
		if group.DeleteOperation == op.ID {
			conditions = append(conditions, clientv3.Compare(clientv3.Version(r.groupNetworkPlacements(scope, op.Group)), "=", 0).WithPrefix(),
				clientv3.Compare(clientv3.Version(r.containerPrefix(scope, op.Group)), "=", 0).WithPrefix(),
				clientv3.Compare(clientv3.Version(r.storageAccountsPrefix(scope, op.Group)), "=", 0).WithPrefix(),
				clientv3.Compare(clientv3.Version(r.replicaSetsPrefix(scope, op.Group)), "=", 0).WithPrefix())
			poolConditions, poolChanges, err := r.releaseGroupPublicIPs(ctx, scope, op.Group)
			if err != nil {
				return err
			}
			conditions = append(conditions, poolConditions...)
			mutations = append(mutations, poolChanges...)
			op.Status = arm.OperationSucceeded
			mutations = append(mutations, clientv3.OpDelete(groupKey),
				clientv3.OpDelete(r.groupInventoryPrefix(scope, op.Group), clientv3.WithPrefix()),
				clientv3.OpDelete(r.groupInventoryReferencesPrefix(scope, op.Group), clientv3.WithPrefix()),
				clientv3.OpDelete(r.assignmentPrefix(scope, op.Group), clientv3.WithPrefix()),
				clientv3.OpDelete(r.groupGrantPrefix(scope, op.Group), clientv3.WithPrefix()))
		}
	} else {
		conditions = append(conditions, clientv3.Compare(clientv3.Version(groupKey), "=", 0))
	}
	event := arm.AuditEvent{Time: now, Actor: op.Actor, Action: "Microsoft.Resources/subscriptions/resourceGroups/delete",
		Target: (arm.Group{Name: op.Group}).ResourceID(scope), Outcome: op.Status}
	data, _ := json.Marshal(op)
	mutations = append(mutations, clientv3.OpPut(key, string(data)), r.auditOp(scope, event))
	_, err = r.client.Txn(ctx).If(conditions...).Then(mutations...).Commit()
	return err
}

func decodeOperation(data []byte, id string) (*arm.Operation, error) {
	var operation arm.Operation
	if err := json.Unmarshal(data, &operation); err != nil {
		return nil, err
	}
	if operation.ID != id || operation.Group == "" || operation.Actor == "" || operation.StartedAt.IsZero() {
		return nil, errors.New("invalid ARM operation record")
	}
	switch operation.Kind {
	case deleteResourceGroup, createApplicationGateway, deleteApplicationGateway, createSiteConnection, deleteSiteConnection,
		createContainer, startContainer, stopContainer, restartContainer, deleteContainer, createFileShare, deleteFileShare, fenceContainer,
		updateFunction, integrateFunction, configureReplicaSet, deleteReplicaSet, createVM, startVM, stopVM, deleteVM, recoverVM:
	default:
		return nil, errors.New("invalid ARM operation kind")
	}
	switch operation.Status {
	case arm.OperationInProgress:
		if operation.FinishedAt == nil {
			return &operation, nil
		}
	case arm.OperationSucceeded, arm.OperationFailed:
		if operation.FinishedAt != nil {
			return &operation, nil
		}
	}
	return nil, errors.New("invalid ARM operation status")
}

func operationID() string {
	var value [16]byte
	rand.Read(value[:])
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
