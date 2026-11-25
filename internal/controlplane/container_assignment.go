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
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) HostContainerTasks(ctx context.Context, host string, certificate []byte, after string, networkOnly bool) (workload.Page, error) {
	if r.workloads == nil {
		return workload.Page{Tasks: []workload.Task{}}, nil
	}
	const size = 16
	prefix := r.hostContainerPrefix(host)
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(size+1))).Commit()
	if err != nil {
		return workload.Page{}, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return workload.Page{}, err
	}
	items := snapshot.Responses[2].GetResponseRange().Kvs
	count := min(size, len(items))
	page := workload.Page{Tasks: make([]workload.Task, 0, count)}
	for _, item := range items[:count] {
		parts := strings.Split(strings.TrimPrefix(string(item.Key), prefix), "/")
		if len(parts) != 3 || !identifier.MatchString(parts[2]) {
			return workload.Page{}, errors.New("invalid workload task key")
		}
		scope := arm.SubscriptionScope{TenantID: parts[0], SubscriptionID: parts[1]}
		recordKey := string(item.Value)
		if !validScope(scope) || !strings.HasPrefix(recordKey, r.armPrefix(scope)+"containers/") {
			return workload.Page{}, errors.New("workload task does not match its scope")
		}
		records, err := r.client.Get(ctx, recordKey, clientv3.WithRev(snapshot.Header.Revision))
		if err != nil {
			return workload.Page{}, err
		}
		var record containerRecord
		if len(records.Kvs) != 1 || json.Unmarshal(records.Kvs[0].Value, &record) != nil ||
			r.containerKey(scope, record.Address) != recordKey || record.Reservation.ID != parts[2] || record.Reservation.HostID != host {
			return workload.Page{}, errors.New("invalid workload task")
		}
		task := workload.Task{AssignmentID: workload.AssignmentID{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, ID: record.Reservation.ID,
			Generation: record.Reservation.Generation, Revision: record.Operation}, State: record.Desired, Address: record.endpoint(),
			Port: record.Port, Restart: record.Restart}
		if networkOnly && record.Desired != workload.Removed && record.Reservation.SubnetID != "" {
			placement := enrollment.Assignment{Generation: record.Reservation.Generation, SubnetID: record.Reservation.SubnetID,
				PrivateIPv4: record.Reservation.PrivateIPv4}
			task.Policy, err = r.assignedNetworkPolicy(ctx, scope, placement, snapshot.Header.Revision)
			if err != nil {
				return workload.Page{}, err
			}
		}
		if !networkOnly && record.Volume != nil {
			task.VolumeID = record.Volume.ID
		}
		if !networkOnly && record.Desired != workload.Removed {
			op, err := r.operationAt(ctx, scope, record.Operation, snapshot.Header.Revision)
			if err != nil {
				return workload.Page{}, err
			}
			task.Start = record.Desired == workload.Running && op.Status == arm.OperationInProgress
			config, err := r.decryptContainer(scope, record)
			if err != nil {
				return workload.Page{}, err
			}
			task.Container, task.RestartPolicy = &config.Properties.Containers[0].Properties, config.Properties.RestartPolicy
		}
		page.Tasks = append(page.Tasks, task)
	}
	if len(items) > count {
		page.Next = strings.TrimPrefix(string(items[count-1].Key), prefix)
	}
	return page, nil
}

func (r *Region) ReportContainerTask(ctx context.Context, host string, certificate []byte, report workload.Report) error {
	if r.workloads == nil {
		return enrollment.ErrHostDenied
	}
	scope := arm.SubscriptionScope{TenantID: report.TenantID, SubscriptionID: report.SubscriptionID}
	hostRecord, liveKey := r.hostKey("registered", host), r.hostKey("live", host)
	hostKey := r.hostContainerKey(scope, host, report.ID)
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(hostRecord), clientv3.OpGet(liveKey), clientv3.OpGet(hostKey)).Commit()
		if err != nil {
			return err
		}
		if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
			return err
		}
		items := snapshot.Responses[2].GetResponseRange().Kvs
		if len(items) == 0 {
			return enrollment.ErrWorkloadChanged
		}
		key := string(items[0].Value)
		group, path, _ := strings.Cut(strings.TrimPrefix(key, r.armPrefix(scope)+"containers/"), "/")
		address := arm.ResourceAddress{Group: group, Path: path}
		if !address.Valid() || key != r.containerKey(scope, address) {
			return errors.New("invalid workload report reference")
		}
		prior, record, op, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return err
		}
		if op == nil || record.Reservation.HostID != host || record.Reservation.ID != report.ID ||
			record.Reservation.Generation != report.Generation || record.Operation != report.Revision {
			return enrollment.ErrWorkloadChanged
		}
		checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(hostRecord), "=", snapshot.Responses[0].GetResponseRange().Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(liveKey), ">", 0), clientv3.Compare(clientv3.ModRevision(hostKey), "=", items[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", revision)}
		if record.Desired == workload.Removed {
			if report.State != workload.Removed {
				return enrollment.ErrWorkloadChanged
			}
			return r.finishContainerDeletion(ctx, scope, record, *op, hostKey, checks, nil, false)
		}
		if report.State != record.Desired && report.State != workload.Failed && !(record.Desired == workload.Running && report.State == workload.Stopped) {
			return enrollment.ErrWorkloadChanged
		}
		config, err := r.decryptContainer(scope, record)
		if err != nil {
			return err
		}
		logs := workload.RedactLogs(report.Logs, config.Properties.Containers[0].Properties.EnvironmentVariables)
		logsKey := key + "/logs"
		previousLogs, err := r.client.Get(ctx, logsKey)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		var writes []clientv3.Op
		var logsRevision int64
		if len(previousLogs.Kvs) == 1 {
			logsRevision = previousLogs.Kvs[0].ModRevision
		}
		if logs != "" && (logsRevision == 0 || string(previousLogs.Kvs[0].Value) != logs) {
			checks = append(checks, clientv3.Compare(clientv3.ModRevision(logsKey), "=", logsRevision))
			writes = append(writes, clientv3.OpPut(logsKey, logs))
		}
		complete := op.Status == arm.OperationInProgress && (report.State == record.Desired || report.State == workload.Failed)
		if complete {
			op.Status, op.FinishedAt = arm.OperationSucceeded, &now
			if report.State == workload.Failed {
				op.Status = arm.OperationFailed
			}
			writes = append(writes, putJSON(r.operationKey(scope, op.ID), op), r.containerAudit(scope, record, *op, "reconcile", now))
		}
		if record.Observed != report.State || complete {
			record.Observed, record.Restart = report.State, false
			projection := projectContainer(config, record, prior.CreatedAt, now, op.Status)
			writes = append(writes, putJSON(key, record), putJSON(r.inventoryPrefix(scope)+address.Key(), projection))
		}
		if len(writes) == 0 {
			return nil
		}
		result, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return enrollment.ErrWorkloadChanged
}

func (r *Region) finishContainerDeletion(ctx context.Context, scope arm.SubscriptionScope, record containerRecord, op arm.Operation,
	hostKey string, checks []clientv3.Cmp, finalWrites []clientv3.Op, fenced bool) error {
	res := record.Reservation
	key := r.containerKey(scope, record.Address)
	now := time.Now().UTC()
	op.Status, op.FinishedAt = arm.OperationSucceeded, &now
	return r.releasePlacement(ctx, scope, res.Cell, res.ID, res.Generation, func(ctx context.Context, _ Reservation) ([]clientv3.Cmp, []clientv3.Op, error) {
		conditions := slices.Clone(checks)
		writes := []clientv3.Op{clientv3.OpDelete(hostKey), clientv3.OpDelete(key), clientv3.OpDelete(key + "/logs"),
			clientv3.OpDelete(r.inventoryPrefix(scope) + record.Address.Key()), putJSON(r.operationKey(scope, op.ID), op),
			r.containerAudit(scope, record, op, "delete", now)}
		writes = append(writes, finalWrites...)
		if record.Volume != nil && !fenced {
			receipt := r.unmountReceiptKey(scope, record.Volume.ID, record.Reservation.Generation, record.Operation)
			proof, err := r.client.Get(ctx, receipt)
			if err != nil {
				return nil, nil, err
			}
			if len(proof.Kvs) != 1 || string(proof.Kvs[0].Value) != record.Reservation.HostID {
				return nil, nil, enrollment.ErrWorkloadChanged
			}
			conditions = append(conditions, clientv3.Compare(clientv3.Value(receipt), "=", record.Reservation.HostID))
			writes = append(writes, clientv3.OpDelete(receipt))
		}
		if record.Volume != nil {
			guard, update, err := r.releaseVolume(ctx, scope, record)
			if err != nil {
				return nil, nil, err
			}
			conditions, writes = append(conditions, guard), append(writes, update)
		}
		if record.PublicIP.IsValid() {
			pool, revision, err := r.readPublicIPPool(ctx, 0)
			if err != nil {
				return nil, nil, err
			}
			if pool.Allocations[key] != record.PublicIP {
				return nil, nil, enrollment.ErrWorkloadChanged
			}
			delete(pool.Allocations, key)
			poolCheck, poolWrite := r.publicIPPoolUpdate(pool, revision)
			conditions, writes = append(conditions, poolCheck), append(writes, poolWrite)
		} else {
			check, write, err := r.releaseContainerNetwork(ctx, key)
			if err != nil {
				return nil, nil, err
			}
			conditions, writes = append(conditions, check), append(writes, write)
		}
		return conditions, writes, nil
	})
}
