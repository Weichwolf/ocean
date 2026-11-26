package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) authorizeVMWorker(host string, certificate []byte, snapshot *clientv3.TxnResponse) error {
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return err
	}
	var live enrollment.Availability
	if json.Unmarshal(snapshot.Responses[1].GetResponseRange().Kvs[0].Value, &live) != nil || !live.VMRuntime {
		return enrollment.ErrHostDenied
	}
	return nil
}

func (r *Region) HostVirtualMachineTasks(ctx context.Context, host string, certificate []byte, after string) (workload.VMTaskPage, error) {
	page := workload.VMTaskPage{Tasks: []workload.VMTask{}}
	if r.vms == nil {
		return page, nil
	}
	const limit = 8
	prefix := r.hostVMPrefix(host)
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(limit+1))).Commit()
	if err != nil {
		return page, err
	}
	if err := r.authorizeVMWorker(host, certificate, read); err != nil {
		return page, err
	}
	items := read.Responses[2].GetResponseRange().Kvs
	count := min(len(items), limit)
	for _, item := range items[:count] {
		parts := strings.Split(strings.TrimPrefix(string(item.Key), prefix), "/")
		if len(parts) != 3 || !identifier.MatchString(parts[2]) {
			return page, errors.New("invalid host VM assignment key")
		}
		scope := arm.SubscriptionScope{TenantID: parts[0], SubscriptionID: parts[1]}
		key := string(item.Value)
		if !validScope(scope) || !strings.HasPrefix(key, r.armPrefix(scope)+"virtual-machines/") {
			return page, errors.New("invalid host VM task scope")
		}
		if err := r.requireActiveHostedTenant(ctx, scope.TenantID); err != nil {
			if errors.Is(err, identity.ErrTenantSuspended) {
				continue
			}
			return workload.VMTaskPage{}, err
		}
		task, err := r.vmTask(ctx, scope, host, parts[2], key, read.Header.Revision)
		if err != nil {
			return page, err
		}
		page.Tasks = append(page.Tasks, task)
	}
	if len(items) > limit {
		page.Next = strings.TrimPrefix(string(items[limit-1].Key), prefix)
	}
	return page, nil
}

func (r *Region) vmTask(ctx context.Context, scope arm.SubscriptionScope, host, placement, key string, at int64) (workload.VMTask, error) {
	empty := workload.VMTask{}
	read, err := r.client.Get(ctx, key, clientv3.WithRev(at))
	if err != nil {
		return empty, err
	}
	var vm vmRecord
	if len(read.Kvs) != 1 || json.Unmarshal(read.Kvs[0].Value, &vm) != nil || r.vmKey(scope, vm.Address) != key ||
		vm.Reservation.HostID != host || vm.Reservation.ID != placement || !vm.Disk.Valid() {
		return empty, errors.New("invalid host VM task")
	}
	assigned, err := r.client.Get(ctx, r.writerKey(scope, vm.Disk.ID), clientv3.WithRev(at))
	if err != nil {
		return empty, err
	}
	var writer volumeWriter
	if len(assigned.Kvs) != 1 || json.Unmarshal(assigned.Kvs[0].Value, &writer) != nil || writer != vm.writer() {
		return empty, errors.New("host VM task does not hold the current disk writer grant")
	}
	task := workload.VMTask{AssignmentID: workload.AssignmentID{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		ID: placement, Generation: vm.Reservation.Generation, Revision: vm.Operation}, MachineID: vm.MachineID,
		Size: vm.Request.Properties.HardwareProfile.VMSize, State: vm.Desired, Prepared: vm.Prepared, Force: vm.Force, Disk: vm.Disk}
	if vm.Desired != workload.Running {
		return task, nil
	}
	rows, err := r.client.Get(ctx, r.vmNICKey(scope, vm.NIC), clientv3.WithRev(at))
	if err != nil {
		return empty, err
	}
	if len(rows.Kvs) != 1 {
		return empty, errors.New("host VM task is missing its private interface")
	}
	nic, err := decodeVMNIC(rows.Kvs[0].Value, vm.NIC)
	if err != nil || nic.VM == nil || nic.VM.Key() != vm.Address.Key() || nic.VMID != vm.MachineID {
		return empty, errors.New("host VM task is missing its private interface assignment")
	}
	task.Network, err = r.assignedNetworkPolicy(ctx, scope, enrollment.Assignment{Generation: nic.Lease, SubnetID: nic.SubnetID, PrivateIPv4: nic.IP}, at)
	if err != nil {
		return empty, err
	}
	task.VolumeKey, err = r.vmDiskKey(scope, vm)
	return task, err
}

func (r *Region) ReportVirtualMachine(ctx context.Context, host string, certificate []byte, report workload.VMReport) error {
	scope := arm.SubscriptionScope{TenantID: report.TenantID, SubscriptionID: report.SubscriptionID}
	if r.vms == nil || !validScope(scope) || !identifier.MatchString(report.ID) || !identifier.MatchString(report.Generation) ||
		!identifier.MatchString(report.Revision) || report.DiskReleased != (report.State == workload.Removed) {
		return enrollment.ErrHostDenied
	}
	hostKey := r.hostVMPrefix(host) + scope.TenantID + "/" + scope.SubscriptionID + "/" + report.ID
	registered, live := r.hostKey("registered", host), r.hostKey("live", host)
	for range 10 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(registered), clientv3.OpGet(live), clientv3.OpGet(hostKey)).Commit()
		if err != nil {
			return err
		}
		if err := r.authorizeVMWorker(host, certificate, read); err != nil {
			return err
		}
		assignment := read.Responses[2].GetResponseRange().Kvs
		if len(assignment) != 1 {
			return enrollment.ErrWorkloadChanged
		}
		key := string(assignment[0].Value)
		prefix := r.armPrefix(scope) + "virtual-machines/"
		group, path, ok := strings.Cut(strings.TrimPrefix(key, prefix), "/")
		if !strings.HasPrefix(key, prefix) || !ok {
			return enrollment.ErrHostDenied
		}
		view, vm, op, revision, at, err := r.readVM(ctx, scope, arm.ResourceAddress{Group: group, Path: path})
		if err != nil {
			return err
		}
		if op == nil || vm.Reservation.HostID != host || vm.Reservation.ID != report.ID || vm.Reservation.Generation != report.Generation ||
			vm.Operation != report.Revision || vm.Desired != report.State {
			return enrollment.ErrWorkloadChanged
		}
		if op.Status == arm.OperationSucceeded && vm.Observed == report.State {
			return nil
		}
		writerKey := r.writerKey(scope, vm.Disk.ID)
		writerRows, err := r.client.Get(ctx, writerKey, clientv3.WithRev(at))
		if err != nil {
			return err
		}
		var writer volumeWriter
		if len(writerRows.Kvs) != 1 || json.Unmarshal(writerRows.Kvs[0].Value, &writer) != nil || writer != vm.writer() || op.Status != arm.OperationInProgress {
			return enrollment.ErrWorkloadChanged
		}
		guards := []clientv3.Cmp{
			clientv3.Compare(clientv3.ModRevision(registered), "=", read.Responses[0].GetResponseRange().Kvs[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(live), "=", read.Responses[1].GetResponseRange().Kvs[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(hostKey), "=", assignment[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.ModRevision(writerKey), "=", writerRows.Kvs[0].ModRevision),
		}
		now := time.Now().UTC()
		op.Status, op.FinishedAt = arm.OperationSucceeded, &now
		if report.State == workload.Removed {
			return r.finishVMDeletion(ctx, scope, vm, view, op, at, guards)
		}
		vm.Observed = report.State
		if report.State == workload.Running {
			vm.Prepared = true
		}
		invKey, diskKey := r.inventoryPrefix(scope)+vm.Address.Key(), r.inventoryPrefix(scope)+vm.DiskAddress.Key()
		completedVM := projectVM(scope, vm, vmSucceeded, view.CreatedAt, now)
		completedDisk := projectVMDisk(scope, vm, vmSucceeded, view.CreatedAt, now)
		writes := []clientv3.Op{putJSON(key, vm), putJSON(invKey, completedVM), putJSON(diskKey, completedDisk), putJSON(r.operationKey(scope, op.ID), op),
			r.vmAudit(scope, op.Actor, vm.Address, op.Kind, arm.OperationSucceeded, now)}
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return enrollment.ErrWorkloadChanged
}

func (r *Region) finishVMDeletion(ctx context.Context, scope arm.SubscriptionScope, vm vmRecord, view arm.InventoryResource,
	op *arm.Operation, at int64, guards []clientv3.Cmp) error {
	return r.releasePlacement(ctx, scope, vm.Reservation.Cell, vm.Reservation.ID, vm.Reservation.Generation,
		func(ctx context.Context, _ Reservation) ([]clientv3.Cmp, []clientv3.Op, error) {
			nicKey, nicViewKey := r.vmNICKey(scope, vm.NIC), r.inventoryPrefix(scope)+vm.NIC.Key()
			rows, err := r.client.Txn(ctx).Then(clientv3.OpGet(nicKey, clientv3.WithRev(at)), clientv3.OpGet(nicViewKey, clientv3.WithRev(at))).Commit()
			if err != nil {
				return nil, nil, err
			}
			nics, views := rows.Responses[0].GetResponseRange().Kvs, rows.Responses[1].GetResponseRange().Kvs
			if len(nics) != 1 || len(views) != 1 {
				return nil, nil, errors.New("deletion is missing the VM network interface")
			}
			nic, err := decodeVMNIC(nics[0].Value, vm.NIC)
			if err != nil || nic.VM == nil || nic.VM.Key() != vm.Address.Key() || nic.VMID != vm.MachineID {
				return nil, nil, errors.New("deletion does not own the VM network interface")
			}
			previous, err := decodeInventoryResource(views[0].Value, vm.NIC.Key())
			if err != nil {
				return nil, nil, err
			}
			nic.VM, nic.VMID = nil, ""
			projection := projectVMNIC(scope, nic)
			conditions, writes, err := r.inventoryReferenceChanges(ctx, scope, vm.Address, &view, nil, at, nil)
			if err != nil {
				return nil, nil, err
			}
			usageGuard, usageWrite, err := r.changeVMDiskUsage(ctx, scope, -vm.Disk.SizeGiB)
			if err != nil {
				return nil, nil, err
			}
			conditions = append(conditions, guards...)
			conditions = append(conditions, usageGuard, clientv3.Compare(clientv3.ModRevision(nicKey), "=", nics[0].ModRevision),
				clientv3.Compare(clientv3.ModRevision(nicViewKey), "=", views[0].ModRevision))
			now := *op.FinishedAt
			writes = append(writes, usageWrite, clientv3.OpDelete(r.vmKey(scope, vm.Address)), clientv3.OpDelete(r.inventoryPrefix(scope)+vm.Address.Key()),
				clientv3.OpDelete(r.inventoryPrefix(scope)+vm.DiskAddress.Key()), clientv3.OpDelete(r.writerKey(scope, vm.Disk.ID)),
				clientv3.OpDelete(r.hostVMKey(scope, vm.Reservation)), putJSON(nicKey, nic), inventoryPut(nicViewKey, &previous, &projection, now),
				putJSON(r.operationKey(scope, op.ID), op), r.vmAudit(scope, op.Actor, vm.Address, "delete", arm.OperationSucceeded, now))
			return conditions, writes, nil
		})
}
