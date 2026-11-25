package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	createVM  = "CreateVirtualMachine"
	startVM   = "StartVirtualMachine"
	stopVM    = "PowerOffVirtualMachine"
	deleteVM  = "DeleteVirtualMachine"
	recoverVM = "RecoverVirtualMachine"
)

type vmRecord struct {
	Address     arm.ResourceAddress       `json:"address"`
	MachineID   string                    `json:"machineId"`
	Request     arm.VirtualMachineRequest `json:"request"`
	Reservation Reservation               `json:"reservation"`
	Image       arm.ResourceAddress       `json:"image"`
	NIC         arm.ResourceAddress       `json:"nic"`
	DiskAddress arm.ResourceAddress       `json:"diskAddress"`
	Disk        storage.VMDisk            `json:"disk"`
	Envelope    []byte                    `json:"envelope"`
	Desired     string                    `json:"desired"`
	Observed    string                    `json:"observed,omitempty"`
	Prepared    bool                      `json:"prepared,omitempty"`
	Force       bool                      `json:"force,omitempty"`
	Fenced      bool                      `json:"fenced,omitempty"`
	Operation   string                    `json:"operation"`
	Creation    string                    `json:"creation"`
	OSType      string                    `json:"osType,omitempty"`
}

func (r *Region) vmPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "virtual-machines/" + strings.ToLower(group) + "/"
}

func (r *Region) vmKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "virtual-machines/" + address.Key()
}

func (r *Region) hostVMPrefix(host string) string { return r.hostKey("vm-tasks", host) + "/" }

func (r *Region) hostVMKey(scope arm.SubscriptionScope, reservation Reservation) string {
	return r.hostVMPrefix(reservation.HostID) + scope.TenantID + "/" + scope.SubscriptionID + "/" + reservation.ID
}

func (v vmRecord) writer() volumeWriter {
	return volumeWriter{Host: v.Reservation.HostID, PlacementID: v.Reservation.ID, Generation: v.Reservation.Generation, Resource: v.Address}
}

func (r *Region) vmKeyLabel(scope arm.SubscriptionScope, record vmRecord) []byte {
	return []byte(r.vmKey(scope, record.Address) + "/" + record.Disk.ID)
}

func (r *Region) vmDiskKey(scope arm.SubscriptionScope, record vmRecord) ([]byte, error) {
	key, err := r.storage.sealer.Open(nil, nil, record.Envelope, r.vmKeyLabel(scope, record))
	if err != nil || len(key) != storage.KeySize {
		clear(key)
		return nil, errors.New("invalid VM disk key envelope")
	}
	return key, nil
}

func (r *Region) changeVMDiskUsage(ctx context.Context, scope arm.SubscriptionScope, delta int64) (clientv3.Cmp, clientv3.Op, error) {
	key := r.armPrefix(scope) + "vm-disk-usage-gib"
	read, err := r.client.Get(ctx, key)
	if err != nil {
		return clientv3.Cmp{}, clientv3.Op{}, err
	}
	var used, revision int64
	if len(read.Kvs) == 1 {
		revision = read.Kvs[0].ModRevision
		used, err = strconv.ParseInt(string(read.Kvs[0].Value), 10, 64)
		if err != nil || used < 0 {
			return clientv3.Cmp{}, clientv3.Op{}, errors.New("invalid VM disk quota counter")
		}
	}
	if delta > 0 && delta > r.vms.diskQuota-used {
		return clientv3.Cmp{}, clientv3.Op{}, arm.ErrVMQuotaExceeded
	}
	if delta < 0 && -delta > used {
		return clientv3.Cmp{}, clientv3.Op{}, errors.New("VM disk quota release exceeds the reserved capacity")
	}
	return clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.OpPut(key, strconv.FormatInt(used+delta, 10)), nil
}

func decodeVM(value []byte, address arm.ResourceAddress) (vmRecord, error) {
	var record vmRecord
	if json.Unmarshal(value, &record) != nil || record.Address.Key() != address.Key() || !record.Address.Valid() ||
		!identifier.MatchString(record.MachineID) || record.Disk.ID != "vm-"+record.MachineID || !record.Disk.Valid() ||
		!workload.ValidVMImageDiskSize(vmOperatingSystem(record.OSType), record.Disk.SizeGiB) ||
		!record.Image.Valid() || !record.DiskAddress.Valid() || !record.NIC.Valid() ||
		!identifier.MatchString(record.Operation) || !identifier.MatchString(record.Creation) || !record.Reservation.NeedsVMRuntime {
		return vmRecord{}, errors.New("invalid VM resource record")
	}
	return record, nil
}

func projectVM(scope arm.SubscriptionScope, record vmRecord, status string, born, now time.Time) arm.InventoryResource {
	request := record.Request
	properties, _ := json.Marshal(map[string]any{
		"vmId": record.MachineID, "provisioningState": status, "hardwareProfile": request.Properties.HardwareProfile,
		"storageProfile": map[string]any{
			"imageReference": map[string]string{"id": record.Image.ID(scope)},
			"osDisk": map[string]any{"name": request.Properties.StorageProfile.OSDisk.Name, "osType": vmOperatingSystem(record.OSType), "createOption": "FromImage",
				"deleteOption": "Delete", "diskSizeGB": record.Disk.SizeGiB,
				"managedDisk": map[string]string{"id": record.DiskAddress.ID(scope), "storageAccountType": "Standard_LRS"}},
		},
		"networkProfile": map[string]any{"networkInterfaces": []any{map[string]any{
			"id": record.NIC.ID(scope), "properties": map[string]any{"primary": true, "deleteOption": "Detach"},
		}}},
	})
	return arm.InventoryResource{Address: record.Address, Location: request.Location, Tags: request.Tags,
		APIVersion: arm.VirtualMachineAPIVersion, ProvisioningState: status, Properties: properties,
		References: []arm.ResourceAddress{record.Image, record.NIC, record.DiskAddress}, CreatedAt: born, ChangedAt: now}
}

func projectVMDisk(scope arm.SubscriptionScope, record vmRecord, status string, born, now time.Time) arm.InventoryResource {
	properties, _ := json.Marshal(map[string]any{"diskSizeGB": record.Disk.SizeGiB, "osType": vmOperatingSystem(record.OSType), "hyperVGeneration": "V2",
		"provisioningState": status, "diskState": "Attached", "creationData": map[string]any{"createOption": "FromImage",
			"imageReference": map[string]string{"id": record.Image.ID(scope)}}})
	return arm.InventoryResource{Address: record.DiskAddress, APIVersion: arm.VMDiskAPIVersion, Location: record.Request.Location,
		SKU: arm.ResourceSKU{Name: "Standard_LRS"}, ProvisioningState: status, Properties: properties, CreatedAt: born, ChangedAt: now}
}

func (r *Region) CreateVirtualMachine(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	wanted arm.VirtualMachineRequest) (arm.InventoryResource, *arm.Operation, bool, error) {
	if r.vms == nil || r.storage == nil {
		return arm.InventoryResource{}, nil, false, arm.ErrVMHostUnavailable
	}
	if view, op, found, err := r.retryVMCreate(ctx, scope, address, wanted); found || err != nil {
		return view, op, false, err
	}
	size, ok := workload.VirtualMachineSize(wanted.Properties.HardwareProfile.VMSize)
	if !ok || len(wanted.Properties.NetworkProfile.NetworkInterfaces) != 1 {
		return arm.InventoryResource{}, nil, false, arm.ErrVMResourceChanged
	}
	key := r.vmKey(scope, address)
	request := PlacementRequest{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key)))[:48], Cell: r.cell, Role: "compute", NeedsStorage: true, NeedsVMRuntime: true,
		Resources: enrollment.Capacity{CPUMillis: int64(size.VCPUs) * 1000, MemoryMiB: int64(size.MemoryMiB)}}
	var submitted string
	_, err := r.reservePlacement(ctx, scope, request, func(ctx context.Context, reservation Reservation) ([]clientv3.Cmp, []clientv3.Op, error) {
		return r.prepareVMCreate(ctx, scope, actor, address, wanted, size, reservation, &submitted)
	})
	switch {
	case errors.Is(err, ErrQuotaExceeded):
		err = arm.ErrVMQuotaExceeded
	case errors.Is(err, ErrNoEligibleHost):
		err = arm.ErrVMHostUnavailable
	case errors.Is(err, ErrReservationChanged):
		err = arm.ErrVMResourceChanged
	}
	if err != nil {
		return arm.InventoryResource{}, nil, false, err
	}
	view, op, found, err := r.retryVMCreate(ctx, scope, address, wanted)
	if !found && err == nil {
		err = arm.ErrVirtualMachineNotFound
	}
	return view, op, op != nil && op.ID == submitted, err
}

func (r *Region) prepareVMCreate(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, wanted arm.VirtualMachineRequest,
	size workload.VMSize, reservation Reservation, submitted *string) ([]clientv3.Cmp, []clientv3.Op, error) {
	imageRef, imageOK := arm.NetworkResourceAddress(scope, wanted.Properties.StorageProfile.ImageReference.ID, arm.VMImageType)
	nicRef, nicOK := arm.NetworkResourceAddress(scope, wanted.Properties.NetworkProfile.NetworkInterfaces[0].ID, arm.VMNetworkInterfaceType)
	if !imageOK || !nicOK || !strings.EqualFold(address.Group, imageRef.Group) || !strings.EqualFold(address.Group, nicRef.Group) {
		return nil, nil, arm.ErrLinkedResourceMissing
	}
	groupKey := r.groupPrefix(scope) + strings.ToLower(address.Group)
	imageKey := r.inventoryPrefix(scope) + imageRef.Key()
	nicKey := r.vmNICKey(scope, nicRef)
	nicViewKey := r.inventoryPrefix(scope) + nicRef.Key()
	diskAddress := arm.ResourceAddress{Group: address.Group, Path: arm.VMDiskType + "/" + wanted.Properties.StorageProfile.OSDisk.Name}
	diskKey := r.inventoryPrefix(scope) + diskAddress.Key()
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(imageKey), clientv3.OpGet(nicKey), clientv3.OpGet(nicViewKey),
		clientv3.OpGet(diskKey, clientv3.WithCountOnly())).Commit()
	if err != nil {
		return nil, nil, err
	}
	groups, imageRows, nicRows, nicViews := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs,
		read.Responses[2].GetResponseRange().Kvs, read.Responses[3].GetResponseRange().Kvs
	if len(groups) != 1 {
		return nil, nil, arm.ErrGroupMissing
	}
	group, err := decodeGroup(groups[0].Value, strings.ToLower(address.Group))
	if err != nil {
		return nil, nil, err
	}
	if group.DeleteOperation != "" {
		return nil, nil, arm.ErrGroupDeleting
	}
	if len(imageRows) != 1 || len(nicRows) != 1 || len(nicViews) != 1 {
		return nil, nil, arm.ErrLinkedResourceMissing
	}
	nic, err := decodeVMNIC(nicRows[0].Value, nicRef)
	if err != nil {
		return nil, nil, err
	}
	if nic.VM != nil || read.Responses[4].GetResponseRange().Count != 0 {
		return nil, nil, arm.ErrLinkedResourceInUse
	}
	nicBefore, err := decodeInventoryResource(nicViews[0].Value, nicRef.Key())
	if err != nil {
		return nil, nil, err
	}
	image, err := decodeInventoryResource(imageRows[0].Value, imageRef.Key())
	if err != nil {
		return nil, nil, err
	}
	var imageProperties arm.VMImageRequest
	if err := json.Unmarshal(image.Properties, &imageProperties.Properties); err != nil {
		return nil, nil, err
	}
	imageDisk := imageProperties.Properties.StorageProfile.OSDisk
	catalog, allowed := r.vms.images[vmCatalogKey{scope, imageDisk.BlobURI}]
	if !allowed || catalog.SizeGiB != imageDisk.DiskSizeGB || vmOperatingSystem(catalog.OSType) != imageDisk.OSType {
		return nil, nil, arm.ErrVMImageUnavailable
	}
	if size.RequiredOS != "" && size.RequiredOS != imageDisk.OSType {
		return nil, nil, arm.ErrVMSizeUnsupported
	}
	diskUsageGuard, diskUsageUpdate, err := r.changeVMDiskUsage(ctx, scope, catalog.SizeGiB)
	if err != nil {
		return nil, nil, err
	}
	address.Group, diskAddress.Group = group.Name, group.Name
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: createVM, Group: group.Name, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
	machine := operationID()
	record := vmRecord{Address: address, MachineID: machine, Request: wanted, Reservation: reservation, Desired: workload.Running,
		Image: image.Address, NIC: nic.Address, DiskAddress: diskAddress, Disk: catalog.disk("vm-" + machine), Operation: op.ID, Creation: op.ID, OSType: catalog.OSType}
	secret := make([]byte, storage.KeySize)
	rand.Read(secret)
	record.Envelope = r.storage.sealer.Seal(nil, nil, secret, r.vmKeyLabel(scope, record))
	clear(secret)
	nic.VM, nic.VMID = &address, machine
	view := projectVM(scope, record, "Creating", now, now)
	disk := projectVMDisk(scope, record, "Creating", now, now)
	nicAfter := projectVMNIC(scope, nic)
	conditions, updates, err := r.inventoryReferenceChanges(ctx, scope, address, nil, &view, read.Header.Revision, map[string]bool{diskAddress.Key(): true})
	if err != nil {
		return nil, nil, err
	}
	key, invKey, hostKey, opKey, writerKey := r.vmKey(scope, address), r.inventoryPrefix(scope)+address.Key(), r.hostVMKey(scope, reservation),
		r.operationKey(scope, op.ID), r.writerKey(scope, record.Disk.ID)
	conditions = append(conditions, diskUsageGuard, clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(imageKey), "=", imageRows[0].ModRevision), clientv3.Compare(clientv3.ModRevision(nicKey), "=", nicRows[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(nicViewKey), "=", nicViews[0].ModRevision), clientv3.Compare(clientv3.Version(diskKey), "=", 0))
	for _, unique := range []string{key, invKey, hostKey, opKey, writerKey} {
		conditions = append(conditions, clientv3.Compare(clientv3.Version(unique), "=", 0))
	}
	*submitted = op.ID
	updates = append(updates, diskUsageUpdate, putJSON(key, record), putJSON(invKey, view), putJSON(diskKey, disk), putJSON(nicKey, nic),
		inventoryPut(nicViewKey, &nicBefore, &nicAfter, now), clientv3.OpPut(hostKey, key), putJSON(opKey, op), putJSON(writerKey, record.writer()),
		r.vmAudit(scope, actor, address, "write", arm.OperationInProgress, now))
	return conditions, updates, nil
}

func (r *Region) readVM(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (arm.InventoryResource, vmRecord, *arm.Operation, int64, int64, error) {
	key := r.vmKey(scope, address)
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(key), clientv3.OpGet(r.inventoryPrefix(scope)+address.Key())).Commit()
	if err != nil {
		return arm.InventoryResource{}, vmRecord{}, nil, 0, 0, err
	}
	rows, views := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
	if len(rows) == 0 && len(views) == 0 {
		return arm.InventoryResource{}, vmRecord{}, nil, 0, read.Header.Revision, nil
	}
	if len(rows) != 1 || len(views) != 1 {
		return arm.InventoryResource{}, vmRecord{}, nil, 0, 0, errors.New("inconsistent VM inventory")
	}
	record, err := decodeVM(rows[0].Value, address)
	if err != nil {
		return arm.InventoryResource{}, vmRecord{}, nil, 0, 0, err
	}
	view, err := decodeInventoryResource(views[0].Value, address.Key())
	if err != nil {
		return arm.InventoryResource{}, vmRecord{}, nil, 0, 0, err
	}
	op, err := r.operationAt(ctx, scope, record.Operation, read.Header.Revision)
	return view, record, op, rows[0].ModRevision, read.Header.Revision, err
}

func (r *Region) retryVMCreate(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress,
	wanted arm.VirtualMachineRequest) (arm.InventoryResource, *arm.Operation, bool, error) {
	view, record, current, _, revision, err := r.readVM(ctx, scope, address)
	if err != nil || current == nil {
		return view, current, current != nil, err
	}
	if !sameVMInput(record.Request, wanted) {
		return view, nil, true, arm.ErrVMResourceChanged
	}
	if record.Desired == workload.Removed {
		return view, nil, true, arm.ErrVMOperationBusy
	}
	if record.Creation == current.ID {
		return view, current, true, nil
	}
	original, err := r.operationAt(ctx, scope, record.Creation, revision)
	return view, original, true, err
}

func (r *Region) MutateVirtualMachine(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, action arm.VMAction) (*arm.Operation, error) {
	kind, desired := startVM, workload.Running
	switch action.Name {
	case "start":
	case "poweroff":
		kind, desired = stopVM, workload.Stopped
	case "delete":
		kind, desired = deleteVM, workload.Removed
	default:
		return nil, arm.ErrVMResourceChanged
	}
	key := r.vmKey(scope, address)
	for range 10 {
		view, record, current, revision, _, err := r.readVM(ctx, scope, address)
		if err != nil {
			return nil, err
		}
		if current == nil {
			if desired == workload.Removed {
				return nil, nil
			}
			return nil, arm.ErrVirtualMachineNotFound
		}
		if record.Fenced {
			return nil, arm.ErrVMOperationBusy
		}
		if current.Status == arm.OperationInProgress {
			if current.Kind == kind && record.Force == action.Force {
				return current, nil
			}
			if desired != workload.Removed {
				return nil, arm.ErrVMOperationBusy
			}
		} else if current.Status == arm.OperationSucceeded && record.Observed == desired {
			return nil, nil
		}
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: kind, Group: address.Group, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		record.Desired, record.Operation, record.Force = desired, op.ID, action.Force
		status := "Updating"
		if desired == workload.Removed {
			status = "Deleting"
		}
		projection := projectVM(scope, record, status, view.CreatedAt, now)
		opKey := r.operationKey(scope, op.ID)
		writes := []clientv3.Op{putJSON(key, record), putJSON(opKey, op), putJSON(r.inventoryPrefix(scope)+address.Key(), projection),
			r.vmAudit(scope, actor, record.Address, action.Name, arm.OperationInProgress, now)}
		if current.Status == arm.OperationInProgress {
			current.Status, current.FinishedAt = arm.OperationFailed, &now
			current.Error = &arm.OperationError{Code: "OperationSuperseded", Message: "A deletion superseded this virtual machine operation."}
			writes = append(writes, putJSON(r.operationKey(scope, current.ID), current))
		}
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.Compare(clientv3.Version(opKey), "=", 0)}
		var conflicts []clientv3.Op
		if desired == workload.Removed {
			prefix := r.dependentsPrefix(scope, record.Address)
			guards = append(guards, clientv3.Compare(clientv3.Version(prefix), "=", 0).WithPrefix())
			conflicts = append(conflicts, clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithCountOnly()))
		}
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Else(conflicts...).Commit()
		if err != nil || result.Succeeded {
			return &op, err
		}
		if desired == workload.Removed && result.Responses[0].GetResponseRange().Count != 0 {
			return nil, arm.ErrLinkedResourceInUse
		}
	}
	return nil, arm.ErrVMOperationBusy
}

func (r *Region) GetVirtualMachineInstanceView(ctx context.Context, scope arm.SubscriptionScope, reader string, address arm.ResourceAddress) (*arm.VMInstanceView, error) {
	key := r.vmKey(scope, address)
	read, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(key))
	if err != nil || len(read.Kvs) == 0 {
		return nil, err
	}
	record, err := decodeVM(read.Kvs[0].Value, address)
	if err != nil {
		return nil, err
	}
	view, err := r.client.Get(ctx, r.inventoryPrefix(scope)+address.Key(), clientv3.WithRev(read.Header.Revision))
	if err != nil {
		return nil, err
	}
	if len(view.Kvs) != 1 {
		return nil, errors.New("VM instance view has no inventory projection")
	}
	projection, err := decodeInventoryResource(view.Kvs[0].Value, address.Key())
	if err != nil {
		return nil, err
	}
	worker, err := r.client.Get(ctx, r.hostKey("live", record.Reservation.HostID), clientv3.WithCountOnly(), clientv3.WithRev(read.Header.Revision))
	if err != nil {
		return nil, err
	}
	power, display := "unknown", "VM power state unknown"
	switch {
	case record.Fenced || worker.Count == 0 && record.Observed != workload.Stopped:
	case record.Observed == workload.Running:
		power, display = "running", "VM running"
	case record.Observed == workload.Stopped:
		power, display = "stopped", "VM stopped"
	case record.Desired == workload.Running:
		power, display = "starting", "VM starting"
	}
	return &arm.VMInstanceView{Statuses: []arm.VMInstanceStatus{
		{Code: "ProvisioningState/" + projection.ProvisioningState, Level: "Info", DisplayStatus: projection.ProvisioningState},
		{Code: "PowerState/" + power, Level: "Info", DisplayStatus: display},
	}}, nil
}
