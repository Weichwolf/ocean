package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/qemu"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const vmSucceeded = "Succeeded"

type vmImageProperties struct {
	HyperVGeneration  string `json:"hyperVGeneration"`
	StorageProfile    any    `json:"storageProfile"`
	ProvisioningState string `json:"provisioningState"`
}

func (r *Region) PutVMImage(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, input arm.VMImageRequest) (arm.InventoryResource, bool, error) {
	disk := input.Properties.StorageProfile.OSDisk
	if r.vms == nil {
		return arm.InventoryResource{}, false, arm.ErrVMImageUnavailable
	}
	image, ok := r.vms.images[vmCatalogKey{scope, disk.BlobURI}]
	if !ok || disk.DiskSizeGB != 0 && disk.DiskSizeGB != image.SizeGiB {
		return arm.InventoryResource{}, false, arm.ErrVMImageUnavailable
	}
	input.Properties.StorageProfile.OSDisk.DiskSizeGB = image.SizeGiB
	properties, err := json.Marshal(vmImageProperties{input.Properties.HyperVGeneration, input.Properties.StorageProfile, vmSucceeded})
	if err != nil {
		return arm.InventoryResource{}, false, err
	}
	view, created, err := r.ChangeInventoryResource(ctx, scope, address, actor, arm.VMImageType+"/write", "", func(previous *arm.InventoryResource, canonical arm.ResourceAddress) (*arm.InventoryResource, error) {
		next := arm.InventoryResource{Address: canonical, Location: r.name, APIVersion: arm.VMImageAPIVersion, Tags: input.Tags, Properties: properties, ProvisioningState: vmSucceeded}
		if previous != nil && !inventoryEqual(*previous, next) {
			return nil, arm.ErrVMResourceChanged
		}
		return &next, nil
	})
	if err != nil {
		return arm.InventoryResource{}, false, err
	}
	return *view, created, nil
}

type vmNIC struct {
	Address  arm.ResourceAddress           `json:"address"`
	Config   arm.VMNetworkInterfaceRequest `json:"config"`
	SubnetID string                        `json:"subnetId"`
	IP       netip.Addr                    `json:"ip"`
	Lease    string                        `json:"lease"`
	VM       *arm.ResourceAddress          `json:"virtualMachine,omitempty"`
	VMID     string                        `json:"vmId,omitempty"`
}

func (r *Region) vmNICKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "vm-nics/" + address.Key()
}

func decodeVMNIC(value []byte, address arm.ResourceAddress) (vmNIC, error) {
	var nic vmNIC
	if json.Unmarshal(value, &nic) != nil || nic.Address.Key() != address.Key() || !nic.IP.Is4() || !identifier.MatchString(nic.Lease) ||
		len(nic.Config.Properties.IPConfigurations) != 1 || nic.SubnetID == "" ||
		(nic.VM == nil) != (nic.VMID == "") || nic.VMID != "" && !identifier.MatchString(nic.VMID) {
		return vmNIC{}, errors.New("invalid private VM network interface record")
	}
	return nic, nil
}

func projectVMNIC(scope arm.SubscriptionScope, nic vmNIC) arm.InventoryResource {
	ip := nic.Config.Properties.IPConfigurations[0]
	properties := map[string]any{
		"provisioningState": vmSucceeded,
		"ipConfigurations": []any{map[string]any{
			"name": ip.Name, "id": nic.Address.ID(scope) + "/ipConfigurations/" + ip.Name,
			"properties": map[string]any{"subnet": ip.Properties.Subnet, "privateIPAllocationMethod": "Dynamic", "privateIPAddress": nic.IP,
				"privateIPAddressVersion": "IPv4", "primary": true, "provisioningState": vmSucceeded},
		}},
	}
	if nic.VM != nil {
		properties["virtualMachine"] = map[string]string{"id": nic.VM.ID(scope)}
		properties["macAddress"] = qemu.MAC(nic.VMID)
	}
	data, _ := json.Marshal(properties)
	return arm.InventoryResource{Address: nic.Address, Location: nic.Config.Location, APIVersion: arm.VMNetworkAPIVersion,
		Tags: nic.Config.Tags, Properties: data, ProvisioningState: vmSucceeded}
}

func sameVMNICInput(a, b arm.VMNetworkInterfaceRequest) bool {
	if a.Location != b.Location || !maps.Equal(a.Tags, b.Tags) || len(a.Properties.IPConfigurations) != 1 || len(b.Properties.IPConfigurations) != 1 {
		return false
	}
	prior, next := a.Properties.IPConfigurations[0], b.Properties.IPConfigurations[0]
	return strings.EqualFold(prior.Name, next.Name) && strings.EqualFold(prior.Properties.Subnet.ID, next.Properties.Subnet.ID)
}

func (r *Region) PutVMNetworkInterface(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, input arm.VMNetworkInterfaceRequest) (arm.InventoryResource, bool, error) {
	if len(input.Properties.IPConfigurations) != 1 {
		return arm.InventoryResource{}, false, arm.ErrLinkedResourceMissing
	}
	nicKey := r.vmNICKey(scope, address)
	viewKey := r.inventoryPrefix(scope) + address.Key()
	groupKey := r.groupPrefix(scope) + strings.ToLower(address.Group)
	subnet := input.Properties.IPConfigurations[0].Properties.Subnet.ID
	var groupGeneration int64
	for range 10 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(nicKey), clientv3.OpGet(viewKey)).Commit()
		if err != nil {
			return arm.InventoryResource{}, false, err
		}
		groups, prior, views := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs, read.Responses[2].GetResponseRange().Kvs
		if len(groups) != 1 {
			return arm.InventoryResource{}, false, arm.ErrGroupMissing
		}
		if groupGeneration != 0 && groupGeneration != groups[0].CreateRevision {
			return arm.InventoryResource{}, false, arm.ErrGroupMissing
		}
		groupGeneration = groups[0].CreateRevision
		group, err := decodeGroup(groups[0].Value, strings.ToLower(address.Group))
		if err != nil {
			return arm.InventoryResource{}, false, err
		}
		if group.DeleteOperation != "" {
			return arm.InventoryResource{}, false, arm.ErrGroupDeleting
		}
		if len(prior) == 1 && len(views) == 1 {
			nic, err := decodeVMNIC(prior[0].Value, address)
			if err == nil && !sameVMNICInput(nic.Config, input) {
				err = arm.ErrVMResourceChanged
			}
			if err != nil {
				return arm.InventoryResource{}, false, err
			}
			view, err := decodeInventoryResource(views[0].Value, address.Key())
			return view, false, err
		}
		if len(prior) != 0 || len(views) != 0 {
			return arm.InventoryResource{}, false, errors.New("inconsistent VM network interface inventory")
		}
		allocation, err := r.allocateSubnet(ctx, scope, subnet)
		if err != nil {
			if current, lookupErr := r.client.Get(ctx, nicKey, clientv3.WithCountOnly()); lookupErr == nil && current.Count != 0 {
				continue
			}
			return arm.InventoryResource{}, false, vmNetworkError(err)
		}
		if allocation.groupGeneration != groupGeneration {
			return arm.InventoryResource{}, false, arm.ErrGroupMissing
		}
		claims, writes, err := r.claimContainerNetwork(ctx, scope, nicKey, subnet, "")
		if err != nil {
			if current, lookupErr := r.client.Get(ctx, nicKey, clientv3.WithCountOnly()); lookupErr == nil && current.Count != 0 {
				continue
			}
			return arm.InventoryResource{}, false, vmNetworkError(err)
		}
		address.Group = group.Name
		nic := vmNIC{Address: address, Config: input, SubnetID: subnet, IP: allocation.address, Lease: operationID()}
		view := projectVMNIC(scope, nic)
		now := time.Now().UTC()
		guards := append(allocation.guards, claims...)
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
			clientv3.Compare(clientv3.Version(nicKey), "=", 0), clientv3.Compare(clientv3.Version(viewKey), "=", 0))
		writes = append(writes, putJSON(nicKey, nic), inventoryPut(viewKey, nil, &view, now), clientv3.OpPut(allocation.key, nic.Lease),
			r.vmAudit(scope, actor, address, "write", vmSucceeded, now))
		commit, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil || commit.Succeeded {
			return view, err == nil, err
		}
	}
	return arm.InventoryResource{}, false, arm.ErrVMOperationBusy
}

func vmNetworkError(err error) error {
	switch {
	case errors.Is(err, ErrPlacementSubnetUnavailable), errors.Is(err, arm.ErrContainerDelegationRequired):
		return arm.ErrLinkedResourceMissing
	case errors.Is(err, ErrSubnetAddressExhausted), errors.Is(err, arm.ErrContainerNetworkConflict):
		return arm.ErrLinkedResourceInUse
	default:
		return err
	}
}

func (r *Region) DeleteVMDependency(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) error {
	if strings.HasPrefix(strings.ToLower(address.Path), strings.ToLower(arm.VMImageType)+"/") {
		_, _, err := r.ChangeInventoryResource(ctx, scope, address, actor, arm.VMImageType+"/delete", "", func(*arm.InventoryResource, arm.ResourceAddress) (*arm.InventoryResource, error) { return nil, nil })
		return err
	}
	nicKey := r.vmNICKey(scope, address)
	viewKey := r.inventoryPrefix(scope) + address.Key()
	for range 10 {
		read, err := r.client.Get(ctx, nicKey)
		if err != nil || len(read.Kvs) == 0 {
			return err
		}
		entry := read.Kvs[0]
		nic, err := decodeVMNIC(entry.Value, address)
		if err != nil {
			return err
		}
		if nic.VM != nil {
			return arm.ErrLinkedResourceInUse
		}
		parent, subnet, ok := arm.SubnetParent(scope, nic.SubnetID)
		if !ok {
			return errors.New("invalid recorded VM subnet")
		}
		lease := r.subnetNetworkPlacements(scope, parent, subnet) + nic.IP.String()
		claimGuard, releaseClaim, err := r.releaseContainerNetwork(ctx, nicKey)
		if err != nil {
			return err
		}
		guards := []clientv3.Cmp{claimGuard, clientv3.Compare(clientv3.ModRevision(nicKey), "=", entry.ModRevision),
			clientv3.Compare(clientv3.Value(lease), "=", nic.Lease), clientv3.Compare(clientv3.Version(r.dependentsPrefix(scope, address)), "=", 0).WithPrefix()}
		writes := []clientv3.Op{releaseClaim, clientv3.OpDelete(nicKey), clientv3.OpDelete(viewKey), clientv3.OpDelete(lease),
			r.vmAudit(scope, actor, nic.Address, "delete", vmSucceeded, time.Now().UTC())}
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return arm.ErrVMOperationBusy
}

func vmAuditAction(address arm.ResourceAddress, action string) string {
	index := strings.LastIndexByte(address.Path, '/')
	return address.Path[:index] + "/" + action
}

func (r *Region) vmAudit(scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, action, status string, now time.Time) clientv3.Op {
	return r.auditOp(scope, arm.AuditEvent{Time: now, Actor: actor, Action: vmAuditAction(address, action), Target: address.ID(scope), Outcome: status})
}

func sameVMInput(a, b arm.VirtualMachineRequest) bool {
	a.Properties.StorageProfile.ImageReference.ID = strings.ToLower(a.Properties.StorageProfile.ImageReference.ID)
	b.Properties.StorageProfile.ImageReference.ID = strings.ToLower(b.Properties.StorageProfile.ImageReference.ID)
	a.Properties.StorageProfile.OSDisk.Name = strings.ToLower(a.Properties.StorageProfile.OSDisk.Name)
	b.Properties.StorageProfile.OSDisk.Name = strings.ToLower(b.Properties.StorageProfile.OSDisk.Name)
	if a.Location != b.Location || !maps.Equal(a.Tags, b.Tags) || len(a.Properties.NetworkProfile.NetworkInterfaces) != 1 || len(b.Properties.NetworkProfile.NetworkInterfaces) != 1 {
		return false
	}
	al, bl := a.Properties.NetworkProfile.NetworkInterfaces[0], b.Properties.NetworkProfile.NetworkInterfaces[0]
	if !strings.EqualFold(al.ID, bl.ID) {
		return false
	}
	// The contract normalizes omitted defaults for the only permitted NIC.
	a.Properties.NetworkProfile.NetworkInterfaces = nil
	b.Properties.NetworkProfile.NetworkInterfaces = nil
	a.Tags, b.Tags = nil, nil
	return reflect.DeepEqual(a, b)
}
