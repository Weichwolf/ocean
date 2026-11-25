package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type desktopAssignment struct {
	arm.DesktopPolicy
	MachineID         string `json:"machineId"`
	DirectoryID       string `json:"directoryId"`
	AssignmentID      string `json:"assignmentId"`
	ProvisioningState string `json:"provisioningState"`
}

func (r *Region) PutPersonalDesktop(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	policy arm.DesktopPolicy) (*arm.InventoryResource, bool, error) {
	vm, ok := arm.NetworkResourceAddress(scope, policy.VirtualMachineID, arm.VirtualMachineType)
	if !ok || !strings.EqualFold(vm.Group, address.Group) {
		return nil, false, arm.ErrDesktopVM
	}
	if !policy.ValidPrincipal() {
		return nil, false, arm.ErrDesktopPolicy
	}
	directory, directoryGuards, err := r.desktopDirectoryPrincipal(ctx, scope, policy)
	if err != nil {
		return nil, false, err
	}
	return r.changeInventoryResource(ctx, scope, address, actor, arm.DesktopType+"/write", "",
		func(previous *arm.InventoryResource, canonical arm.ResourceAddress, revision int64) (*arm.InventoryResource, []clientv3.Cmp, error) {
			target, guards, err := r.desktopVMAt(ctx, scope, vm, revision, previous == nil)
			if err != nil {
				return nil, nil, err
			}
			wanted := desktopAssignment{DesktopPolicy: policy, MachineID: target.MachineID, DirectoryID: directory,
				AssignmentID: operationID(), ProvisioningState: vmSucceeded}
			wanted.VirtualMachineID = target.Address.ID(scope)
			if previous != nil {
				old, err := decodeDesktopAssignment(previous.Properties)
				if err != nil {
					return nil, nil, err
				}
				if old.VirtualMachineID != wanted.VirtualMachineID || old.MachineID != wanted.MachineID || old.DirectoryID != wanted.DirectoryID {
					return nil, nil, arm.ErrDesktopConflict
				}
				if old.DesktopPolicy == wanted.DesktopPolicy {
					wanted.AssignmentID = old.AssignmentID
				}
			}
			properties, err := json.Marshal(wanted)
			if err != nil {
				return nil, nil, err
			}
			next := &arm.InventoryResource{Address: canonical, APIVersion: arm.DesktopAPIVersion, Location: r.name,
				Properties: properties, References: []arm.ResourceAddress{target.Address}, ProvisioningState: vmSucceeded}
			return next, append(guards, directoryGuards...), nil
		})
}

func decodeDesktopAssignment(data []byte) (desktopAssignment, error) {
	var saved desktopAssignment
	if json.Unmarshal(data, &saved) != nil || !saved.ValidPrincipal() || !identifier.MatchString(saved.MachineID) ||
		!enrollment.ValidDirectoryJoinID(saved.DirectoryID) || !enrollment.ValidDirectoryJoinID(saved.AssignmentID) {
		return desktopAssignment{}, errors.New("invalid personal desktop assignment record")
	}
	return saved, nil
}

func (r *Region) desktopVMAt(ctx context.Context, scope arm.SubscriptionScope, vm arm.ResourceAddress,
	revision int64, exclusive bool) (vmRecord, []clientv3.Cmp, error) {
	key := r.vmKey(scope, vm)
	read, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return vmRecord{}, nil, err
	}
	if len(read.Kvs) != 1 {
		return vmRecord{}, nil, arm.ErrDesktopVM
	}
	target, err := decodeVM(read.Kvs[0].Value, vm)
	if err != nil {
		return vmRecord{}, nil, err
	}
	if vmOperatingSystem(target.OSType) != workload.VMLinux || !target.Prepared || target.Desired == workload.Removed || target.Fenced {
		return vmRecord{}, nil, arm.ErrDesktopVM
	}
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", read.Kvs[0].ModRevision)}
	if exclusive {
		prefix := r.dependentsPrefix(scope, vm) + strings.ToLower(arm.DesktopType) + "/"
		references, err := r.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithCountOnly(), clientv3.WithRev(revision))
		if err != nil {
			return vmRecord{}, nil, err
		}
		if references.Count != 0 {
			return vmRecord{}, nil, arm.ErrDesktopConflict
		}
		guards = append(guards, clientv3.Compare(clientv3.Version(prefix), "=", 0).WithPrefix())
	}
	return target, guards, nil
}

func (r *Region) desktopDirectoryPrincipal(ctx context.Context, scope arm.SubscriptionScope, policy arm.DesktopPolicy) (string, []clientv3.Cmp, error) {
	tenant, err := r.LookupTenant(ctx, scope.TenantID)
	if err != nil || tenant == nil || !tenant.Valid(scope.TenantID) || tenant.SubscriptionID != scope.SubscriptionID {
		return "", nil, arm.ErrDesktopDirectory
	}
	directory, guards, _, err := r.managedDirectorySnapshot(ctx, *tenant)
	if err != nil || directory == nil || directory.ProvisionedAt.IsZero() {
		return "", nil, arm.ErrDesktopDirectory
	}
	operation := enrollment.DirectoryUserGet
	if policy.PrincipalType == "Group" {
		operation = enrollment.DirectoryGroupGet
	}
	result, err := r.RunDirectoryGraph(ctx, *tenant, enrollment.DirectoryGraphInput{Operation: operation, Selector: policy.PrincipalID})
	if err != nil || result.Status != http.StatusOK && result.Status != http.StatusNotFound {
		return "", nil, arm.ErrDesktopDirectory
	}
	if operation == enrollment.DirectoryUserGet {
		if result.User == nil || result.User.ID != policy.PrincipalID || !result.User.Enabled {
			return "", nil, arm.ErrDesktopPolicy
		}
	} else if result.Group == nil || result.Group.ID != policy.PrincipalID || !result.Group.Security ||
		!strings.HasPrefix(result.Group.SID, directory.DomainSID+"-") {
		return "", nil, arm.ErrDesktopPolicy
	}
	return directory.ID, guards, nil
}

func (r *Region) DeletePersonalDesktop(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) error {
	_, _, err := r.ChangeInventoryResource(ctx, scope, address, actor, arm.DesktopType+"/delete", "",
		func(*arm.InventoryResource, arm.ResourceAddress) (*arm.InventoryResource, error) { return nil, nil })
	return err
}

func (r *Region) AuthorizePersonalDesktop(ctx context.Context, principal identity.DesktopPrincipal, address arm.ResourceAddress) (arm.DesktopAdmission, error) {
	access, err := r.resolvePersonalDesktop(ctx, principal, address, nil)
	return access.DesktopAdmission, err
}

func (r *Region) resolvePersonalDesktop(ctx context.Context, principal identity.DesktopPrincipal, address arm.ResourceAddress, gatewayGuards []clientv3.Cmp) (arm.DesktopLaunch, error) {
	var empty arm.DesktopLaunch
	started := time.Now().UTC()
	if !principal.Tenant.Valid(principal.Tenant.TenantID) || !enrollment.ValidDirectoryJoinID(principal.UserID) ||
		!enrollment.ValidDirectoryJoinID(principal.DirectoryID) || !started.Before(principal.ExpiresAt) {
		return empty, arm.ErrDesktopDenied
	}
	scope := arm.SubscriptionScope{TenantID: principal.Tenant.TenantID, SubscriptionID: principal.Tenant.SubscriptionID}
	key := r.inventoryPrefix(scope) + address.Key()
	read, err := r.client.Get(ctx, key)
	if err != nil {
		return empty, err
	}
	if len(read.Kvs) != 1 {
		return empty, arm.ErrDesktopDenied
	}
	resource, err := decodeInventoryResource(read.Kvs[0].Value, address.Key())
	if err != nil {
		return empty, err
	}
	policy, err := decodeDesktopAssignment(resource.Properties)
	if err != nil {
		return empty, err
	}
	if policy.DirectoryID != principal.DirectoryID || policy.PrincipalType == "User" && policy.PrincipalID != principal.UserID {
		return empty, arm.ErrDesktopDenied
	}
	directory, guards, _, err := r.managedDirectorySnapshot(ctx, principal.Tenant)
	if err != nil || directory == nil || directory.ID != policy.DirectoryID || directory.ProvisionedAt.IsZero() {
		return empty, arm.ErrDesktopDirectory
	}
	check := enrollment.DirectoryGraphInput{Operation: enrollment.DirectoryUserDesktopCheck, Selector: principal.UserID}
	if policy.PrincipalType == "Group" {
		check.GroupID = policy.PrincipalID
	}
	result, err := r.RunDirectoryGraph(ctx, principal.Tenant, check)
	if err != nil || result.Status != http.StatusOK && result.Status != http.StatusNotFound {
		return empty, arm.ErrDesktopDirectory
	}
	if result.User == nil || result.User.ID != principal.UserID || !result.User.Enabled {
		return empty, arm.ErrDesktopDenied
	}
	vm, ok := arm.NetworkResourceAddress(scope, policy.VirtualMachineID, arm.VirtualMachineType)
	if !ok || !strings.EqualFold(vm.Group, address.Group) {
		return empty, errors.New("invalid virtual machine reference in the desktop assignment")
	}
	target, vmGuards, err := r.desktopVMAt(ctx, scope, vm, read.Header.Revision, false)
	if errors.Is(err, arm.ErrDesktopVM) {
		return empty, arm.ErrDesktopOffline
	}
	if err != nil {
		return empty, err
	}
	if target.MachineID != policy.MachineID || target.Desired != workload.Running || target.Observed != workload.Running {
		return empty, arm.ErrDesktopOffline
	}
	hostKey := r.hostKey("live", target.Reservation.HostID)
	host, err := r.client.Get(ctx, hostKey)
	if err != nil {
		return empty, err
	}
	var availability enrollment.Availability
	if len(host.Kvs) != 1 || host.Kvs[0].Lease == 0 ||
		json.Unmarshal(host.Kvs[0].Value, &availability) != nil || !availability.VMRuntime ||
		availability.HostID != target.Reservation.HostID || availability.Cell != target.Reservation.Cell {
		return empty, arm.ErrDesktopOffline
	}
	guards = append(guards, vmGuards...)
	var access arm.DesktopLaunch
	actions := []clientv3.Op{clientv3.OpGet(key, clientv3.WithCountOnly())}
	if gatewayGuards != nil {
		user := strings.ToLower(result.User.UPN)
		if !strings.HasSuffix(user, "@"+directory.Spec.DNSName) {
			return empty, arm.ErrDesktopDenied
		}
		nic, nicGuards, err := r.desktopPrivateNIC(ctx, scope, target, read.Header.Revision)
		if err != nil {
			return empty, err
		}
		guards = append(guards, nicGuards...)
		guards = append(guards, gatewayGuards...)
		access.User, access.PrivateIP, access.NetworkInterface, access.SubnetID = user, nic.IP, nic.Address.ID(scope), nic.SubnetID
		actions = []clientv3.Op{r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: principal.UserID,
			Action: arm.DesktopType + "/launch/action", Target: resource.Address.ID(scope), Outcome: "Authorized"})}
	}
	guards = append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", read.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(hostKey), "=", host.Kvs[0].ModRevision))
	expires := started.Add(desktop.LaunchLifetime)
	if principal.ExpiresAt.Before(expires) {
		expires = principal.ExpiresAt
	}
	if !time.Now().Before(expires) {
		return empty, arm.ErrDesktopDenied
	}
	current, err := r.client.Txn(ctx).If(guards...).Then(actions...).Commit()
	if err != nil {
		return empty, err
	}
	if !current.Succeeded || !time.Now().Before(expires) {
		return empty, arm.ErrDesktopDenied
	}
	access.DesktopAdmission = arm.DesktopAdmission{AssignmentID: policy.AssignmentID, MachineID: policy.MachineID, ExpiresAt: expires}
	return access, nil
}
