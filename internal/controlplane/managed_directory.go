package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) managedDirectoryKey(tenant string) string {
	return r.root + "/managed-directories/" + tenant
}

func (r *Region) managedDirectorySubnetLock(scope arm.SubscriptionScope, parent arm.ResourceAddress, subnet string) string {
	return r.subnetNetworkPlacements(scope, parent, subnet) + "_managed-directory"
}

func (r *Region) managedDirectorySnapshot(ctx context.Context, tenant identity.TenantReservation) (*identity.ManagedDirectory, []clientv3.Cmp, error) {
	if !tenant.Valid(tenant.TenantID) {
		return nil, nil, identity.ErrDirectoryTenant
	}
	registration, subscription := r.tenantKeys(tenant.TenantID)
	key := r.managedDirectoryKey(tenant.TenantID)
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(registration), clientv3.OpGet(subscription), clientv3.OpGet(key)).Commit()
	if err != nil {
		return nil, nil, err
	}
	registrations := read.Responses[0].GetResponseRange().Kvs
	subscriptions := read.Responses[1].GetResponseRange().Kvs
	if len(registrations) != 1 || len(subscriptions) != 1 {
		return nil, nil, identity.ErrDirectoryTenant
	}
	var saved identity.TenantReservation
	var sub identity.Subscription
	if json.Unmarshal(registrations[0].Value, &saved) != nil || json.Unmarshal(subscriptions[0].Value, &sub) != nil {
		return nil, nil, errors.New("invalid tenant metadata for managed directory")
	}
	if saved != tenant || !sub.Valid(tenant.TenantID) || sub.SubscriptionID != tenant.SubscriptionID {
		return nil, nil, identity.ErrDirectoryTenant
	}
	items := read.Responses[2].GetResponseRange().Kvs
	guards := []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(registration), "=", registrations[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(subscription), "=", subscriptions[0].ModRevision),
	}
	if len(items) == 0 {
		return nil, append(guards, clientv3.Compare(clientv3.Version(key), "=", 0)), nil
	}
	var directory identity.ManagedDirectory
	if json.Unmarshal(items[0].Value, &directory) != nil || !directory.Valid(tenant) {
		return nil, nil, errors.New("invalid managed directory record")
	}
	return &directory, append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", items[0].ModRevision)), nil
}

func (r *Region) LookupManagedDirectory(ctx context.Context, tenant identity.TenantReservation) (*identity.ManagedDirectory, error) {
	directory, _, err := r.managedDirectorySnapshot(ctx, tenant)
	return directory, err
}

func (r *Region) RequestManagedDirectory(ctx context.Context, tenant identity.TenantReservation, spec identity.DirectorySpec) (identity.ManagedDirectory, error) {
	var empty identity.ManagedDirectory
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	spec, ok := spec.Canonical()
	if !ok {
		return empty, errors.New("invalid managed directory configuration")
	}
	parent, name, ok := arm.SubnetParent(scope, spec.SubnetID)
	if !ok {
		return empty, identity.ErrDirectorySubnet
	}
	key := r.managedDirectoryKey(tenant.TenantID)
	lock := r.managedDirectorySubnetLock(scope, parent, name)
	for range 8 {
		existing, guards, err := r.managedDirectorySnapshot(ctx, tenant)
		if err != nil {
			return empty, err
		}
		if existing != nil {
			if existing.Spec != spec {
				return empty, identity.ErrDirectoryConflict
			}
			return *existing, nil
		}
		subnet, err := r.allocateSubnet(ctx, scope, spec.SubnetID)
		if errors.Is(err, ErrPlacementSubnetUnavailable) || errors.Is(err, ErrSubnetAddressExhausted) {
			// A concurrent request may have committed while the subnet was changing.
			existing, readErr := r.LookupManagedDirectory(ctx, tenant)
			if readErr != nil {
				return empty, readErr
			}
			if existing != nil {
				if existing.Spec == spec {
					return *existing, nil
				}
				return empty, identity.ErrDirectoryConflict
			}
			return empty, identity.ErrDirectorySubnet
		}
		if err != nil {
			return empty, err
		}
		now := time.Now().UTC()
		directory := identity.ManagedDirectory{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
			ID: operationID(), Spec: spec, RequestedAt: now}
		data, _ := json.Marshal(directory)
		guards = append(append(guards, subnet.guards...), clientv3.Compare(clientv3.Version(lock), "=", 0))
		result, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpPut(key, string(data)), clientv3.OpPut(lock, directory.ID),
			r.auditOp(scope, arm.AuditEvent{Time: now, Actor: tenant.Administrator, Action: "Ocean.Identity/directories/write",
				Target: directory.ID, Outcome: "Accepted"})).Commit()
		if err != nil {
			return empty, err
		}
		if result.Succeeded {
			return directory, nil
		}
	}
	return empty, errors.New("the tenant directory reservation changed concurrently")
}
