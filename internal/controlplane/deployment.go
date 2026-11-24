package controlplane

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// DeployNetwork builds a dry run from one revision and commits the exact
// resulting resource graph as a single transaction for deployment writes.
func (r *Region) DeployNetwork(ctx context.Context, scope arm.SubscriptionScope, actor string, template arm.NetworkDeployment, commit bool) (arm.NetworkDeploymentPlan, bool, error) {
	group := strings.ToLower(template.Address.Group)
	groupKey := r.groupPrefix(scope) + group
	prefix := r.inventoryPrefix(scope)
	addresses := template.Addresses()
	gets := []clientv3.Op{clientv3.OpGet(groupKey)}
	for _, address := range addresses {
		gets = append(gets, clientv3.OpGet(prefix+address.Key()))
	}
	var groupGeneration int64
	for range 8 {
		read, err := r.client.Txn(ctx).Then(gets...).Commit()
		if err != nil {
			return arm.NetworkDeploymentPlan{}, false, err
		}
		groups := read.Responses[0].GetResponseRange().Kvs
		if len(groups) == 0 || groupGeneration != 0 && groupGeneration != groups[0].CreateRevision {
			return arm.NetworkDeploymentPlan{}, false, arm.ErrGroupMissing
		}
		groupGeneration = groups[0].CreateRevision
		record, err := decodeGroup(groups[0].Value, group)
		if err != nil {
			return arm.NetworkDeploymentPlan{}, false, err
		}
		if record.DeleteOperation != "" {
			return arm.NetworkDeploymentPlan{}, false, arm.ErrGroupDeleting
		}
		snapshot := make(map[string]arm.InventoryResource)
		conditions := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision)}
		for index, address := range addresses {
			items := read.Responses[index+1].GetResponseRange().Kvs
			var revision int64
			if len(items) == 1 {
				entry, err := decodeInventoryResource(items[0].Value, address.Key())
				if err != nil {
					return arm.NetworkDeploymentPlan{}, false, err
				}
				snapshot[address.Key()] = entry
				revision = items[0].ModRevision
			}
			conditions = append(conditions, clientv3.Compare(clientv3.ModRevision(prefix+address.Key()), "=", revision))
		}
		plan, err := template.Plan(record.Name, snapshot)
		if err != nil {
			return arm.NetworkDeploymentPlan{}, false, arm.InvalidDeployment{Cause: err}
		}
		checks, mutations, err := r.prepareDeployment(ctx, scope, actor, plan.Resources, snapshot, read.Header.Revision)
		if err != nil {
			return arm.NetworkDeploymentPlan{}, false, err
		}
		_, existed := snapshot[template.Address.Key()]
		if !commit || len(mutations) == 0 {
			return plan, !existed, nil
		}
		result, err := r.client.Txn(ctx).If(append(conditions, checks...)...).Then(mutations...).Commit()
		if err != nil || result.Succeeded {
			return plan, !existed, err
		}
	}
	return arm.NetworkDeploymentPlan{}, false, errors.New("the network deployment changed concurrently")
}

func (r *Region) prepareDeployment(ctx context.Context, scope arm.SubscriptionScope, actor string, resources []arm.InventoryResource,
	snapshot map[string]arm.InventoryResource, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	staged, exclusive := make(map[string]bool), make(map[string]bool)
	for _, resource := range resources {
		staged[resource.Address.Key()] = true
		for _, ref := range resource.References {
			if isPublicIPAddress(ref) {
				if exclusive[ref.Key()] {
					return nil, nil, arm.ErrPublicIPInUse
				}
				exclusive[ref.Key()] = true
			}
		}
	}
	var conditions []clientv3.Cmp
	var mutations []clientv3.Op
	var pool publicIPPool
	var poolRevision int64
	now := time.Now().UTC()
	for index := range resources {
		resource := &resources[index]
		if !resource.Valid() {
			return nil, nil, errors.New("invalid network deployment projection")
		}
		key := r.inventoryPrefix(scope) + resource.Address.Key()
		var previous *arm.InventoryResource
		if current, exists := snapshot[resource.Address.Key()]; exists {
			if inventoryEqual(current, *resource) {
				*resource = current
				continue
			}
			previous = &current
		}
		checks, updates, err := r.inventoryReferenceChanges(ctx, scope, resource.Address, previous, resource, revision, staged)
		if err != nil {
			return nil, nil, err
		}
		conditions = append(conditions, checks...)
		mutations = append(mutations, updates...)
		if previous == nil && isPublicIPAddress(resource.Address) {
			if poolRevision == 0 {
				pool, poolRevision, err = r.readPublicIPPool(ctx, revision)
				if err != nil {
					return nil, nil, err
				}
			}
			if err := assignPublicIPv4(pool, key, resource); err != nil {
				return nil, nil, err
			}
		}
		mutations = append(mutations, inventoryPut(key, previous, resource, now), r.auditOp(scope, arm.AuditEvent{
			Time: now, Actor: actor, Action: resource.Address.Path[:strings.LastIndexByte(resource.Address.Path, '/')] + "/write",
			Target: resource.Address.ID(scope), Outcome: "Succeeded"}))
	}
	if poolRevision != 0 {
		check, update := r.publicIPPoolUpdate(pool, poolRevision)
		conditions = append(conditions, check)
		mutations = append(mutations, update)
	}
	return conditions, mutations, nil
}
