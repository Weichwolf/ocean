package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) inventoryPrefix(scope arm.SubscriptionScope) string {
	return r.armPrefix(scope) + "resources/"
}

func (r *Region) groupInventoryPrefix(scope arm.SubscriptionScope, group string) string {
	return r.inventoryPrefix(scope) + strings.ToLower(group) + "/"
}

func (r *Region) GetInventoryResource(ctx context.Context, scope arm.SubscriptionScope, reader string, address arm.ResourceAddress) (*arm.InventoryResource, error) {
	key := r.inventoryPrefix(scope) + address.Key()
	result, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(key))
	if err != nil || len(result.Kvs) == 0 {
		return nil, err
	}
	resource, err := decodeInventoryResource(result.Kvs[0].Value, address.Key())
	return &resource, err
}

func (r *Region) ListInventoryResources(ctx context.Context, scope arm.SubscriptionScope, reader string, query arm.InventoryQuery, limit int) ([]arm.InventoryResource, error) {
	root := r.inventoryPrefix(scope)
	prefix := root
	if query.Group != "" {
		prefix = r.groupInventoryPrefix(scope, query.Group)
	}
	end := clientv3.GetPrefixRangeEnd(prefix)
	start := prefix
	if after := root + query.After + "\x00"; query.After != "" && after > start {
		start = after
	}
	var revision int64
	if query.GroupScope {
		groupKey := r.groupPrefix(scope) + strings.ToLower(query.Group)
		result, err := r.readForGroup(ctx, scope, reader, query.Group, clientv3.OpGet(groupKey, clientv3.WithCountOnly()))
		if err != nil {
			return nil, err
		}
		if result.Count == 0 {
			return nil, arm.ErrGroupMissing
		}
		revision = result.Header.Revision
	}
	resources := make([]arm.InventoryResource, 0, limit)
	access := make(map[string]bool)
	for start < end {
		result, err := r.client.Get(ctx, start, clientv3.WithRange(end), clientv3.WithLimit(128), clientv3.WithRev(revision))
		if err != nil {
			return nil, err
		}
		if revision == 0 {
			revision = result.Header.Revision
		}
		for _, item := range result.Kvs {
			key := strings.TrimPrefix(string(item.Key), root)
			group, _, _ := strings.Cut(key, "/")
			if reader != "" && !query.GroupScope {
				granted, seen := access[group]
				if !seen {
					grant := r.groupGrantPrefix(scope, group) + reader
					permission, err := r.client.Get(ctx, grant, clientv3.WithRev(revision), clientv3.WithCountOnly())
					if err != nil {
						return nil, err
					}
					granted = permission.Count == 1
					access[group] = granted
				}
				if !granted {
					continue
				}
			}
			resource, err := decodeInventoryResource(item.Value, key)
			if err != nil {
				return nil, err
			}
			if query.Match(resource) {
				resources = append(resources, resource)
				if len(resources) == limit {
					return resources, nil
				}
			}
		}
		if !result.More {
			break
		}
		start = string(result.Kvs[len(result.Kvs)-1].Key) + "\x00"
	}
	return resources, nil
}

// PutInventoryResource publishes a provider-owned ARM projection for a live
// group. The group revision coordinates inventory writes with group deletion.
func (r *Region) PutInventoryResource(ctx context.Context, scope arm.SubscriptionScope, resource arm.InventoryResource) error {
	if !resource.Valid() {
		return errors.New("invalid resource projection")
	}
	_, _, err := r.ChangeInventoryResource(ctx, scope, resource.Address, "", "", "", func(_ *arm.InventoryResource, address arm.ResourceAddress) (*arm.InventoryResource, error) {
		resource.Address = address
		return &resource, nil
	})
	return err
}

// ChangeInventoryResource commits a provider mutation against the group and
// resource revisions. The callback receives a read-only projection and can run
// again after a concurrent change. The audit suffix identifies a nested target.
func (r *Region) ChangeInventoryResource(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress, actor, action, auditSuffix string,
	change func(*arm.InventoryResource, arm.ResourceAddress) (*arm.InventoryResource, error)) (*arm.InventoryResource, bool, error) {
	group := strings.ToLower(address.Group)
	groupKey := r.groupPrefix(scope) + group
	key := r.inventoryPrefix(scope) + address.Key()
	var groupGeneration int64
	for range 8 {
		result, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(key)).Commit()
		if err != nil {
			return nil, false, err
		}
		groups := result.Responses[0].GetResponseRange().Kvs
		if len(groups) == 0 {
			return nil, false, arm.ErrGroupMissing
		}
		record := groups[0]
		if groupGeneration != 0 && groupGeneration != record.CreateRevision {
			return nil, false, arm.ErrGroupMissing
		}
		groupGeneration = record.CreateRevision
		current, err := decodeGroup(record.Value, group)
		if err != nil {
			return nil, false, err
		}
		if current.DeleteOperation != "" {
			return nil, false, arm.ErrGroupDeleting
		}
		canonical := address
		canonical.Group = current.Name
		var saved *arm.InventoryResource
		var revision int64
		if previous := result.Responses[1].GetResponseRange().Kvs; len(previous) == 1 {
			old, err := decodeInventoryResource(previous[0].Value, address.Key())
			if err != nil {
				return nil, false, err
			}
			saved = &old
			canonical = old.Address
			revision = previous[0].ModRevision
		}
		resource, err := change(saved, canonical)
		if err != nil || resource == nil && saved == nil {
			return nil, false, err
		}
		if resource != nil && (!resource.Valid() || resource.Address != canonical) {
			return nil, false, errors.New("invalid resource projection")
		}
		if saved != nil && resource != nil && saved.APIVersion == resource.APIVersion && saved.Location == resource.Location &&
			saved.ProvisioningState == resource.ProvisioningState && maps.Equal(saved.Tags, resource.Tags) && bytes.Equal(saved.Properties, resource.Properties) {
			return saved, false, nil
		}
		now := time.Now().UTC()
		mutation := clientv3.OpDelete(key)
		if resource != nil {
			resource.CreatedAt = now
			resource.ChangedAt = now
			if saved != nil {
				resource.CreatedAt = saved.CreatedAt
				if resource.ChangedAt.Before(saved.ChangedAt) {
					resource.ChangedAt = saved.ChangedAt
				}
			}
			data, _ := json.Marshal(resource)
			mutation = clientv3.OpPut(key, string(data))
		}
		mutations := []clientv3.Op{mutation}
		if actor != "" {
			mutations = append(mutations, r.auditOp(scope, arm.AuditEvent{Time: now, Actor: actor, Action: action,
				Target: canonical.ID(scope) + auditSuffix, Outcome: "Succeeded"}))
		}
		write, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(groupKey), "=", record.ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", revision)).Then(mutations...).Commit()
		if err != nil {
			return nil, false, err
		}
		if write.Succeeded {
			return resource, saved == nil, nil
		}
	}
	return nil, false, errors.New("resource group changed during inventory publication")
}

func decodeInventoryResource(data []byte, key string) (arm.InventoryResource, error) {
	var resource arm.InventoryResource
	if err := json.Unmarshal(data, &resource); err != nil {
		return arm.InventoryResource{}, err
	}
	if !resource.Valid() || resource.Address.Key() != key || resource.CreatedAt.IsZero() || resource.ChangedAt.Before(resource.CreatedAt) {
		return arm.InventoryResource{}, errors.New("inventory resource does not match its key")
	}
	return resource, nil
}
