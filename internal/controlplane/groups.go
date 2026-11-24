package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) groupPrefix(scope arm.SubscriptionScope) string {
	return r.armPrefix(scope) + "resource-groups/"
}

func (r *Region) GetGroup(ctx context.Context, scope arm.SubscriptionScope, name string) (*arm.Group, error) {
	key := r.groupPrefix(scope) + strings.ToLower(name)
	result, err := r.client.Get(ctx, key)
	if err != nil || len(result.Kvs) == 0 {
		return nil, err
	}
	group, err := decodeGroup(result.Kvs[0].Value, strings.ToLower(name))
	return &group, err
}

func (r *Region) ListGroups(ctx context.Context, scope arm.SubscriptionScope, after string, limit int) ([]arm.Group, error) {
	prefix := r.groupPrefix(scope)
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	result, err := r.client.Get(ctx, start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)),
		clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend), clientv3.WithLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	groups := make([]arm.Group, 0, len(result.Kvs))
	for _, item := range result.Kvs {
		group, err := decodeGroup(item.Value, strings.TrimPrefix(string(item.Key), prefix))
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (r *Region) PutGroup(ctx context.Context, scope arm.SubscriptionScope, requested arm.Group, actor string) (arm.Group, bool, error) {
	name := strings.ToLower(requested.Name)
	key := r.groupPrefix(scope) + name
	for range 8 {
		current, err := r.client.Get(ctx, key)
		if err != nil {
			return arm.Group{}, false, err
		}
		group := requested
		var revision int64
		created := len(current.Kvs) == 0
		if !created {
			item := current.Kvs[0]
			existing, err := decodeGroup(item.Value, name)
			if err != nil {
				return arm.Group{}, false, err
			}
			if existing.DeleteOperation != "" {
				return arm.Group{}, false, arm.ErrGroupDeleting
			}
			if existing.Location != group.Location {
				return arm.Group{}, false, arm.ErrGroupLocation
			}
			if maps.Equal(existing.Tags, group.Tags) {
				return existing, false, nil
			}
			revision = item.ModRevision
			group.Name = existing.Name
		}
		data, _ := json.Marshal(group)
		event := arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: "Microsoft.Resources/subscriptions/resourceGroups/write",
			Target: group.ResourceID(scope), Outcome: "Succeeded"}
		mutations := []clientv3.Op{clientv3.OpPut(key, string(data)), r.auditOp(scope, event)}
		if created {
			mutations = append(mutations, clientv3.OpDelete(r.deletionKey(scope, name)))
		}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision)).Then(mutations...).Commit()
		if err != nil {
			return arm.Group{}, false, err
		}
		if result.Succeeded {
			return group, created, nil
		}
	}
	return arm.Group{}, false, errors.New("resource group changed concurrently")
}

func decodeGroup(value []byte, name string) (arm.Group, error) {
	var group arm.Group
	if err := json.Unmarshal(value, &group); err != nil {
		return arm.Group{}, fmt.Errorf("decode resource group: %w", err)
	}
	if group.Name == "" || strings.ToLower(group.Name) != name || group.Location == "" || group.Tags == nil {
		return arm.Group{}, errors.New("invalid resource group record")
	}
	return group, nil
}
