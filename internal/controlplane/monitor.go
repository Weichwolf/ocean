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

func auditGroup(target string) string {
	parts := strings.SplitN(target, "/", 6)
	if len(parts) < 5 || !strings.EqualFold(parts[3], "resourceGroups") {
		return ""
	}
	return strings.ToLower(parts[4])
}

func compareActivity(a, b arm.ActivityRecord) int {
	switch {
	case a.Time.After(b.Time):
		return -1
	case a.Time.Before(b.Time):
		return 1
	default:
		return strings.Compare(b.ID, a.ID)
	}
}

func (r *Region) ListActivity(ctx context.Context, scope arm.SubscriptionScope, reader string, filter arm.ActivityFilter, limit int) ([]arm.ActivityRecord, error) {
	prefix := r.armPrefix(scope) + "audit/"
	end := clientv3.GetPrefixRangeEnd(prefix)
	start := prefix
	var revision int64
	if reader != "" && filter.Group != "" {
		grant := r.groupGrantPrefix(scope, filter.Group) + reader
		entry, err := r.client.Get(ctx, grant, clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if entry.Count == 0 {
			return nil, arm.ErrRoleDenied
		}
		revision = entry.Header.Revision
	}
	rows := make([]arm.ActivityRecord, 0, limit)
	access := make(map[string]bool)
	var expiration time.Time
	if r.auditRetention != 0 {
		expiration = time.Now().Add(-r.auditRetention)
	}
	boundary := arm.ActivityRecord{ID: filter.BeforeID, AuditEvent: arm.AuditEvent{Time: filter.BeforeTime}}
	for start < end {
		entries, err := r.client.Get(ctx, start, clientv3.WithRange(end), clientv3.WithLimit(128), clientv3.WithRev(revision))
		if err != nil {
			return nil, err
		}
		if revision == 0 {
			revision = entries.Header.Revision
		}
		for _, entry := range entries.Kvs {
			var event arm.AuditEvent
			if json.Unmarshal(entry.Value, &event) != nil || event.Time.IsZero() || event.Action == "" {
				return nil, errors.New("invalid activity audit record")
			}
			group := auditGroup(event.Target)
			if !expiration.IsZero() && !event.Time.After(expiration) || event.Time.Before(filter.Start) || event.Time.After(filter.End) ||
				filter.Group != "" && !strings.EqualFold(filter.Group, group) ||
				filter.ResourceID != "" && !strings.EqualFold(filter.ResourceID, event.Target) ||
				filter.Caller != "" && !strings.EqualFold(filter.Caller, event.Actor) ||
				filter.Status != "" && !strings.EqualFold(filter.Status, event.Outcome) &&
					!(strings.EqualFold(filter.Status, "Failed") && event.Outcome == "Denied") {
				continue
			}
			row := arm.ActivityRecord{ID: strings.TrimPrefix(string(entry.Key), prefix), AuditEvent: event}
			if filter.BeforeID != "" && compareActivity(row, boundary) <= 0 {
				continue
			}
			if reader != "" && filter.Group == "" {
				granted, seen := access[group]
				if !seen && group != "" {
					check, err := r.client.Get(ctx, r.groupGrantPrefix(scope, group)+reader, clientv3.WithRev(revision), clientv3.WithCountOnly())
					if err != nil {
						return nil, err
					}
					granted = check.Count == 1
					access[group] = granted
				}
				if !granted {
					continue
				}
			}
			index, _ := slices.BinarySearchFunc(rows, row, compareActivity)
			if index < limit {
				if len(rows) == limit {
					rows = rows[:limit-1]
				}
				rows = slices.Insert(rows, index, row)
			}
		}
		if !entries.More {
			break
		}
		start = string(entries.Kvs[len(entries.Kvs)-1].Key) + "\x00"
	}
	return rows, nil
}

func (r *Region) WorkloadHealth(ctx context.Context, scope arm.SubscriptionScope, reader string, address arm.ResourceAddress) (*arm.ResourceHealth, error) {
	key := r.containerKey(scope, address)
	lookup, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(key))
	if err != nil || len(lookup.Kvs) == 0 {
		return nil, err
	}
	var record containerRecord
	if json.Unmarshal(lookup.Kvs[0].Value, &record) != nil || record.Address.Key() != address.Key() {
		return nil, errors.New("invalid workload health record")
	}
	// Inventory publishes observation changes in the same transaction.
	entry, err := r.client.Get(ctx, r.inventoryPrefix(scope)+address.Key(), clientv3.WithRev(lookup.Header.Revision))
	if err != nil || len(entry.Kvs) == 0 {
		return nil, err
	}
	inventory, err := decodeInventoryResource(entry.Kvs[0].Value, address.Key())
	if err != nil {
		return nil, err
	}
	health := arm.ResourceHealth{State: "Unknown", Reason: "Provisioning", ChangedAt: inventory.ChangedAt}
	if record.Desired == workload.Stopped && record.Observed == workload.Stopped {
		health.State, health.Reason, health.Category = "Unavailable", "UserInitiated", "Planned"
	} else if record.Observed == workload.Failed || record.Observed == workload.Stopped && record.Desired == workload.Running {
		health.State, health.Reason, health.Category = "Unavailable", "WorkloadNotRunning", "Unplanned"
	} else if record.Desired == workload.Running && record.Observed == workload.Running {
		live, err := r.client.Get(ctx, r.hostKey("live", record.Reservation.HostID), clientv3.WithRev(lookup.Header.Revision), clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if live.Count == 1 && inventory.ProvisioningState == arm.OperationSucceeded {
			health.State, health.Reason = "Available", "WorkloadRunning"
		} else if live.Count == 0 {
			health.State, health.Reason, health.Category = "Unavailable", "HostUnreachable", "Unplanned"
		}
	}
	return &health, nil
}

func (r *Region) RegionalUsage(ctx context.Context, scope arm.SubscriptionScope) (arm.RegionalUsage, error) {
	var usage arm.RegionalUsage
	if r.workloads == nil {
		return usage, ErrPlacementPolicy
	}
	base := r.armPrefix(scope)
	prefix := base + "containers/"
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(base+"placement-policy"), clientv3.OpGet(base+"placement-usage"),
		clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())).Commit()
	if err != nil {
		return usage, err
	}
	policy := r.workloads.defaultPlacement
	if rows := snapshot.Responses[0].GetResponseRange().Kvs; len(rows) > 0 {
		if json.Unmarshal(rows[0].Value, &policy) != nil || !validCapacity(policy.Quota) {
			return usage, ErrPlacementPolicy
		}
	}
	usage.CPULimitMillis, usage.MemoryLimitMiB = policy.Quota.CPUMillis, policy.Quota.MemoryMiB
	// An admitted container uses at least 10 millicores and 16 MiB.
	usage.GroupLimit = min(usage.CPULimitMillis/10, usage.MemoryLimitMiB/16)
	if rows := snapshot.Responses[1].GetResponseRange().Kvs; len(rows) > 0 {
		var capacity enrollment.Capacity
		if json.Unmarshal(rows[0].Value, &capacity) != nil || capacity.CPUMillis < 0 || capacity.MemoryMiB < 0 {
			return usage, errors.New("invalid workload reservation usage")
		}
		usage.CPUMillis, usage.MemoryMiB = capacity.CPUMillis, capacity.MemoryMiB
	}
	for _, row := range snapshot.Responses[2].GetResponseRange().Kvs {
		groupAndPath := strings.Split(strings.TrimPrefix(string(row.Key), prefix), "/")
		if len(groupAndPath) == 4 && strings.EqualFold(strings.Join(groupAndPath[1:3], "/"), workload.ContainerGroupType) {
			usage.Groups++
		}
	}
	return usage, nil
}
