package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

var (
	ErrPlacementPolicy    = errors.New("tenant placement policy is unavailable")
	ErrQuotaExceeded      = errors.New("tenant reservation quota exceeded")
	ErrNoEligibleHost     = errors.New("no eligible host has sufficient available capacity")
	ErrReservationChanged = errors.New("reservation does not match its original request or generation")
)

type PlacementPolicy = identity.PlacementPolicy

type PlacementRequest struct {
	ID                    string              `json:"id"`
	Cell                  string              `json:"cell"`
	Role                  string              `json:"role"`
	Resources             enrollment.Capacity `json:"resources"`
	SubnetID              string              `json:"subnetId,omitempty"`
	NeedsContainerNetwork bool                `json:"needsContainerNetwork,omitempty"`
	NeedsDirectoryRuntime bool                `json:"needsDirectoryRuntime,omitempty"`
	NeedsStorage          bool                `json:"needsStorage,omitempty"`
	NeedsVMRuntime        bool                `json:"needsVMRuntime,omitempty"`
	SpreadSet             string              `json:"spreadSet,omitempty"`
}

type Reservation struct {
	PlacementRequest
	Generation  string     `json:"generation"`
	HostID      string     `json:"hostId"`
	Pool        string     `json:"pool"`
	PrivateIPv4 netip.Addr `json:"privateIPv4,omitzero"`
}

type capacityCounter struct {
	key      string
	used     enrollment.Capacity
	revision int64
}

func validCapacity(capacity enrollment.Capacity) bool {
	return capacity.CPUMillis > 0 && capacity.MemoryMiB > 0
}

func fits(limit, used, request enrollment.Capacity) bool {
	return used.CPUMillis <= limit.CPUMillis && used.MemoryMiB <= limit.MemoryMiB &&
		request.CPUMillis <= limit.CPUMillis-used.CPUMillis && request.MemoryMiB <= limit.MemoryMiB-used.MemoryMiB
}

func addCapacity(a, b enrollment.Capacity) enrollment.Capacity {
	return enrollment.Capacity{CPUMillis: a.CPUMillis + b.CPUMillis, MemoryMiB: a.MemoryMiB + b.MemoryMiB}
}

func (r *Region) counter(ctx context.Context, key string, options ...clientv3.OpOption) (capacityCounter, error) {
	counter := capacityCounter{key: key}
	result, err := r.client.Get(ctx, key, options...)
	if err != nil || len(result.Kvs) == 0 {
		return counter, err
	}
	item := result.Kvs[0]
	if json.Unmarshal(item.Value, &counter.used) != nil || counter.used.CPUMillis < 0 || counter.used.MemoryMiB < 0 {
		return capacityCounter{}, errors.New("invalid capacity counter")
	}
	counter.revision = item.ModRevision
	return counter, nil
}

func (c capacityCounter) compare() clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(c.key), "=", c.revision)
}

func (c capacityCounter) write(delta enrollment.Capacity) clientv3.Op {
	data, _ := json.Marshal(addCapacity(c.used, delta))
	return clientv3.OpPut(c.key, string(data))
}

func (r *Region) reservationKey(scope arm.SubscriptionScope, cell, id string) string {
	return r.root + "/cells/" + cell + "/reservations/" + scope.TenantID + "/" + scope.SubscriptionID + "/" + id
}

func (r *Region) hostReservationPrefix(id string) string { return r.hostKey("placements", id) + "/" }

func (r *Region) hostReservationKey(scope arm.SubscriptionScope, host, id string) string {
	return r.hostReservationPrefix(host) + scope.TenantID + "/" + scope.SubscriptionID + "/" + id
}

// HostAssignments reads only the current certified host's placement records.
// Authorization and the returned page share the same regional snapshot.
func (r *Region) HostAssignments(ctx context.Context, id string, certificate []byte, after string) (enrollment.AssignmentPage, error) {
	const size = 32
	prefix := r.hostReservationPrefix(id)
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", id)), clientv3.OpGet(r.hostKey("live", id), clientv3.WithCountOnly()),
		clientv3.OpGet(start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(size+1))).Commit()
	if err != nil {
		return enrollment.AssignmentPage{}, err
	}
	hosts := snapshot.Responses[0].GetResponseRange().Kvs
	if len(hosts) != 1 || snapshot.Responses[1].GetResponseRange().Count != 1 {
		return enrollment.AssignmentPage{}, enrollment.ErrHostDenied
	}
	var host enrollment.Host
	if json.Unmarshal(hosts[0].Value, &host) != nil || host.HostID != id || host.RevokedAt != nil || !bytes.Equal(host.Certificate, certificate) ||
		!r.hosted.allowsPool(host.Pool) {
		return enrollment.AssignmentPage{}, enrollment.ErrHostDenied
	}
	items := snapshot.Responses[2].GetResponseRange().Kvs
	count := min(len(items), size)
	page := enrollment.AssignmentPage{Assignments: make([]enrollment.Assignment, 0, count)}
	for _, item := range items[:count] {
		var assignment enrollment.Assignment
		if json.Unmarshal(item.Value, &assignment) != nil {
			return enrollment.AssignmentPage{}, errors.New("invalid host assignment")
		}
		scope := arm.SubscriptionScope{TenantID: assignment.TenantID, SubscriptionID: assignment.SubscriptionID}
		if !validScope(scope) || !identifier.MatchString(assignment.ID) || !identifier.MatchString(assignment.Generation) ||
			string(item.Key) != r.hostReservationKey(scope, id, assignment.ID) {
			return enrollment.AssignmentPage{}, errors.New("host assignment does not match its key")
		}
		if r.hosted != nil {
			if _, err := r.hostedPoolGuard(ctx, scope, host.Pool, snapshot.Header.Revision); err != nil {
				if errors.Is(err, ErrPlacementPolicy) {
					continue
				}
				return enrollment.AssignmentPage{}, err
			}
		}
		if directory := assignment.Directory; directory != nil {
			index, ips := directory.ControllerIndex, directory.ControllerIPv4
			if !identifier.MatchString(directory.DirectoryID) || assignment.Role != "compute" || assignment.SubnetID == "" ||
				index < 1 || index > len(ips) || ips[index-1] != assignment.PrivateIPv4 ||
				!ips[0].Is4() || !ips[1].Is4() || ips[0] == ips[1] {
				return enrollment.AssignmentPage{}, errors.New("invalid directory controller assignment")
			}
		}
		if assignment.SubnetID != "" {
			policy, err := r.assignedNetworkPolicy(ctx, scope, assignment, snapshot.Header.Revision)
			if err != nil && !errors.Is(err, ErrPlacementSubnetUnavailable) {
				return enrollment.AssignmentPage{}, err
			}
			assignment.Network, assignment.NetworkUnavailable = policy, err != nil
		}
		page.Assignments = append(page.Assignments, assignment)
	}
	if len(items) > count {
		page.Next = strings.TrimPrefix(string(items[count-1].Key), prefix)
	}
	return page, nil
}

func validScope(scope arm.SubscriptionScope) bool {
	return identifier.MatchString(scope.TenantID) && identifier.MatchString(scope.SubscriptionID)
}

// SetPlacementPolicy is called by the trusted provisioning plane. Workload
// requests inherit this policy from their subscription.
func (r *Region) SetPlacementPolicy(ctx context.Context, scope arm.SubscriptionScope, policy PlacementPolicy) error {
	_, err := r.writePlacementPolicy(ctx, scope, "", policy)
	if errors.Is(err, identity.ErrPlacementTenantGone) {
		return ErrPlacementPolicy
	}
	return err
}

func (r *Region) readPlacementSubscription(ctx context.Context, scope arm.SubscriptionScope) (int64, error) {
	if !validScope(scope) {
		return 0, identity.ErrPlacementTenantGone
	}
	_, key := r.tenantKeys(scope.TenantID)
	rows, err := r.client.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	if len(rows.Kvs) == 0 {
		return 0, identity.ErrPlacementTenantGone
	}
	var sub identity.Subscription
	if json.Unmarshal(rows.Kvs[0].Value, &sub) != nil || !sub.Valid(scope.TenantID) {
		return 0, errors.New("invalid placement subscription")
	}
	if sub.SubscriptionID != scope.SubscriptionID {
		return 0, identity.ErrPlacementTenantGone
	}
	return rows.Kvs[0].ModRevision, nil
}

func (r *Region) ReadTenantPlacementPolicy(ctx context.Context, sub identity.Subscription, actor string) (PlacementPolicy, error) {
	scope := arm.SubscriptionScope{TenantID: sub.TenantID, SubscriptionID: sub.SubscriptionID}
	_, subKey := r.tenantKeys(scope.TenantID)
	for range 8 {
		revision, err := r.readPlacementSubscription(ctx, scope)
		if err != nil {
			return PlacementPolicy{}, err
		}
		key := r.armPrefix(scope) + "placement-policy"
		policy, policyRevision, err := r.placementPolicy(ctx, key, true)
		if err != nil {
			return PlacementPolicy{}, err
		}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(subKey), "=", revision),
			clientv3.Compare(clientv3.ModRevision(key), "=", policyRevision)).Then(r.placementAudit(scope, actor, "read")).Commit()
		if err != nil || result.Succeeded {
			return policy, err
		}
	}
	return PlacementPolicy{}, errors.New("tenant placement policy changed concurrently")
}

func (r *Region) WriteTenantPlacementPolicy(ctx context.Context, sub identity.Subscription, actor string, policy PlacementPolicy) (PlacementPolicy, error) {
	stored, err := r.writePlacementPolicy(ctx, arm.SubscriptionScope{TenantID: sub.TenantID, SubscriptionID: sub.SubscriptionID}, actor, policy)
	switch {
	case errors.Is(err, ErrPlacementPolicy):
		return PlacementPolicy{}, identity.ErrPlacementPolicy
	case errors.Is(err, ErrQuotaExceeded):
		return PlacementPolicy{}, identity.ErrPlacementPolicyQuota
	default:
		return stored, err
	}
}

func (r *Region) writePlacementPolicy(ctx context.Context, scope arm.SubscriptionScope, actor string, policy PlacementPolicy) (PlacementPolicy, error) {
	if len(policy.Pools) == 0 || len(policy.Pools) > 16 || !validCapacity(policy.Quota) || !r.hosted.allowsPlacement(policy.Pools) {
		return PlacementPolicy{}, ErrPlacementPolicy
	}
	policy.Pools = slices.Clone(policy.Pools)
	slices.Sort(policy.Pools)
	for i, name := range policy.Pools {
		if !identifier.MatchString(name) || i > 0 && policy.Pools[i-1] == name {
			return PlacementPolicy{}, ErrPlacementPolicy
		}
	}
	base := r.armPrefix(scope)
	key := base + "placement-policy"
	_, subKey := r.tenantKeys(scope.TenantID)
	for range 8 {
		subRevision, err := r.readPlacementSubscription(ctx, scope)
		if err != nil {
			return PlacementPolicy{}, err
		}
		used, err := r.counter(ctx, base+"placement-usage")
		if err != nil {
			return PlacementPolicy{}, err
		}
		if !fits(policy.Quota, used.used, enrollment.Capacity{}) {
			return PlacementPolicy{}, ErrQuotaExceeded
		}
		guards := []clientv3.Cmp{used.compare(), clientv3.Compare(clientv3.ModRevision(subKey), "=", subRevision)}
		if r.hosted != nil {
			previous, revision, err := r.placementPolicy(ctx, key, true)
			if err != nil {
				return PlacementPolicy{}, err
			}
			if revision != 0 && previous.Quota == policy.Quota && slices.Equal(previous.Pools, policy.Pools) {
				return policy, nil // A retry preserves the original policy and its audit event.
			}
			guards = append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", revision))
			if slices.ContainsFunc(previous.Pools, func(pool string) bool { return !slices.Contains(policy.Pools, pool) }) {
				restrictions, err := r.narrowHostedPlacement(ctx, base, used)
				if err != nil {
					return PlacementPolicy{}, err
				}
				guards = append(guards, restrictions...)
			}
		}
		writes := []clientv3.Op{putJSON(key, policy)}
		if r.hosted != nil {
			writes = append(writes, r.advanceBackupPolicy())
		}
		if actor != "" {
			writes = append(writes, r.placementAudit(scope, actor, "write"))
		}
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return policy, err
		}
	}
	return PlacementPolicy{}, errors.New("tenant placement state changed concurrently")
}

func (r *Region) narrowHostedPlacement(ctx context.Context, base string, used capacityCounter) ([]clientv3.Cmp, error) {
	if used.used != (enrollment.Capacity{}) {
		return nil, identity.ErrPlacementPolicyInUse
	}
	var guards []clientv3.Cmp
	for _, prefix := range []string{base + "storage/shares/", base + "smb/groups/"} {
		rows, err := r.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if rows.Count != 0 {
			return nil, identity.ErrPlacementPolicyInUse
		}
		guards = append(guards, clientv3.Compare(clientv3.Version(prefix), "=", 0).WithPrefix())
	}
	return guards, nil
}

func (r *Region) placementAudit(scope arm.SubscriptionScope, actor, action string) clientv3.Op {
	return r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: "Ocean.Hosted/placementPolicies/" + action,
		Target: "/subscriptions/" + scope.SubscriptionID + "/providers/Ocean.Hosted/placementPolicies/default", Outcome: arm.OperationSucceeded})
}

// ReservePlacement commits one reservation together with tenant and host
// accounting. A lost response can be retried with the same placement request.
type placementMutation func(context.Context, Reservation) ([]clientv3.Cmp, []clientv3.Op, error)

func (r *Region) placementPolicy(ctx context.Context, key string, managed bool, options ...clientv3.OpOption) (PlacementPolicy, int64, error) {
	value, err := r.client.Get(ctx, key, options...)
	if err != nil {
		return PlacementPolicy{}, 0, err
	}
	if len(value.Kvs) == 1 {
		var policy PlacementPolicy
		if json.Unmarshal(value.Kvs[0].Value, &policy) != nil || !r.hosted.allowsPlacement(policy.Pools) {
			return PlacementPolicy{}, 0, ErrPlacementPolicy
		}
		return policy, value.Kvs[0].ModRevision, nil
	}
	if managed && r.workloads != nil && r.hosted.allowsPlacement(r.workloads.defaultPlacement.Pools) {
		return r.workloads.defaultPlacement, 0, nil
	}
	return PlacementPolicy{}, 0, ErrPlacementPolicy
}

func (r *Region) ReservePlacement(ctx context.Context, scope arm.SubscriptionScope, wanted PlacementRequest) (Reservation, error) {
	return r.reservePlacement(ctx, scope, wanted, nil)
}

func (r *Region) reservePlacement(ctx context.Context, scope arm.SubscriptionScope, wanted PlacementRequest, extra placementMutation) (Reservation, error) {
	if !validScope(scope) || !identifier.MatchString(wanted.ID) || !identifier.MatchString(wanted.Cell) ||
		!slices.Contains([]string{"compute", "storage", "gateway"}, wanted.Role) || !validCapacity(wanted.Resources) {
		return Reservation{}, ErrReservationChanged
	}
	if wanted.SpreadSet != "" && (!identifier.MatchString(wanted.SpreadSet) || wanted.Role != "compute" || wanted.NeedsStorage) {
		return Reservation{}, ErrReservationChanged
	}
	if wanted.SubnetID != "" && wanted.Role != "compute" {
		return Reservation{}, ErrPlacementSubnetUnavailable
	}
	base := r.armPrefix(scope)
	key := base + "placement-requests/" + wanted.ID
	var groupGeneration int64
	for range 12 {
		if saved, found, err := r.placementRetry(ctx, key, wanted); found || err != nil {
			return saved, err
		}
		policyKey := base + "placement-policy"
		policy, policyRevision, err := r.placementPolicy(ctx, policyKey, extra != nil)
		if err != nil {
			return Reservation{}, err
		}
		tenant, err := r.counter(ctx, base+"placement-usage")
		if err != nil {
			return Reservation{}, err
		}
		if !fits(policy.Quota, tenant.used, wanted.Resources) {
			if saved, found, err := r.placementRetry(ctx, key, wanted); found || err != nil {
				return saved, err
			}
			return Reservation{}, ErrQuotaExceeded
		}
		candidates, err := r.chooseHosts(ctx, scope, wanted, policy.Pools, 1)
		if err != nil {
			if errors.Is(err, ErrNoEligibleHost) {
				if saved, found, retryErr := r.placementRetry(ctx, key, wanted); found || retryErr != nil {
					return saved, retryErr
				}
			}
			return Reservation{}, err
		}
		candidate := candidates[0]
		expected := []clientv3.Cmp{tenant.compare(), clientv3.Compare(clientv3.ModRevision(policyKey), "=", policyRevision)}
		reservation := Reservation{PlacementRequest: wanted, Generation: operationID(), HostID: candidate.host.HostID, Pool: candidate.host.Pool}
		var writes []clientv3.Op
		if wanted.SubnetID != "" {
			allocation, err := r.allocateSubnet(ctx, scope, wanted.SubnetID)
			if err != nil {
				if saved, found, retryErr := r.placementRetry(ctx, key, wanted); found || retryErr != nil {
					return saved, retryErr
				}
				return Reservation{}, err
			}
			if groupGeneration != 0 && allocation.groupGeneration != groupGeneration {
				return Reservation{}, ErrPlacementSubnetUnavailable
			}
			groupGeneration = allocation.groupGeneration
			reservation.PrivateIPv4 = allocation.address
			expected = append(expected, allocation.guards...)
			writes = append(writes, clientv3.OpPut(allocation.key, reservation.Generation))
		}
		hostGuards, hostWrites := r.placementWrites(scope, reservation, candidate, nil)
		expected = append(expected, hostGuards...)
		writes = append(append(writes, hostWrites...), tenant.write(wanted.Resources))
		if extra != nil {
			checks, additional, err := extra(ctx, reservation)
			if err != nil {
				if saved, found, retryErr := r.placementRetry(ctx, key, wanted); found || retryErr != nil {
					return saved, retryErr
				}
				return Reservation{}, err
			}
			expected = append(expected, checks...)
			writes = append(writes, additional...)
		}
		result, err := r.client.Txn(ctx).If(expected...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return reservation, err
		}
	}
	return Reservation{}, errors.New("placement changed concurrently")
}

func (r *Region) placementWrites(scope arm.SubscriptionScope, reservation Reservation, candidate placementHost,
	directory *enrollment.DirectoryAssignment) ([]clientv3.Cmp, []clientv3.Op) {
	key := r.armPrefix(scope) + "placement-requests/" + reservation.ID
	cell := r.reservationKey(scope, reservation.Cell, reservation.ID)
	host := r.hostReservationKey(scope, reservation.HostID, reservation.ID)
	data, _ := json.Marshal(reservation)
	guards := append(candidate.guards, clientv3.Compare(clientv3.Version(key), "=", 0),
		clientv3.Compare(clientv3.Version(cell), "=", 0), clientv3.Compare(clientv3.Version(host), "=", 0))
	writes := []clientv3.Op{clientv3.OpPut(key, string(data)), clientv3.OpPut(cell, string(data)),
		putJSON(host, placementAssignment(scope, reservation, directory)), candidate.usage.write(reservation.Resources)}
	if reservation.SpreadSet != "" {
		writes = append(writes, clientv3.OpPut(r.spreadHostKey(scope, reservation.SpreadSet, reservation.HostID), reservation.Generation))
	}
	return guards, writes
}

func placementAssignment(scope arm.SubscriptionScope, reservation Reservation, directory *enrollment.DirectoryAssignment) enrollment.Assignment {
	return enrollment.Assignment{ID: reservation.ID, Generation: reservation.Generation, Cell: reservation.Cell,
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Role: reservation.Role, Resources: reservation.Resources,
		SubnetID: reservation.SubnetID, PrivateIPv4: reservation.PrivateIPv4, Directory: directory}
}

func (r *Region) placementRetry(ctx context.Context, key string, wanted PlacementRequest) (Reservation, bool, error) {
	current, err := r.client.Get(ctx, key)
	if err != nil || len(current.Kvs) == 0 {
		return Reservation{}, false, err
	}
	var saved Reservation
	if json.Unmarshal(current.Kvs[0].Value, &saved) != nil || saved.PlacementRequest != wanted || saved.Generation == "" {
		return Reservation{}, false, ErrReservationChanged
	}
	return saved, true, nil
}

type placementHost struct {
	host   enrollment.Availability
	usage  capacityCounter
	guards []clientv3.Cmp
}

func (r *Region) spreadHostKey(scope arm.SubscriptionScope, set, host string) string {
	return r.armPrefix(scope) + "placement-spread/" + set + "/" + host
}

func (r *Region) chooseHosts(ctx context.Context, scope arm.SubscriptionScope, wanted PlacementRequest, pools []string, count int, excluded ...string) ([]placementHost, error) {
	available, err := r.client.Get(ctx, r.hostKey("live", ""), clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	selected := make([]placementHost, 0, count)
	for _, item := range available.Kvs {
		var host enrollment.Availability
		if json.Unmarshal(item.Value, &host) != nil || !identifier.MatchString(host.HostID) || string(item.Key) != r.hostKey("live", host.HostID) || item.Lease == 0 {
			return nil, errors.New("invalid available host record")
		}
		if slices.Contains(excluded, host.HostID) || host.Cell != wanted.Cell || !slices.Contains(host.Roles, wanted.Role) || !slices.Contains(pools, host.Pool) || !r.hosted.allowsPool(host.Pool) ||
			wanted.NeedsContainerNetwork && !host.ContainerNetwork || wanted.NeedsDirectoryRuntime && !host.DirectoryRuntime ||
			wanted.NeedsVMRuntime && !host.VMRuntime ||
			wanted.NeedsStorage && (r.storage == nil || !slices.Contains(r.storage.workers, host.HostID)) {
			continue
		}
		drainKey := r.hostKey("drain", host.HostID)
		drain, err := r.client.Get(ctx, drainKey, clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if drain.Count != 0 {
			continue
		}
		used, err := r.counter(ctx, r.hostKey("placement-usage", host.HostID))
		if err != nil {
			return nil, err
		}
		if !fits(host.Capacity, used.used, wanted.Resources) {
			continue
		}
		guards := []clientv3.Cmp{used.compare(), clientv3.Compare(clientv3.ModRevision(string(item.Key)), "=", item.ModRevision),
			clientv3.Compare(clientv3.Version(drainKey), "=", 0)}
		if wanted.SpreadSet != "" {
			key := r.spreadHostKey(scope, wanted.SpreadSet, host.HostID)
			occupied, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
			if err != nil {
				return nil, err
			}
			if occupied.Count != 0 {
				continue
			}
			guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
		}
		selected = append(selected, placementHost{host: host, usage: used, guards: guards})
		if len(selected) == count {
			return selected, nil
		}
	}
	return nil, ErrNoEligibleHost
}

// ReleasePlacement returns capacity after the caller has stopped the placement.
func (r *Region) ReleasePlacement(ctx context.Context, scope arm.SubscriptionScope, cell, id, generation string) error {
	return r.releasePlacement(ctx, scope, cell, id, generation, nil)
}

func (r *Region) releasePlacement(ctx context.Context, scope arm.SubscriptionScope, cell, id, generation string, extra placementMutation) error {
	if !validScope(scope) || !identifier.MatchString(cell) || !identifier.MatchString(id) || !identifier.MatchString(generation) {
		return ErrReservationChanged
	}
	base := r.armPrefix(scope)
	key := base + "placement-requests/" + id
	cellKey := r.reservationKey(scope, cell, id)
	for range 12 {
		current, err := r.client.Get(ctx, key)
		if err != nil || len(current.Kvs) == 0 {
			return err
		}
		item := current.Kvs[0]
		var saved Reservation
		if json.Unmarshal(item.Value, &saved) != nil || saved.Generation != generation || saved.Cell != cell ||
			!identifier.MatchString(saved.HostID) || !validCapacity(saved.Resources) {
			return ErrReservationChanged
		}
		tenant, err := r.counter(ctx, base+"placement-usage")
		if err != nil {
			return err
		}
		host, err := r.counter(ctx, r.hostKey("placement-usage", saved.HostID))
		if err != nil {
			return err
		}
		if !fits(tenant.used, enrollment.Capacity{}, saved.Resources) || !fits(host.used, enrollment.Capacity{}, saved.Resources) {
			latest, err := r.client.Get(ctx, key)
			if err != nil {
				return err
			}
			if len(latest.Kvs) == 0 || latest.Kvs[0].ModRevision != item.ModRevision {
				continue
			}
			return errors.New("inconsistent reservation accounting")
		}
		delta := enrollment.Capacity{CPUMillis: -saved.Resources.CPUMillis, MemoryMiB: -saved.Resources.MemoryMiB}
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision), tenant.compare(), host.compare()}
		writes := []clientv3.Op{clientv3.OpDelete(key), clientv3.OpDelete(cellKey), clientv3.OpDelete(r.hostReservationKey(scope, saved.HostID, id)),
			tenant.write(delta), host.write(delta)}
		if saved.SpreadSet != "" {
			spread := r.spreadHostKey(scope, saved.SpreadSet, saved.HostID)
			guards = append(guards, clientv3.Compare(clientv3.Value(spread), "=", generation))
			writes = append(writes, clientv3.OpDelete(spread))
		}
		if saved.SubnetID != "" {
			parent, name, ok := arm.SubnetParent(scope, saved.SubnetID)
			if !ok || !saved.PrivateIPv4.Is4() {
				return ErrReservationChanged
			}
			allocation := r.subnetNetworkPlacements(scope, parent, name) + saved.PrivateIPv4.String()
			guards = append(guards, clientv3.Compare(clientv3.Value(allocation), "=", generation))
			writes = append(writes, clientv3.OpDelete(allocation))
		}
		if extra != nil {
			checks, additional, err := extra(ctx, saved)
			if err != nil {
				return err
			}
			guards = append(guards, checks...)
			writes = append(writes, additional...)
		}
		result, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return errors.New("reservation accounting changed concurrently")
}

// SetHostDraining blocks new placements while existing reservations reconcile.
func (r *Region) SetHostDraining(ctx context.Context, id string, draining bool) error {
	if !identifier.MatchString(id) {
		return enrollment.ErrHostDenied
	}
	key := r.hostKey("drain", id)
	change := clientv3.OpDelete(key)
	if draining {
		change = clientv3.OpPut(key, "true")
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(r.hostKey("registered", id)), ">", 0)).Then(change).Commit()
	if err == nil && !result.Succeeded {
		return enrollment.ErrHostDenied
	}
	return err
}
