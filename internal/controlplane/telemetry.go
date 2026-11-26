package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/telemetry"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type telemetryConfig struct {
	Etcd             etcdConfig `json:"etcd"`
	RetentionSeconds int64      `json:"retentionSeconds"`
}

type telemetryControl struct {
	client    *clientv3.Client
	retention time.Duration
	pool      string
	mu        sync.Mutex
	leases    map[time.Time]clientv3.LeaseID
}

func openTelemetry(config *telemetryConfig, pool string) (*telemetryControl, error) {
	if config == nil {
		return nil, nil
	}
	if config.RetentionSeconds < 300 || config.RetentionSeconds > 86400 {
		return nil, errors.New("telemetry retention must be between 300 and 86400 seconds")
	}
	options, err := config.Etcd.clientConfig()
	if err != nil {
		return nil, err
	}
	client, err := clientv3.New(options)
	if err != nil {
		return nil, err
	}
	return &telemetryControl{client: client, retention: time.Duration(config.RetentionSeconds) * time.Second,
		pool: pool, leases: make(map[time.Time]clientv3.LeaseID)}, nil
}

// Batch expiries share leases by observation minute. Buffered observations thus
// expire according to when they occurred, including after an ingestion retry.
const telemetryLeaseWindow = time.Minute

func (control *telemetryControl) leaseThrough(ctx context.Context, expires time.Time) (clientv3.LeaseID, error) {
	control.mu.Lock()
	defer control.mu.Unlock()
	now := time.Now().UTC()
	if lease := control.leases[expires]; lease != 0 && expires.After(now) {
		return lease, nil
	}
	for old := range control.leases {
		if !old.After(now) {
			delete(control.leases, old)
		}
	}
	ttl := max(1, int64((expires.Sub(now)+time.Second-1)/time.Second))
	granted, err := control.client.Grant(ctx, ttl)
	if err != nil {
		return 0, err
	}
	control.leases[expires] = granted.ID
	return granted.ID, nil
}

func (r *Region) telemetryPrefix(scope arm.SubscriptionScope, address arm.ResourceAddress, created int64) string {
	return fmt.Sprintf("%stelemetry/%s/%d/", r.armPrefix(scope), address.Key(), created)
}

func telemetryTime(t time.Time) string { return fmt.Sprintf("%020d", t.UnixNano()) }

func (r *Region) ReportTelemetry(ctx context.Context, host string, certificate []byte, batch telemetry.Batch) error {
	if r.telemetry == nil {
		return telemetry.ErrDisabled
	}
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)),
		clientv3.OpGet(r.hostKey("live", host))).Commit()
	if err != nil {
		return err
	}
	registration, err := r.authorizeRegisteredHost(host, certificate, "compute", snapshot)
	if err != nil {
		return err
	}
	assignments := make(map[telemetry.Assignment]string)
	samples := make(map[string]telemetry.Sample)
	allowed := make(map[arm.SubscriptionScope]bool)
	earliest := time.Now().Add(-r.telemetry.retention)
	for _, entry := range batch.Observations {
		if entry.Sample.Time.Before(earliest) {
			continue
		}
		id := entry.Assignment
		prefix, found := assignments[id]
		if !found {
			scope := arm.SubscriptionScope{TenantID: id.TenantID, SubscriptionID: id.SubscriptionID}
			if r.telemetry.pool != "" && validScope(scope) {
				admitted, seen := allowed[scope]
				if !seen {
					admitted, err = r.hostedTelemetryAdmission(ctx, scope, registration.Pool, snapshot.Header.Revision)
					if err != nil {
						return err
					}
					allowed[scope] = admitted
				}
				if !admitted {
					continue
				}
			}
			prefix, err = r.telemetryAssignment(ctx, scope, host, id, snapshot.Header.Revision)
			if err != nil {
				return err
			}
			assignments[id] = prefix
		}
		// A previously assigned workload may have been retired while its
		// samples were queued. Discard stale samples without blocking the batch.
		if prefix != "" {
			key := prefix + telemetryTime(entry.Sample.Time) + "/" + entry.Sample.ID
			samples[key] = entry.Sample
		}
	}
	return r.telemetry.store(ctx, samples)
}

func (control *telemetryControl) store(ctx context.Context, samples map[string]telemetry.Sample) error {
	if len(samples) == 0 {
		return nil
	}
	leases := make(map[time.Time]clientv3.LeaseID)
	writes := make([]clientv3.Op, 0, len(samples))
	for key, sample := range samples {
		expires := sample.Time.UTC().Add(control.retention).Truncate(telemetryLeaseWindow).Add(telemetryLeaseWindow)
		lease := leases[expires]
		if lease == 0 {
			var err error
			lease, err = control.leaseThrough(ctx, expires)
			if err != nil {
				return err
			}
			leases[expires] = lease
		}
		data, err := json.Marshal(sample)
		if err != nil {
			return err
		}
		writes = append(writes, clientv3.OpPut(key, string(data), clientv3.WithLease(lease)))
	}
	_, err := control.client.Txn(ctx).Then(writes...).Commit()
	if errors.Is(err, rpctypes.ErrLeaseNotFound) {
		// A backend restore or revoke can invalidate a cached lease.
		control.mu.Lock()
		for expiry, id := range leases {
			if control.leases[expiry] == id {
				delete(control.leases, expiry)
			}
		}
		control.mu.Unlock()
	}
	return err
}

func (r *Region) telemetryAssignment(ctx context.Context, scope arm.SubscriptionScope, host string,
	id telemetry.Assignment, revision int64) (string, error) {
	if !validScope(scope) || !identifier.MatchString(id.ID) || !identifier.MatchString(id.Generation) {
		return "", enrollment.ErrHostDenied
	}
	index, err := r.client.Get(ctx, r.hostContainerKey(scope, host, id.ID), clientv3.WithRev(revision))
	if err != nil || len(index.Kvs) == 0 {
		return "", err
	}
	key := string(index.Kvs[0].Value)
	if !strings.HasPrefix(key, r.armPrefix(scope)+"containers/") {
		return "", errors.New("telemetry assignment does not match its subscription")
	}
	items, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil || len(items.Kvs) == 0 {
		return "", err
	}
	var workload containerRecord
	if json.Unmarshal(items.Kvs[0].Value, &workload) != nil || !workload.Address.Valid() ||
		r.containerKey(scope, workload.Address) != key || workload.Reservation.ID != id.ID {
		return "", errors.New("invalid assigned workload")
	}
	if workload.Reservation.HostID != host || workload.Reservation.Generation != id.Generation {
		return "", nil
	}
	return r.telemetryPrefix(scope, workload.Address, items.Kvs[0].CreateRevision), nil
}

func (r *Region) TelemetrySamples(ctx context.Context, scope arm.SubscriptionScope, reader string, address arm.ResourceAddress,
	start, end time.Time, limit int64) ([]telemetry.Sample, error) {
	resource, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(r.containerKey(scope, address)))
	if err != nil {
		return nil, err
	}
	if len(resource.Kvs) == 0 {
		return nil, arm.ErrContainerMissing
	}
	if r.telemetry == nil {
		return nil, telemetry.ErrDisabled
	}
	if r.telemetry.pool != "" {
		allowed, err := r.hostedTelemetryAdmission(ctx, scope, "", resource.Header.Revision)
		if err != nil || !allowed {
			return nil, errors.Join(telemetry.ErrDisabled, err)
		}
	}
	earliest := time.Now().Add(-r.telemetry.retention)
	if start.Before(earliest) {
		start = earliest
	}
	if start.After(end) {
		return nil, nil
	}
	prefix := r.telemetryPrefix(scope, address, resource.Kvs[0].CreateRevision)
	query, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	startKey, endKey := prefix+telemetryTime(start)+"/", prefix+telemetryTime(end.Add(time.Nanosecond))+"/"
	rows, err := r.telemetry.client.Get(query, startKey, clientv3.WithRange(endKey), clientv3.WithLimit(limit+1))
	if err != nil {
		return nil, errors.Join(telemetry.ErrDisabled, err)
	}
	if int64(len(rows.Kvs)) > limit || rows.More {
		return nil, telemetry.ErrTooManySamples
	}
	out := make([]telemetry.Sample, 0, len(rows.Kvs))
	for _, row := range rows.Kvs {
		var sample telemetry.Sample
		if json.Unmarshal(row.Value, &sample) != nil {
			return nil, errors.New("invalid stored telemetry sample")
		}
		out = append(out, sample)
	}
	return out, nil
}

func (r *Region) close() error {
	err := r.client.Close()
	if r.telemetry != nil {
		err = errors.Join(err, r.telemetry.client.Close())
	}
	if r.deletionLedger != nil {
		err = errors.Join(err, r.deletionLedger.client.Close())
	}
	return err
}
