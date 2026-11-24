package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// PublishHostCapacity renews a host's availability only while its registration
// and approval remain valid. A disconnected host's lease expires independently.
func (r *Region) PublishHostCapacity(ctx context.Context, id string, certificate []byte, report enrollment.Report) error {
	registered, approval, live := r.hostKey("registered", id), r.hostKey("inventory", id), r.hostKey("live", id)
	for range 4 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(registered), clientv3.OpGet(approval), clientv3.OpGet(live)).Commit()
		if err != nil {
			return err
		}
		hosts, approvals, previous := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs,
			snapshot.Responses[2].GetResponseRange().Kvs
		if len(hosts) != 1 || len(approvals) != 1 {
			return enrollment.ErrHostDenied
		}
		var host enrollment.Host
		var policy enrollment.Approval
		if json.Unmarshal(hosts[0].Value, &host) != nil || json.Unmarshal(approvals[0].Value, &policy) != nil || !policy.Valid() ||
			host.HostID != id || policy.HostID != id || host.Cell != policy.Cell || host.Pool != policy.Pool {
			return errors.New("invalid host availability policy")
		}
		if host.RevokedAt != nil || !bytes.Equal(host.Certificate, certificate) {
			return enrollment.ErrHostDenied
		}
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(registered), "=", hosts[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(approval), "=", approvals[0].ModRevision)}
		capacity, eligible := policy.Available(report)
		if !eligible {
			if _, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpDelete(live)).Commit(); err != nil {
				return err
			}
			return enrollment.ErrHostUnqualified
		}
		available, _ := json.Marshal(enrollment.Availability{HostID: id, Cell: policy.Cell, Pool: policy.Pool, Roles: policy.Roles, Capacity: capacity, ContainerNetwork: report.ContainerNetwork})
		var revision int64
		var lease clientv3.LeaseID
		if len(previous) == 1 {
			revision = previous[0].ModRevision
			if previous[0].Lease != 0 {
				candidate := clientv3.LeaseID(previous[0].Lease)
				if kept, err := r.client.KeepAliveOnce(ctx, candidate); err == nil && kept.TTL > 0 {
					if bytes.Equal(previous[0].Value, available) {
						return nil
					}
					lease = candidate
				}
			}
		}
		fresh := lease == 0
		if fresh {
			granted, err := r.client.Grant(ctx, int64(enrollment.HostAvailabilityTTL.Seconds()))
			if err != nil {
				return err
			}
			lease = granted.ID
		}
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(live), "=", revision))
		result, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpPut(live, string(available), clientv3.WithLease(lease))).Commit()
		if err == nil && result.Succeeded {
			return nil
		}
		if err != nil {
			return err // The transaction may have committed after the client timed out.
		}
		if fresh {
			_, _ = r.client.Revoke(ctx, lease)
		}
	}
	return errors.New("host availability changed concurrently")
}
