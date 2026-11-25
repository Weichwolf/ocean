package controlplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) HostDirectoryBootstrap(ctx context.Context, host string, certificate []byte, tenant, generation string) ([]byte, error) {
	if !validCapacity(r.directoryCapacity) || r.workloads == nil || !identifier.MatchString(tenant) || !identifier.MatchString(generation) {
		return nil, enrollment.ErrHostDenied
	}
	key := r.managedDirectoryPlacementKey(tenant)
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(key), clientv3.OpGet(r.managedDirectoryKey(tenant))).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return nil, err
	}
	var live enrollment.Availability
	if json.Unmarshal(snapshot.Responses[1].GetResponseRange().Kvs[0].Value, &live) != nil || !live.DirectoryRuntime {
		return nil, enrollment.ErrHostDenied
	}
	rows := snapshot.Responses[2].GetResponseRange().Kvs
	var placement directoryPlacement
	if len(rows) == 0 {
		return nil, enrollment.ErrHostDenied
	}
	if json.Unmarshal(rows[0].Value, &placement) != nil || placement.DirectoryID == "" {
		return nil, errors.New("invalid managed directory placement")
	}
	primary := placement.Controllers[0]
	if primary.HostID != host || primary.Generation != generation {
		return nil, enrollment.ErrHostDenied
	}
	directories := snapshot.Responses[3].GetResponseRange().Kvs
	var directory identity.ManagedDirectory
	if len(directories) != 1 || json.Unmarshal(directories[0].Value, &directory) != nil ||
		directory.ID != placement.DirectoryID || directory.TenantID != tenant {
		return nil, enrollment.ErrHostDenied
	}
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: directory.SubscriptionID}
	if !validScope(scope) || !identifier.MatchString(primary.ID) {
		return nil, errors.New("invalid directory controller identity")
	}
	active, err := r.client.Get(ctx, r.hostReservationKey(scope, host, primary.ID), clientv3.WithRev(snapshot.Header.Revision))
	if err != nil {
		return nil, err
	}
	var assignment enrollment.Assignment
	if len(active.Kvs) != 1 || json.Unmarshal(active.Kvs[0].Value, &assignment) != nil || assignment.Generation != generation ||
		assignment.Directory == nil || assignment.Directory.DirectoryID != directory.ID || assignment.Directory.ControllerIndex != 1 {
		return nil, enrollment.ErrHostDenied
	}
	return r.workloads.sealer.Open(nil, nil, placement.Bootstrap, placement.bootstrapLabel(key))
}
