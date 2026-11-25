package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) HostDirectoryBootstrap(ctx context.Context, host string, certificate []byte, tenant, generation string) ([]byte, error) {
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return nil, err
	}
	return r.workloads.sealer.Open(nil, nil, binding.placement.Bootstrap,
		binding.placement.bootstrapLabel(r.managedDirectoryPlacementKey(tenant)))
}

type authorizedDirectoryController struct {
	placement directoryPlacement
	lease     clientv3.LeaseID
	guards    []clientv3.Cmp
}

func (r *Region) authorizeDirectoryController(ctx context.Context, host string, certificate []byte, tenant, generation string) (*authorizedDirectoryController, error) {
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
	index := slices.IndexFunc(placement.Controllers[:], func(controller Reservation) bool {
		return controller.HostID == host && controller.Generation == generation
	})
	if index < 0 {
		return nil, enrollment.ErrHostDenied
	}
	directories := snapshot.Responses[3].GetResponseRange().Kvs
	var directory identity.ManagedDirectory
	if len(directories) != 1 || json.Unmarshal(directories[0].Value, &directory) != nil ||
		directory.ID != placement.DirectoryID || directory.TenantID != tenant {
		return nil, enrollment.ErrHostDenied
	}
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: directory.SubscriptionID}
	controller := placement.Controllers[index]
	if !validScope(scope) || !identifier.MatchString(controller.ID) {
		return nil, errors.New("invalid directory controller identity")
	}
	assignmentKey := r.hostReservationKey(scope, host, controller.ID)
	active, err := r.client.Get(ctx, assignmentKey, clientv3.WithRev(snapshot.Header.Revision))
	if err != nil {
		return nil, err
	}
	if len(active.Kvs) != 1 || !directoryAssignmentMatches(active.Kvs[0].Value, directory, controller, index) {
		return nil, enrollment.ErrHostDenied
	}
	binding := &authorizedDirectoryController{placement: placement, lease: clientv3.LeaseID(snapshot.Responses[1].GetResponseRange().Kvs[0].Lease)}
	for _, response := range snapshot.Responses {
		kv := response.GetResponseRange().Kvs[0]
		binding.guards = append(binding.guards, clientv3.Compare(clientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision))
	}
	binding.guards = append(binding.guards, clientv3.Compare(clientv3.ModRevision(assignmentKey), "=", active.Kvs[0].ModRevision))
	return binding, nil
}

func directoryAssignmentMatches(raw []byte, directory identity.ManagedDirectory, controller Reservation, index int) bool {
	var assigned enrollment.Assignment
	return json.Unmarshal(raw, &assigned) == nil && assigned.Generation == controller.Generation &&
		assigned.ID == controller.ID && assigned.TenantID == directory.TenantID && assigned.SubscriptionID == directory.SubscriptionID &&
		assigned.PrivateIPv4 == controller.PrivateIPv4 && assigned.Directory != nil &&
		assigned.Directory.DirectoryID == directory.ID && assigned.Directory.ControllerIndex == index+1 &&
		assigned.Directory.DNSName == directory.Spec.DNSName && assigned.Directory.NetBIOSName == directory.Spec.NetBIOSName &&
		assigned.Directory.ControllerIPv4[index] == controller.PrivateIPv4
}
