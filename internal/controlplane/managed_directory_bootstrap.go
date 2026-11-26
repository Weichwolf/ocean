package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) HostDirectoryBootstrap(ctx context.Context, host string, certificate []byte, tenant, generation string) (enrollment.DirectoryBootstrap, error) {
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return enrollment.DirectoryBootstrap{}, err
	}
	bootstrap := enrollment.DirectoryBootstrap{DomainSID: binding.directory.DomainSID}
	writer := binding.placement.writerSlot()
	if binding.index == writer && bootstrap.DomainSID != "" && binding.assignment.Directory.RecoveryID == "" {
		// A previously initialized writer only needs its existing local keys.
		return bootstrap, nil
	}
	if binding.index != writer && binding.placement.Recovery != "" {
		scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: binding.directory.SubscriptionID}
		sid, _, err := r.directoryControllerHealth(ctx, binding.directory, scope, binding.placement.Controllers[writer], writer, binding.revision)
		if err != nil {
			return bootstrap, err
		}
		if sid == "" {
			return bootstrap, enrollment.ErrDirectoryAssignmentChanged
		}
	}
	bootstrap.Credential, err = r.workloads.sealer.Open(nil, nil, binding.placement.Bootstrap,
		binding.placement.bootstrapLabel(r.managedDirectoryPlacementKey(tenant)))
	return bootstrap, err
}

// CommitDirectoryIdentity authorizes a controller to start its AD listeners.
func (r *Region) CommitDirectoryIdentity(ctx context.Context, host string, certificate []byte, tenant, generation, sid string) error {
	if !(enrollment.DirectoryHealth{Ready: true, DomainSID: sid}).Valid() {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	key := r.managedDirectoryKey(tenant)
	directory := binding.directory
	var writes []clientv3.Op
	switch {
	case directory.DomainSID == sid:
		writes = append(writes, clientv3.OpGet(key, clientv3.WithCountOnly()))
	case directory.DomainSID == "" && binding.index == 0:
		directory.DomainSID = sid
		data, _ := json.Marshal(directory)
		scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: directory.SubscriptionID}
		writes = append(writes, clientv3.OpPut(key, string(data)), r.auditOp(scope, arm.AuditEvent{
			Time: time.Now().UTC(), Actor: "managed-directory-controller", Action: "Ocean.Identity/directories/initialize",
			Target: directory.ID, Outcome: "Succeeded",
		}))
	default:
		return enrollment.ErrDirectoryAssignmentChanged
	}
	result, err := r.client.Txn(ctx).If(binding.guards...).Then(writes...).Commit()
	if err == nil && !result.Succeeded {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	return err
}

type authorizedDirectoryController struct {
	placement  directoryPlacement
	directory  identity.ManagedDirectory
	index      int
	assignment enrollment.Assignment
	revision   int64
	lease      clientv3.LeaseID
	guards     []clientv3.Cmp
}

func (binding *authorizedDirectoryController) activeWriter() bool {
	return binding.index == binding.placement.writerSlot() && !binding.placement.Promoting && binding.placement.Recovery == ""
}

func (r *Region) authorizeDirectoryController(ctx context.Context, host string, certificate []byte, tenant, generation string) (*authorizedDirectoryController, error) {
	if !validCapacity(r.directoryCapacity) || r.workloads == nil || !identifier.MatchString(tenant) || !identifier.MatchString(generation) {
		return nil, enrollment.ErrHostDenied
	}
	if err := r.requireActiveHostedTenant(ctx, tenant); err != nil {
		if errors.Is(err, identity.ErrTenantSuspended) {
			return nil, enrollment.ErrHostDenied
		}
		return nil, err
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
	var assignment enrollment.Assignment
	if len(active.Kvs) != 1 || !directoryAssignmentMatches(active.Kvs[0].Value, directory, controller, index) ||
		json.Unmarshal(active.Kvs[0].Value, &assignment) != nil || assignment.Directory.ControllerNames != placement.Names {
		return nil, enrollment.ErrHostDenied
	}
	binding := &authorizedDirectoryController{placement: placement, directory: directory, index: index, assignment: assignment, revision: snapshot.Header.Revision,
		lease: clientv3.LeaseID(snapshot.Responses[1].GetResponseRange().Kvs[0].Lease)}
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
