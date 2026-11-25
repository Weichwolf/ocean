package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type directoryObservation struct {
	enrollment.DirectoryHealth
	ObservedAt time.Time `json:"observedAt"`
}

func (r *Region) directoryObservationKey(tenant, generation string) string {
	return r.root + "/managed-directory-health/" + tenant + "/" + generation
}

func (r *Region) readyDirectoryWriter(ctx context.Context, directory identity.ManagedDirectory, revision int64) (Reservation, []clientv3.Cmp, error) {
	key := r.managedDirectoryPlacementKey(directory.TenantID)
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return Reservation{}, nil, err
	}
	var placement directoryPlacement
	if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placement) != nil || placement.DirectoryID != directory.ID || placement.Promoting {
		return Reservation{}, nil, identity.ErrDirectoryJoinUnavailable
	}
	index := placement.writerSlot()
	writer := placement.Controllers[index]
	scope := arm.SubscriptionScope{TenantID: directory.TenantID, SubscriptionID: directory.SubscriptionID}
	sid, guards, err := r.directoryControllerHealth(ctx, directory, scope, writer, index, revision)
	if err != nil {
		return Reservation{}, nil, err
	}
	if sid == "" {
		return Reservation{}, nil, identity.ErrDirectoryJoinUnavailable
	}
	return writer, append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", rows.Kvs[0].ModRevision)), nil
}

// ReportDirectoryHealth records a probe only for the host's current assignment.
func (r *Region) ReportDirectoryHealth(ctx context.Context, host string, certificate []byte, tenant, generation string, health enrollment.DirectoryHealth) error {
	if !health.Valid() {
		return enrollment.ErrHostDenied
	}
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	if health.Ready && (binding.directory.DomainSID == "" || binding.directory.DomainSID != health.DomainSID) {
		health = enrollment.DirectoryHealth{}
	}
	report, _ := json.Marshal(directoryObservation{DirectoryHealth: health, ObservedAt: time.Now().UTC()})
	committed, err := r.client.Txn(ctx).If(binding.guards...).Then(
		clientv3.OpPut(r.directoryObservationKey(tenant, generation), string(report), clientv3.WithLease(binding.lease))).Commit()
	if err != nil {
		return err
	}
	if !committed.Succeeded {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	if !health.Ready {
		return nil
	}
	return r.completeDirectoryProvisioning(ctx, tenant)
}

func (r *Region) completeDirectoryProvisioning(ctx context.Context, tenant string) error {
	key := r.managedDirectoryKey(tenant)
	result, err := r.client.Get(ctx, key)
	if err != nil {
		return err
	}
	var directory identity.ManagedDirectory
	if len(result.Kvs) != 1 || json.Unmarshal(result.Kvs[0].Value, &directory) != nil || directory.TenantID != tenant {
		return errors.New("invalid managed directory for health report")
	}
	if !directory.ProvisionedAt.IsZero() {
		return nil
	}
	sid, guards, err := r.readManagedDirectoryHealth(ctx, &directory, result.Header.Revision)
	if err != nil || sid == "" {
		return err
	}
	directory.ProvisionedAt = time.Now().UTC()
	data, _ := json.Marshal(directory)
	guards = append(guards, clientv3.Compare(clientv3.ModRevision(key), "=", result.Kvs[0].ModRevision))
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: directory.SubscriptionID}
	_, err = r.client.Txn(ctx).If(guards...).Then(clientv3.OpPut(key, string(data)),
		r.auditOp(scope, arm.AuditEvent{Time: directory.ProvisionedAt, Actor: "managed-directory-controller",
			Action: "Ocean.Identity/directories/provision", Target: directory.ID, Outcome: "Succeeded"})).Commit()
	// Reports are periodic and retry a lost compare-and-swap.
	return err
}

func (r *Region) readManagedDirectoryHealth(ctx context.Context, directory *identity.ManagedDirectory, revision int64) (string, []clientv3.Cmp, error) {
	key := r.managedDirectoryPlacementKey(directory.TenantID)
	records, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil || len(records.Kvs) == 0 {
		return "", nil, err
	}
	var placement directoryPlacement
	scope := arm.SubscriptionScope{TenantID: directory.TenantID, SubscriptionID: directory.SubscriptionID}
	if len(records.Kvs) != 1 || json.Unmarshal(records.Kvs[0].Value, &placement) != nil ||
		placement.DirectoryID != directory.ID || !validScope(scope) {
		return "", nil, errors.New("invalid managed directory placement for health report")
	}
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", records.Kvs[0].ModRevision)}
	var observed [directoryControllerCount]string
	for i, controller := range placement.Controllers {
		if !identifier.MatchString(controller.HostID) || !identifier.MatchString(controller.ID) ||
			!identifier.MatchString(controller.Generation) || !controller.PrivateIPv4.Is4() {
			return "", nil, errors.New("invalid managed directory controller")
		}
		directory.Controllers[i] = identity.DirectoryControllerReadiness{
			DNSName: fmt.Sprintf("dc%02d.%s", i+1, directory.Spec.DNSName), PrivateIPv4: controller.PrivateIPv4,
			Writer: i == placement.writerSlot() && !placement.Promoting,
		}
		sid, checked, err := r.directoryControllerHealth(ctx, *directory, scope, controller, i, revision)
		if err != nil {
			return "", nil, err
		}
		observed[i] = sid
		directory.Controllers[i].Ready = sid != ""
		guards = append(guards, checked...)
	}
	if observed[0] != "" && observed[1] != "" {
		if observed[0] == observed[1] {
			return observed[0], guards, nil
		}
		// During initial provisioning there is no established SID to trust.
		directory.Controllers[0].Ready, directory.Controllers[1].Ready = false, false
	}
	return "", guards, nil
}

func (r *Region) directoryControllerHealth(ctx context.Context, directory identity.ManagedDirectory, scope arm.SubscriptionScope,
	controller Reservation, index int, revision int64) (string, []clientv3.Cmp, error) {
	read, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(r.hostKey("registered", controller.HostID), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("live", controller.HostID), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostReservationKey(scope, controller.HostID, controller.ID), clientv3.WithRev(revision)),
		clientv3.OpGet(r.directoryObservationKey(scope.TenantID, controller.Generation), clientv3.WithRev(revision))).Commit()
	if err != nil {
		return "", nil, err
	}
	for _, response := range read.Responses {
		if len(response.GetResponseRange().Kvs) != 1 {
			return "", nil, nil
		}
	}
	host, live := read.Responses[0].GetResponseRange().Kvs[0], read.Responses[1].GetResponseRange().Kvs[0]
	assignment, observation := read.Responses[2].GetResponseRange().Kvs[0], read.Responses[3].GetResponseRange().Kvs[0]
	var registered enrollment.Host
	var available enrollment.Availability
	var report directoryObservation
	if json.Unmarshal(host.Value, &registered) != nil || json.Unmarshal(live.Value, &available) != nil ||
		json.Unmarshal(observation.Value, &report) != nil {
		return "", nil, errors.New("invalid managed directory observation")
	}
	age := time.Since(report.ObservedAt)
	if registered.HostID != controller.HostID || registered.RevokedAt != nil || available.HostID != controller.HostID ||
		registered.Cell != available.Cell || registered.Pool != available.Pool ||
		!slices.Contains(registered.Roles, "compute") || !slices.Contains(available.Roles, "compute") ||
		!available.DirectoryRuntime || live.Lease == 0 || live.Lease != observation.Lease || !report.Ready || !report.Valid() ||
		directory.DomainSID != "" && directory.DomainSID != report.DomainSID ||
		age >= enrollment.HostAvailabilityTTL || age < -2*time.Second ||
		!directoryAssignmentMatches(assignment.Value, directory, controller, index) {
		return "", nil, nil
	}
	var guards []clientv3.Cmp
	for _, response := range read.Responses {
		kv := response.GetResponseRange().Kvs[0]
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(kv.Key)), "=", kv.ModRevision))
	}
	return report.DomainSID, guards, nil
}
