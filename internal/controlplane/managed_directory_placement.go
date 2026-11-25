package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const directoryControllerCount = 2

type directoryPlacement struct {
	DirectoryID string                                `json:"directoryId"`
	Controllers [directoryControllerCount]Reservation `json:"controllers"`
}

func (r *Region) managedDirectoryPlacementKey(tenant string) string {
	return r.root + "/managed-directory-placements/" + tenant
}

func (r *Region) bootstrapManagedDirectories(ctx context.Context) error {
	key := r.root + "/managed-directory-config"
	if !validCapacity(r.directoryCapacity) {
		result, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && result.Count != 0 {
			return errors.New("managed directory configuration is required for this region")
		}
		return err
	}
	manifest, _ := json.Marshal(r.directoryCapacity)
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, string(manifest))).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != string(manifest) {
		return errors.New("managed directory configuration differs from the regional record")
	}
	return nil
}

func (r *Region) reconcileManagedDirectories(ctx context.Context, logger *slog.Logger) {
	prefix := r.managedDirectoryKey("")
	end := clientv3.GetPrefixRangeEnd(prefix)
	cursor := prefix
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		read, cancel := context.WithTimeout(ctx, 2*time.Second)
		page, err := r.client.Get(read, cursor, clientv3.WithRange(end), clientv3.WithKeysOnly(), clientv3.WithLimit(16))
		cancel()
		if err == nil {
			for _, item := range page.Kvs {
				if ctx.Err() != nil {
					return
				}
				tenant := strings.TrimPrefix(string(item.Key), prefix)
				run, cancel := context.WithTimeout(ctx, 4*time.Second)
				err = r.placeManagedDirectory(run, tenant)
				cancel()
				if err != nil && ctx.Err() == nil && !directoryPlacementPending(err) {
					logger.Warn("directory placement will retry", "tenant", tenant, "error", err)
				}
			}
			cursor = prefix
			if page.More {
				cursor = string(page.Kvs[len(page.Kvs)-1].Key) + "\x00"
			}
		} else if ctx.Err() == nil {
			logger.Warn("read pending directory requests", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func directoryPlacementPending(err error) bool {
	return errors.Is(err, ErrNoEligibleHost) || errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrPlacementPolicy) ||
		errors.Is(err, ErrPlacementSubnetUnavailable) || errors.Is(err, ErrSubnetAddressExhausted) || errors.Is(err, identity.ErrDirectoryTenant)
}

func (r *Region) placeManagedDirectory(ctx context.Context, tenantID string) error {
	// A saved pair represents admitted capacity even while the controllers are still starting.
	key := r.managedDirectoryPlacementKey(tenantID)
	existing, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
	if err != nil || existing.Count != 0 {
		return err
	}
	err = r.reserveDirectoryControllers(ctx, tenantID, key)
	if !directoryPlacementPending(err) {
		return err
	}
	// Reads of capacity, spread slots and addresses can observe the winning
	// transaction before this replica reaches its own compare-and-swap.
	existing, readErr := r.client.Get(ctx, key, clientv3.WithCountOnly())
	if readErr != nil || existing.Count != 0 {
		return readErr
	}
	return err
}

func (r *Region) reserveDirectoryControllers(ctx context.Context, tenantID, key string) error {
	tenant, err := r.LookupTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil || !tenant.Valid(tenantID) {
		return identity.ErrDirectoryTenant
	}
	directory, guards, err := r.managedDirectorySnapshot(ctx, *tenant)
	if err != nil || directory == nil {
		return err
	}
	scope := arm.SubscriptionScope{TenantID: directory.TenantID, SubscriptionID: directory.SubscriptionID}
	parent, subnet, ok := arm.SubnetParent(scope, directory.Spec.SubnetID)
	if !ok {
		return fmt.Errorf("invalid private subnet in directory %s", directory.ID)
	}
	lockKey := r.managedDirectorySubnetLock(scope, parent, subnet)
	lock, err := r.client.Get(ctx, lockKey)
	if err != nil {
		return err
	}
	if len(lock.Kvs) != 0 && string(lock.Kvs[0].Value) != directory.ID {
		return ErrPlacementSubnetUnavailable
	}
	base := r.armPrefix(scope)
	policyKey := base + "placement-policy"
	policy, revision, err := r.placementPolicy(ctx, policyKey, true)
	if err != nil {
		return err
	}
	usage, err := r.counter(ctx, base+"placement-usage")
	if err != nil {
		return err
	}
	perController := r.directoryCapacity
	if !validCapacity(perController) {
		return errors.New("managed directory controller capacity must be positive")
	}
	if !fits(policy.Quota, usage.used, perController) || !fits(policy.Quota, addCapacity(usage.used, perController), perController) {
		return ErrQuotaExceeded
	}
	request := PlacementRequest{Cell: r.cell, Role: "compute", Resources: perController,
		SubnetID: directory.Spec.SubnetID, NeedsContainerNetwork: true, SpreadSet: "directory-" + directory.ID}
	hosts, err := r.chooseHosts(ctx, scope, request, policy.Pools, directoryControllerCount)
	if err != nil {
		return err
	}
	addresses, err := r.allocateSubnetAddresses(ctx, scope, request.SubnetID, directoryControllerCount)
	if err != nil {
		return err
	}
	placement := directoryPlacement{DirectoryID: directory.ID}
	controllerIPs := [directoryControllerCount]netip.Addr{addresses[0].address, addresses[1].address}
	guards = append(guards, usage.compare(), clientv3.Compare(clientv3.ModRevision(policyKey), "=", revision),
		clientv3.Compare(clientv3.Version(key), "=", 0))
	writes := []clientv3.Op{usage.write(addCapacity(perController, perController))}
	if len(lock.Kvs) == 0 {
		// Requests from before subnet holds were introduced acquire the hold
		// together with their first controller placement.
		guards = append(guards, clientv3.Compare(clientv3.Version(lockKey), "=", 0))
		writes = append(writes, clientv3.OpPut(lockKey, directory.ID))
	} else {
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(lockKey), "=", lock.Kvs[0].ModRevision))
	}
	for i, host := range hosts {
		address := addresses[i]
		request.ID = request.SpreadSet + "-" + strconv.Itoa(i+1)
		reservation := Reservation{PlacementRequest: request, Generation: operationID(), HostID: host.host.HostID, Pool: host.host.Pool,
			PrivateIPv4: address.address}
		placement.Controllers[i] = reservation
		assignment := &enrollment.DirectoryAssignment{DirectoryID: directory.ID, DNSName: directory.Spec.DNSName,
			NetBIOSName: directory.Spec.NetBIOSName, ControllerIndex: i + 1, ControllerIPv4: controllerIPs}
		hostGuards, hostWrites := r.placementWrites(scope, reservation, host, assignment)
		guards = append(append(guards, hostGuards...), address.guards...)
		writes = append(append(writes, hostWrites...), clientv3.OpPut(address.key, reservation.Generation))
	}
	data, _ := json.Marshal(placement)
	writes = append(writes, clientv3.OpPut(key, string(data)), r.auditOp(scope, arm.AuditEvent{
		Time: time.Now().UTC(), Actor: "managed-directory-controller", Action: "Ocean.Identity/directories/place",
		Target: directory.ID, Outcome: "Reserved",
	}))
	_, err = r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	// Another replica may have won, or capacity changed. The next scan retries
	// from the regional record without leaving an individual controller behind.
	return err
}
