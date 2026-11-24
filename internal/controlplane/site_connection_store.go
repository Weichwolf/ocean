package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	createSiteConnection = "CreateSiteConnection"
	deleteSiteConnection = "DeleteSiteConnection"
)

type siteConnectionNetwork struct {
	parent     arm.ResourceAddress
	group      string
	subnetLock string
	prefixes   []netip.Prefix
	revision   int64
	guards     []clientv3.Cmp
}

func (r *Region) siteConnectionNetwork(ctx context.Context, scope arm.SubscriptionScope, desired arm.SiteConnectionRequest) (siteConnectionNetwork, error) {
	var target siteConnectionNetwork
	parent, child, ok := arm.SubnetParent(scope, desired.Subnet.ID(scope))
	if !ok || !strings.EqualFold(parent.Group, desired.Address.Group) {
		return target, arm.ErrLinkedResourceMissing
	}
	groupName := strings.ToLower(parent.Group)
	groupKey, vnetKey := r.groupPrefix(scope)+groupName, r.inventoryPrefix(scope)+parent.Key()
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(vnetKey)).Commit()
	if err != nil {
		return target, err
	}
	groups, networks := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	if len(groups) != 1 {
		return target, arm.ErrGroupMissing
	}
	group, err := decodeGroup(groups[0].Value, groupName)
	if err != nil {
		return target, err
	}
	if group.DeleteOperation != "" {
		return target, arm.ErrGroupDeleting
	}
	if len(networks) != 1 {
		return target, arm.ErrLinkedResourceMissing
	}
	_, subnet, err := decodeSubnet(networks[0].Value, parent.Key(), child)
	if errors.Is(err, ErrPlacementSubnetUnavailable) {
		return target, arm.ErrLinkedResourceMissing
	}
	if err != nil {
		return target, err
	}
	prefixes, err := subnet.Properties.Prefixes()
	if err != nil {
		return target, err
	}
	forbidden := slices.Clone(r.wireGuard.ProtectedPrefixes)
	forbidden = append(forbidden, prefixes...)
	for index, prefix := range forbidden {
		if slices.ContainsFunc(forbidden[:index], prefix.Overlaps) {
			return target, arm.InvalidDeployment{Cause: errors.New("the selected tenant subnet overlaps a protected network")}
		}
	}
	for _, remote := range desired.Properties.CustomerPrefixes {
		if slices.ContainsFunc(forbidden, remote.Overlaps) {
			return target, arm.InvalidDeployment{Cause: errors.New("the customer prefixes overlap the tenant subnet or a protected network")}
		}
	}
	for _, peer := range desired.Properties.Peers {
		if slices.ContainsFunc(forbidden, func(prefix netip.Prefix) bool {
			return prefix.Contains(peer.Endpoint.Addr()) || prefix.Overlaps(peer.GatewayTunnel.Masked())
		}) {
			return target, arm.InvalidDeployment{Cause: errors.New("a tunnel endpoint or link address overlaps a tenant or protected network")}
		}
	}
	return siteConnectionNetwork{parent: parent, group: group.Name, prefixes: prefixes,
		subnetLock: r.subnetNetworkPlacements(scope, parent, child) + "_site-connection", revision: snapshot.Header.Revision,
		guards: []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(vnetKey), "=", networks[0].ModRevision)}}, nil
}

func (r *Region) CreateSiteConnection(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.SiteConnectionRequest) (arm.InventoryResource, *arm.Operation, bool, error) {
	var empty arm.InventoryResource
	if r.wireGuard == nil {
		return empty, nil, false, arm.ErrGatewayExecutionUnavailable
	}
	target, err := r.siteConnectionNetwork(ctx, scope, desired)
	if err != nil {
		return empty, nil, false, err
	}
	desired.Address.Group = target.group
	recordKey := r.gatewayRecordKey(scope, desired.Address)
	payload, err := json.Marshal(desired)
	if err != nil {
		return empty, nil, false, err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	existing, err := r.client.Get(ctx, recordKey, clientv3.WithRev(target.revision))
	if err != nil {
		return empty, nil, false, err
	}
	resourceKey := r.inventoryPrefix(scope) + desired.Address.Key()
	if len(existing.Kvs) == 1 {
		return r.retrySiteConnection(ctx, scope, desired.Address, existing.Kvs[0].Value, digest, target.revision)
	}
	binding, err := r.client.Get(ctx, target.subnetLock, clientv3.WithRev(target.revision), clientv3.WithCountOnly())
	if err != nil {
		return empty, nil, false, err
	}
	if binding.Count != 0 {
		return empty, nil, false, arm.ErrSiteConnectionInUse
	}
	slot, slotGuards, err := r.availableGatewaySlot(ctx, target.revision, r.wireGuard.Slots)
	if err != nil {
		return empty, nil, false, err
	}
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: createSiteConnection, Group: target.group, Actor: actor,
		Status: arm.OperationInProgress, StartedAt: now}
	opKey := r.operationKey(scope, op.ID)
	record := gatewayRecord{
		Scope: scope, Resource: desired.Address, Subnet: desired.Subnet, SubnetLock: target.subnetLock,
		Slot: slot.Name, Hosts: slot.Hosts, OperationID: op.ID, RequestDigest: digest,
		Site: &wireGuardDesired{Peers: desired.Properties.Peers, LocalPrefixes: target.prefixes, CustomerPrefixes: desired.Properties.CustomerPrefixes,
			ProtectedPrefixes: r.wireGuard.ProtectedPrefixes},
	}
	properties, _ := json.Marshal(struct {
		network.SiteConnectionProperties
		ProvisioningState string `json:"provisioningState"`
	}{desired.Properties, "Updating"})
	resource := arm.InventoryResource{Address: desired.Address, APIVersion: network.SiteConnectionAPIVersion, Location: desired.Location,
		Tags: desired.Tags, Properties: properties, ProvisioningState: "Updating", References: []arm.ResourceAddress{target.parent}}
	refGuards, refWrites, err := r.inventoryReferenceChanges(ctx, scope, desired.Address, nil, &resource, target.revision, nil)
	if err != nil {
		return empty, nil, false, err
	}
	guards := append(target.guards, slotGuards...)
	guards = append(guards, refGuards...)
	for _, key := range []string{recordKey, resourceKey, target.subnetLock, opKey} {
		guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
	}
	recordData, _ := json.Marshal(record)
	opData, _ := json.Marshal(op)
	writes := append(refWrites, clientv3.OpPut(recordKey, string(recordData)), clientv3.OpPut(target.subnetLock, recordKey),
		clientv3.OpPut(r.gatewaySlotKey(slot.Name), recordKey), clientv3.OpPut(opKey, string(opData)), inventoryPut(resourceKey, nil, &resource, now),
		r.auditOp(scope, arm.AuditEvent{Time: now, Actor: actor, Action: network.SiteConnectionType + "/write",
			Target: desired.Address.ID(scope), Outcome: "Accepted"}))
	for _, host := range slot.Hosts {
		key := r.gatewayTaskKey(host, slot.Name)
		guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
		writes = append(writes, clientv3.OpPut(key, recordKey))
	}
	committed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err != nil {
		return empty, nil, false, err
	}
	if !committed.Succeeded {
		return empty, nil, false, arm.ErrGatewayExecutionUnavailable
	}
	return resource, &op, true, nil
}

func (r *Region) retrySiteConnection(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress, data []byte,
	digest string, revision int64) (arm.InventoryResource, *arm.Operation, bool, error) {
	var resource arm.InventoryResource
	var saved gatewayRecord
	if err := json.Unmarshal(data, &saved); err != nil || saved.Scope != scope || saved.Resource.Key() != address.Key() || saved.Site == nil {
		return resource, nil, false, errors.New("invalid WireGuard site connection state")
	}
	if saved.DeleteOperation != "" || saved.RequestDigest != digest {
		return resource, nil, false, arm.ErrSiteConnectionInUse
	}
	key := r.inventoryPrefix(scope) + address.Key()
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(key, clientv3.WithRev(revision)),
		clientv3.OpGet(r.operationKey(scope, saved.OperationID), clientv3.WithRev(revision))).Commit()
	if err != nil {
		return resource, nil, false, err
	}
	resources, operations := snapshot.Responses[0].GetResponseRange().Kvs, snapshot.Responses[1].GetResponseRange().Kvs
	if len(resources) != 1 || len(operations) != 1 {
		return resource, nil, false, errors.New("missing WireGuard site connection inventory or operation")
	}
	resource, err = decodeInventoryResource(resources[0].Value, address.Key())
	if err != nil {
		return resource, nil, false, err
	}
	operation, err := decodeOperation(operations[0].Value, saved.OperationID)
	if err != nil {
		return resource, nil, false, err
	}
	if operation.Status != arm.OperationInProgress {
		operation = nil
	}
	return resource, operation, false, nil
}
