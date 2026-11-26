package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	createIPsecGateway    = "CreateIPsecGateway"
	deleteIPsecGateway    = "DeleteIPsecGateway"
	createIPsecConnection = "CreateIPsecConnection"
	deleteIPsecConnection = "DeleteIPsecConnection"
)

type vpnGatewayRecord struct {
	Scope       arm.SubscriptionScope `json:"scope"`
	Gateway     arm.ResourceAddress   `json:"gateway"`
	Slot        string                `json:"slot"`
	Host        string                `json:"host"`
	PublicIPv4  netip.Addr            `json:"publicIPv4"`
	InsideIPv4  netip.Prefix          `json:"insideIPv4"`
	VNetRanges  []netip.Prefix        `json:"vnetRanges"`
	SubnetLocks []string              `json:"subnetLocks"`
	Generation  string                `json:"generation"`
	Kind        string                `json:"kind"`
	Connection  *vpnConnectionRecord  `json:"connection,omitempty"`
}

type vpnConnectionRecord struct {
	Resource    arm.ResourceAddress   `json:"resource"`
	Local       arm.ResourceAddress   `json:"local"`
	Deployments []arm.ResourceAddress `json:"deployments"`
	Peer        network.IPsecPeer     `json:"peer"`
	KeyEnvelope []byte                `json:"keyEnvelope"`
}

func (r *Region) vpnKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "ipsec/gateways/" + address.Key()
}

func (r *Region) vpnTaskKey(host, slot string) string {
	return r.root + "/ipsec/hosts/" + host + "/" + slot
}

func (r *Region) vpnSlotKey(slot string) string {
	return r.root + "/ipsec/slots/" + slot
}

func (r *Region) vpnObservationKey(slot string) string {
	return r.root + "/ipsec/observations/" + slot
}

func keyUnchanged(key *mvccpb.KeyValue) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(string(key.Key)), "=", key.ModRevision)
}

func (r *Region) PutVPNLocalGateway(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.VPNLocalGatewayRequest) (arm.VPNChangeResult, error) {
	if r.ipsec == nil {
		return arm.VPNChangeResult{}, arm.ErrGatewayExecutionUnavailable
	}
	if err := desired.Peer.Validate(); err != nil {
		return arm.VPNChangeResult{}, arm.InvalidDeployment{Cause: err}
	}
	properties, _ := json.Marshal(map[string]any{
		"gatewayIpAddress": desired.Peer.Endpoint, "localNetworkAddressSpace": map[string]any{"addressPrefixes": desired.Peer.Prefixes},
		"provisioningState": arm.OperationSucceeded,
	})
	updated, created, err := r.changeInventoryResource(ctx, scope, desired.Address, actor, arm.VPNLocalGatewayType+"/write", "",
		func(previous *arm.InventoryResource, address arm.ResourceAddress, _ int64) (*arm.InventoryResource, []clientv3.Cmp, error) {
			resource := arm.InventoryResource{Address: address, Location: desired.Location, APIVersion: arm.VPNLocalGatewayAPIVersion,
				Tags: desired.Tags, Properties: properties, ProvisioningState: arm.OperationSucceeded}
			if previous != nil && !inventoryEqual(*previous, resource) {
				return nil, nil, arm.InvalidDeployment{Cause: errors.New("updating an existing IPsec local gateway is unsupported")}
			}
			return &resource, nil, nil
		})
	if err != nil {
		return arm.VPNChangeResult{}, err
	}
	return arm.VPNChangeResult{Resource: *updated, Created: created}, nil
}

func (r *Region) PutVPNVirtualGateway(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.VPNVirtualGatewayRequest) (arm.VPNChangeResult, error) {
	var result arm.VPNChangeResult
	if r.ipsec == nil {
		return result, arm.ErrGatewayExecutionUnavailable
	}
	vnet, gatewaySubnetName, ok := arm.SubnetParent(scope, desired.Subnet.ID(scope))
	if !ok || !strings.EqualFold(vnet.Group, desired.Address.Group) || !strings.EqualFold(gatewaySubnetName, "GatewaySubnet") {
		return result, arm.ErrLinkedResourceMissing
	}
	groupName := strings.ToLower(desired.Address.Group)
	groupKey, inventory := r.groupPrefix(scope)+groupName, r.inventoryPrefix(scope)
	resourceKey, desiredKey := inventory+desired.Address.Key(), r.vpnKey(scope, desired.Address)
	for range 8 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(inventory+vnet.Key()),
			clientv3.OpGet(inventory+desired.PublicIP.Key()), clientv3.OpGet(resourceKey), clientv3.OpGet(desiredKey)).Commit()
		if err != nil {
			return result, err
		}
		groupValues, vnetValues := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
		ipValues := read.Responses[2].GetResponseRange().Kvs
		resources, records := read.Responses[3].GetResponseRange().Kvs, read.Responses[4].GetResponseRange().Kvs
		if len(groupValues) != 1 {
			return result, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groupValues[0].Value, groupName)
		if err != nil {
			return result, err
		}
		if group.DeleteOperation != "" {
			return result, arm.ErrGroupDeleting
		}
		if len(vnetValues) != 1 || len(ipValues) != 1 {
			return result, arm.ErrLinkedResourceMissing
		}
		desired.Address.Group = group.Name
		vnetProperties, gatewaySubnet, err := decodeSubnet(vnetValues[0].Value, vnet.Key(), gatewaySubnetName)
		if errors.Is(err, ErrPlacementSubnetUnavailable) {
			return result, arm.ErrLinkedResourceMissing
		}
		if err != nil {
			return result, err
		}
		public, err := ipsecPublicAddress(ipValues[0], desired.PublicIP)
		if err != nil {
			return result, err
		}
		slot, workload, ranges, err := r.ipsecGatewayTarget(scope, public, vnetProperties, gatewaySubnet)
		if err != nil {
			return result, err
		}
		if len(records) != 0 || len(resources) != 0 {
			if len(records) != 1 || len(resources) != 1 {
				return result, errors.New("IPsec gateway reservation has incomplete inventory")
			}
			return r.retryIPsecGateway(ctx, scope, desired, slot, vnet, resources[0], records[0], read.Header.Revision)
		}
		hostGuards, err := r.ipsecHostAvailability(ctx, slot.Host, read.Header.Revision)
		if err != nil {
			return result, err
		}
		resource := ipsecGatewayResource(scope, desired, vnet, "Updating")
		refGuards, refWrites, err := r.inventoryReferenceChanges(ctx, scope, desired.Address, nil, &resource, read.Header.Revision, nil)
		if err != nil {
			return result, err
		}
		op := newIPsecOperation(createIPsecGateway, group.Name, actor)
		record := vpnGatewayRecord{Scope: scope, Gateway: desired.Address, Slot: slot.Name, Host: slot.Host, PublicIPv4: slot.PublicIPv4,
			InsideIPv4: slot.InsideIPv4, VNetRanges: ranges, Generation: op.ID, Kind: op.Kind,
			SubnetLocks: []string{r.subnetNetworkPlacements(scope, vnet, gatewaySubnet.Name) + "_ipsec",
				r.subnetNetworkPlacements(scope, vnet, workload) + "_ipsec"}}
		taskKey, slotKey := r.vpnTaskKey(slot.Host, slot.Name), r.vpnSlotKey(slot.Name)
		guards := append(hostGuards, refGuards...)
		guards = append(guards, keyUnchanged(groupValues[0]), keyUnchanged(vnetValues[0]), keyUnchanged(ipValues[0]))
		opKey := r.operationKey(scope, op.ID)
		for _, key := range slices.Concat([]string{resourceKey, desiredKey, opKey, taskKey, slotKey}, record.SubnetLocks) {
			guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
		}
		writes := append(refWrites, putIPsecRecord(desiredKey, record), putIPsecOperation(opKey, op),
			clientv3.OpPut(taskKey, desiredKey), clientv3.OpPut(slotKey, desiredKey),
			inventoryPut(resourceKey, nil, &resource, op.StartedAt), r.ipsecAudit(scope, op, desired.Address, "Accepted"))
		for _, key := range record.SubnetLocks {
			writes = append(writes, clientv3.OpPut(key, desiredKey))
		}
		committed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
		if err != nil {
			return result, err
		}
		if committed.Succeeded {
			return arm.VPNChangeResult{Resource: resource, Operation: &op, Created: true}, nil
		}
	}
	return result, arm.ErrGatewayExecutionUnavailable
}

func ipsecPublicAddress(value *mvccpb.KeyValue, address arm.ResourceAddress) (netip.Addr, error) {
	resource, err := decodeInventoryResource(value.Value, address.Key())
	if err != nil {
		return netip.Addr{}, err
	}
	var public network.PublicIPAddressProperties
	if err := json.Unmarshal(resource.Properties, &public); err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(public.Address)
	if err != nil || !ip.Is4() || resource.SKU.Name != "Standard" || public.ProvisioningState != arm.OperationSucceeded ||
		public.AllocationMethod != "Static" || public.IPVersion != "IPv4" {
		return netip.Addr{}, arm.InvalidDeployment{Cause: errors.New("IPsec requires an allocated Standard static public IPv4 address")}
	}
	return ip, nil
}

func (r *Region) ipsecGatewayTarget(scope arm.SubscriptionScope, public netip.Addr, vnet network.VNetProperties,
	gateway network.Subnet) (ipsecSlot, string, []netip.Prefix, error) {
	index := slices.IndexFunc(r.ipsec.slots, func(slot ipsecSlot) bool { return slot.PublicIPv4 == public && slot.scope() == scope })
	if index < 0 {
		return ipsecSlot{}, "", nil, arm.ErrGatewayExecutionUnavailable
	}
	slot := r.ipsec.slots[index]
	if len(vnet.Subnets) != 2 || gateway.Properties.NetworkSecurityGroup != nil || gateway.Properties.NATGateway != nil ||
		len(gateway.Properties.Delegations) != 0 {
		return ipsecSlot{}, "", nil, arm.InvalidDeployment{Cause: errors.New("IPsec requires a dedicated GatewaySubnet and one attached workload subnet")}
	}
	ranges := make([]netip.Prefix, 0, len(vnet.AddressSpace.Prefixes))
	for _, cidr := range vnet.AddressSpace.Prefixes {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Contains(public) || slices.ContainsFunc(r.ipsec.protected, prefix.Overlaps) {
			return ipsecSlot{}, "", nil, arm.InvalidDeployment{Cause: errors.New("the virtual network overlaps a protected prefix or endpoint")}
		}
		ranges = append(ranges, prefix)
	}
	for _, subnet := range vnet.Subnets {
		if strings.EqualFold(subnet.Name, gateway.Name) {
			continue
		}
		prefixes, err := subnet.Properties.Prefixes()
		if err == nil && len(prefixes) == 1 && prefixes[0] == slot.InsideIPv4.Masked() {
			return slot, subnet.Name, ranges, nil
		}
	}
	return ipsecSlot{}, "", nil, arm.InvalidDeployment{Cause: errors.New("the workload subnet does not match the attached IPsec slot")}
}

func (r *Region) ipsecHostAvailability(ctx context.Context, host string, revision int64) ([]clientv3.Cmp, error) {
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host), clientv3.WithRev(revision)),
		clientv3.OpGet(r.hostKey("live", host), clientv3.WithRev(revision))).Commit()
	if err != nil {
		return nil, err
	}
	registered, live := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
	var identity enrollment.Host
	if len(registered) != 1 || len(live) != 1 || json.Unmarshal(registered[0].Value, &identity) != nil ||
		len(identity.Certificate) == 0 || r.authorizeHostRole(host, identity.Certificate, "gateway", read) != nil {
		return nil, arm.ErrGatewayExecutionUnavailable
	}
	return []clientv3.Cmp{keyUnchanged(registered[0]), keyUnchanged(live[0])}, nil
}

func ipsecGatewayResource(scope arm.SubscriptionScope, desired arm.VPNVirtualGatewayRequest, vnet arm.ResourceAddress, state string) arm.InventoryResource {
	properties, _ := json.Marshal(map[string]any{
		"gatewayType": "Vpn", "vpnType": "RouteBased", "activeActive": false, "enableBgp": false, "provisioningState": state,
		"sku": arm.ResourceSKU{Name: "VpnGw1", Tier: "VpnGw1"},
		"ipConfigurations": []any{map[string]any{"name": desired.IPConfigName, "properties": map[string]any{
			"privateIPAllocationMethod": "Dynamic", "publicIPAddress": network.ResourceReference{ID: desired.PublicIP.ID(scope)},
			"subnet": network.ResourceReference{ID: desired.Subnet.ID(scope)},
		}}},
	})
	return arm.InventoryResource{Address: desired.Address, Location: desired.Location, APIVersion: arm.VPNGatewayAPIVersion,
		Tags: desired.Tags, Properties: properties, ProvisioningState: state, References: []arm.ResourceAddress{desired.PublicIP, vnet}}
}

func (r *Region) retryIPsecGateway(ctx context.Context, scope arm.SubscriptionScope, desired arm.VPNVirtualGatewayRequest,
	slot ipsecSlot, vnet arm.ResourceAddress, resourceValue, recordValue *mvccpb.KeyValue, revision int64) (arm.VPNChangeResult, error) {
	var record vpnGatewayRecord
	resource, err := decodeInventoryResource(resourceValue.Value, desired.Address.Key())
	if err != nil {
		return arm.VPNChangeResult{}, err
	}
	if json.Unmarshal(recordValue.Value, &record) != nil || record.Scope != scope || record.Gateway != resource.Address || record.Slot != slot.Name {
		return arm.VPNChangeResult{}, errors.New("invalid IPsec gateway reservation")
	}
	expected := ipsecGatewayResource(scope, desired, vnet, resource.ProvisioningState)
	if record.Kind == deleteIPsecGateway || !maps.Equal(expected.Tags, resource.Tags) ||
		!strings.EqualFold(string(expected.Properties), string(resource.Properties)) || !slices.EqualFunc(expected.References, resource.References,
		func(a, b arm.ResourceAddress) bool { return a.Key() == b.Key() }) {
		return arm.VPNChangeResult{}, arm.InvalidDeployment{Cause: errors.New("the gateway is being deleted or already has another configuration")}
	}
	result := arm.VPNChangeResult{Resource: resource}
	if resource.ProvisioningState != arm.OperationSucceeded {
		result.Operation, err = r.ipsecOperationAt(ctx, scope, record.Generation, revision)
	}
	return result, err
}

func newIPsecOperation(kind, group, actor string) arm.Operation {
	return arm.Operation{ID: operationID(), Kind: kind, Group: group, Actor: actor,
		Status: arm.OperationInProgress, StartedAt: time.Now().UTC()}
}

func putIPsecRecord(key string, record vpnGatewayRecord) clientv3.Op {
	data, _ := json.Marshal(record)
	return clientv3.OpPut(key, string(data))
}

func putIPsecOperation(key string, op arm.Operation) clientv3.Op {
	data, _ := json.Marshal(op)
	return clientv3.OpPut(key, string(data))
}

func (r *Region) ipsecOperationAt(ctx context.Context, scope arm.SubscriptionScope, id string, revision int64) (*arm.Operation, error) {
	entries, err := r.client.Get(ctx, r.operationKey(scope, id), clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	if len(entries.Kvs) != 1 {
		return nil, errors.New("IPsec operation is missing")
	}
	return decodeOperation(entries.Kvs[0].Value, id)
}

func (r *Region) ipsecAudit(scope arm.SubscriptionScope, op arm.Operation, address arm.ResourceAddress, outcome string) clientv3.Op {
	action := arm.VPNConnectionType
	if op.Kind == createIPsecGateway || op.Kind == deleteIPsecGateway {
		action = arm.VPNVirtualGatewayType
	}
	verb := "/write"
	if op.Kind == deleteIPsecConnection || op.Kind == deleteIPsecGateway {
		verb = "/delete"
	}
	return r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: op.Actor, Action: action + verb, Target: address.ID(scope), Outcome: outcome})
}
