package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const securityGroupType = "Microsoft.Network/networkSecurityGroups"

var (
	ErrPlacementSubnetUnavailable = errors.New("the requested subnet is unavailable in the subscription")
	ErrSubnetAddressExhausted     = errors.New("the subnet has no available private IPv4 address")
)

func (r *Region) groupNetworkPlacements(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "network-placements/" + strings.ToLower(group) + "/"
}

func (r *Region) subnetNetworkPlacements(scope arm.SubscriptionScope, parent arm.ResourceAddress, subnet string) string {
	return r.vnetNetworkPlacements(scope, parent) + strings.ToLower(subnet) + "/"
}

func (r *Region) vnetNetworkPlacements(scope arm.SubscriptionScope, parent arm.ResourceAddress) string {
	return r.groupNetworkPlacements(scope, parent.Group) + strings.ToLower(parent.Path+"/subnets/")
}

type subnetAllocation struct {
	address         netip.Addr
	key             string
	groupGeneration int64
	guards          []clientv3.Cmp
}

func (r *Region) allocateSubnet(ctx context.Context, scope arm.SubscriptionScope, id string) (subnetAllocation, error) {
	parent, name, ok := arm.SubnetParent(scope, id)
	if !ok {
		return subnetAllocation{}, ErrPlacementSubnetUnavailable
	}
	groupKey := r.groupPrefix(scope) + strings.ToLower(parent.Group)
	vnetKey := r.inventoryPrefix(scope) + parent.Key()
	prefix := r.subnetNetworkPlacements(scope, parent, name)
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(vnetKey),
		clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())).Commit()
	if err != nil {
		return subnetAllocation{}, err
	}
	groups, networks := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
	if len(groups) != 1 || len(networks) != 1 {
		return subnetAllocation{}, ErrPlacementSubnetUnavailable
	}
	group, err := decodeGroup(groups[0].Value, strings.ToLower(parent.Group))
	if err != nil {
		return subnetAllocation{}, err
	}
	if group.DeleteOperation != "" {
		return subnetAllocation{}, ErrPlacementSubnetUnavailable
	}
	_, subnet, err := decodeSubnet(networks[0].Value, parent.Key(), name)
	if err != nil {
		return subnetAllocation{}, err
	}
	ranges, err := subnet.Properties.Prefixes()
	if err != nil {
		return subnetAllocation{}, err
	}
	used := make(map[string]bool)
	for _, item := range read.Responses[2].GetResponseRange().Kvs {
		used[string(item.Key)] = true
	}
	for _, cidr := range ranges {
		for address := network.FirstUsableSubnetAddress(cidr); network.IsUsableSubnetAddress(cidr, address); address = address.Next() {
			key := prefix + address.String()
			if used[key] {
				continue
			}
			return subnetAllocation{address: address, key: key, groupGeneration: groups[0].CreateRevision, guards: []clientv3.Cmp{
				clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
				clientv3.Compare(clientv3.ModRevision(vnetKey), "=", networks[0].ModRevision),
				clientv3.Compare(clientv3.Version(key), "=", 0),
			}}, nil
		}
	}
	return subnetAllocation{}, ErrSubnetAddressExhausted
}

func decodeSubnet(data []byte, key, name string) (network.VNetProperties, network.Subnet, error) {
	var vnet network.VNetProperties
	resource, err := decodeInventoryResource(data, key)
	if err != nil {
		return vnet, network.Subnet{}, err
	}
	if err := json.Unmarshal(resource.Properties, &vnet); err != nil {
		return vnet, network.Subnet{}, err
	}
	index := vnet.SubnetIndex(name)
	if index < 0 {
		return vnet, network.Subnet{}, ErrPlacementSubnetUnavailable
	}
	return vnet, vnet.Subnets[index], nil
}

func (r *Region) assignedNetworkPolicy(ctx context.Context, scope arm.SubscriptionScope, assignment enrollment.Assignment, revision int64) (*network.SubnetPolicy, error) {
	parent, name, ok := arm.SubnetParent(scope, assignment.SubnetID)
	address := assignment.PrivateIPv4
	if !ok || !address.Is4() {
		return nil, ErrPlacementSubnetUnavailable
	}
	key := r.inventoryPrefix(scope) + parent.Key()
	owner := r.subnetNetworkPlacements(scope, parent, name) + address.String()
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(key, clientv3.WithRev(revision)), clientv3.OpGet(owner, clientv3.WithRev(revision))).Commit()
	if err != nil {
		return nil, err
	}
	vnets, leases := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
	if len(vnets) != 1 || len(leases) != 1 || string(leases[0].Value) != assignment.Generation {
		return nil, ErrPlacementSubnetUnavailable
	}
	vnet, subnet, err := decodeSubnet(vnets[0].Value, parent.Key(), name)
	if err != nil {
		return nil, err
	}
	ranges, err := subnet.Properties.Prefixes()
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(ranges, func(prefix netip.Prefix) bool {
		return network.IsUsableSubnetAddress(prefix, address)
	})
	if index < 0 {
		return nil, ErrPlacementSubnetUnavailable
	}
	canonical, _, ok := arm.SubnetParent(scope, subnet.ID)
	if !ok || canonical.Key() != parent.Key() {
		return nil, ErrPlacementSubnetUnavailable
	}
	policy := &network.SubnetPolicy{Revision: revision, VNetID: canonical.ID(scope), Prefixes: vnet.AddressSpace.Prefixes,
		Address: netip.PrefixFrom(address, ranges[index].Bits()), Gateway: ranges[index].Addr().Next(),
		SecurityRules: []network.SecurityRule{}}
	if group := subnet.Properties.NetworkSecurityGroup; group != nil {
		var properties network.SecurityGroupProperties
		if err := r.networkPropertiesAt(ctx, scope, parent.Group, group.ID, securityGroupType, revision, &properties); err != nil {
			return nil, err
		}
		policy.SecurityRules = properties.SecurityRules
	}
	if gateway := subnet.Properties.NATGateway; gateway != nil {
		var properties network.NATGatewayProperties
		if err := r.networkPropertiesAt(ctx, scope, parent.Group, gateway.ID, network.NATGatewayType, revision, &properties); err != nil {
			return nil, err
		}
		if len(properties.PublicIPAddresses) != 1 {
			return nil, ErrPlacementSubnetUnavailable
		}
		var publicIP network.PublicIPAddressProperties
		if err := r.networkPropertiesAt(ctx, scope, parent.Group, properties.PublicIPAddresses[0].ID,
			network.PublicIPType, revision, &publicIP); err != nil {
			return nil, err
		}
		policy.NATGatewayID = gateway.ID
		policy.PublicIPv4, _ = netip.ParseAddr(publicIP.Address)
	}
	if !policy.ValidFor(address) {
		return nil, ErrPlacementSubnetUnavailable
	}
	return policy, nil
}

func (r *Region) networkPropertiesAt(ctx context.Context, scope arm.SubscriptionScope, group, id, kind string, revision int64, target any) error {
	address, ok := arm.NetworkResourceAddress(scope, id, kind)
	if !ok || !strings.EqualFold(group, address.Group) {
		return ErrPlacementSubnetUnavailable
	}
	read, err := r.client.Get(ctx, r.inventoryPrefix(scope)+address.Key(), clientv3.WithRev(revision))
	if err != nil {
		return err
	}
	if len(read.Kvs) != 1 {
		return ErrPlacementSubnetUnavailable
	}
	resource, err := decodeInventoryResource(read.Kvs[0].Value, address.Key())
	if err != nil {
		return err
	}
	return json.Unmarshal(resource.Properties, target)
}

func (r *Region) networkPlacementGuards(ctx context.Context, scope arm.SubscriptionScope, previous, next *arm.InventoryResource,
	revision int64) ([]clientv3.Cmp, error) {
	if previous == nil || strings.Count(previous.Address.Path, "/") != 2 ||
		!strings.HasPrefix(strings.ToLower(previous.Address.Path), "microsoft.network/virtualnetworks/") {
		return nil, nil
	}
	var prefixes []string
	if next == nil {
		prefixes = []string{r.vnetNetworkPlacements(scope, previous.Address)}
	} else {
		var prior, updated network.VNetProperties
		if err := json.Unmarshal(previous.Properties, &prior); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(next.Properties, &updated); err != nil {
			return nil, err
		}
		for _, child := range prior.Subnets {
			index := updated.SubnetIndex(child.Name)
			if index < 0 || !sameSubnetPrefixes(child.Properties, updated.Subnets[index].Properties) {
				prefixes = append(prefixes, r.subnetNetworkPlacements(scope, previous.Address, child.Name))
			}
		}
	}
	// Large replacements use one conservative comparison to stay within the
	// regional transaction budget. Ordinary subnet edits check only their keys.
	if len(prefixes) > 32 {
		prefixes = []string{r.vnetNetworkPlacements(scope, previous.Address)}
	}
	if len(prefixes) == 0 {
		return nil, nil
	}
	reads := make([]clientv3.Op, 0, len(prefixes))
	guards := make([]clientv3.Cmp, 0, len(prefixes))
	for _, prefix := range prefixes {
		reads = append(reads, clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly(), clientv3.WithRev(revision)))
		guards = append(guards, clientv3.Compare(clientv3.Version(prefix), "=", 0).WithPrefix())
	}
	read, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return nil, err
	}
	for _, response := range read.Responses {
		if len(response.GetResponseRange().Kvs) != 0 {
			return nil, arm.ErrSubnetInUse
		}
	}
	return guards, nil
}

func sameSubnetPrefixes(previous, next network.SubnetProperties) bool {
	a, first := previous.Prefixes()
	b, second := next.Prefixes()
	if first != nil || second != nil || len(a) != len(b) {
		return false
	}
	for _, prefix := range a {
		if !slices.Contains(b, prefix) {
			return false
		}
	}
	return true
}
