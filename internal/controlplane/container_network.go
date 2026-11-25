package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Phase one uses one routed workload fabric per region. Reserve VNet prefixes
// with each live container so a second tenant cannot advertise the same space.
type containerNetworkClaim struct {
	Network  string         `json:"network"`
	Prefixes []netip.Prefix `json:"prefixes"`
}

func (r *Region) containerNetworkClaims(ctx context.Context) (map[string]containerNetworkClaim, clientv3.Cmp, string, error) {
	key := r.root + "/workloads/private-address-spaces"
	current, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, clientv3.Cmp{}, "", err
	}
	claims := make(map[string]containerNetworkClaim)
	var revision int64
	if len(current.Kvs) != 0 {
		item := current.Kvs[0]
		revision = item.ModRevision
		if json.Unmarshal(item.Value, &claims) != nil || claims == nil {
			return nil, clientv3.Cmp{}, "", errors.New("invalid recorded container network claims")
		}
	}
	return claims, clientv3.Compare(clientv3.ModRevision(key), "=", revision), key, nil
}

func (r *Region) claimContainerNetwork(ctx context.Context, scope arm.SubscriptionScope, owner, subnet, service string) ([]clientv3.Cmp, []clientv3.Op, error) {
	parent, name, ok := arm.SubnetParent(scope, subnet)
	if !ok {
		return nil, nil, ErrPlacementSubnetUnavailable
	}
	networkKey := r.inventoryPrefix(scope) + parent.Key()
	current, err := r.client.Get(ctx, networkKey)
	if err != nil {
		return nil, nil, err
	}
	if len(current.Kvs) != 1 {
		return nil, nil, ErrPlacementSubnetUnavailable
	}
	item := current.Kvs[0]
	resource, err := decodeInventoryResource(item.Value, parent.Key())
	if err != nil {
		return nil, nil, err
	}
	var vnet network.VNetProperties
	if err := json.Unmarshal(resource.Properties, &vnet); err != nil {
		return nil, nil, err
	}
	index := vnet.SubnetIndex(name)
	if index < 0 || service != "" && !vnet.Subnets[index].Properties.HasDelegation(service) ||
		service == "" && len(vnet.Subnets[index].Properties.Delegations) != 0 {
		return nil, nil, arm.ErrContainerDelegationRequired
	}
	claims, guard, key, err := r.containerNetworkClaims(ctx)
	if err != nil {
		return nil, nil, err
	}
	if _, exists := claims[owner]; exists {
		return nil, nil, errors.New("a network claim already exists without the workload")
	}
	wanted := containerNetworkClaim{Network: networkKey}
	for _, value := range vnet.AddressSpace.Prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, err
		}
		for _, existing := range claims {
			if existing.Network == networkKey {
				continue
			}
			for _, other := range existing.Prefixes {
				if prefix.Overlaps(other) {
					return nil, nil, arm.ErrContainerNetworkConflict
				}
			}
		}
		wanted.Prefixes = append(wanted.Prefixes, prefix)
	}
	claims[owner] = wanted
	return []clientv3.Cmp{guard, clientv3.Compare(clientv3.ModRevision(networkKey), "=", item.ModRevision)}, []clientv3.Op{putJSON(key, claims)}, nil
}

func (r *Region) releaseContainerNetwork(ctx context.Context, owner string) (clientv3.Cmp, clientv3.Op, error) {
	claims, guard, key, err := r.containerNetworkClaims(ctx)
	if err != nil {
		return clientv3.Cmp{}, clientv3.Op{}, err
	}
	if _, exists := claims[owner]; !exists {
		return clientv3.Cmp{}, clientv3.Op{}, errors.New("the deleted workload has no network claim")
	}
	delete(claims, owner)
	return guard, putJSON(key, claims), nil
}
