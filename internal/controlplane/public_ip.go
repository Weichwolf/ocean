package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type publicIPPool struct {
	Addresses   []netip.Addr          `json:"addresses"`
	Allocations map[string]netip.Addr `json:"allocations"`
}

func configuredPublicIPs(addresses []netip.Addr) ([]netip.Addr, error) {
	if len(addresses) > 256 {
		return nil, errors.New("region.publicIPv4Addresses accepts at most 256 addresses")
	}
	items := slices.Clone(addresses)
	slices.SortFunc(items, netip.Addr.Compare)
	for index, address := range items {
		if !address.Is4() || !address.IsGlobalUnicast() || index > 0 && items[index-1] == address {
			return nil, errors.New("region.publicIPv4Addresses must contain distinct unicast IPv4 addresses")
		}
	}
	return items, nil
}

func (r *Region) publicIPPoolKey() string {
	return r.root + "/network/public-ipv4-pool"
}

func (r *Region) bootstrapPublicIPPool(ctx context.Context) error {
	key := r.publicIPPoolKey()
	if len(r.publicIPv4) == 0 {
		record, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && record.Count != 0 {
			return errors.New("region.publicIPv4Addresses must match the existing regional pool")
		}
		return err
	}
	data, _ := json.Marshal(publicIPPool{Addresses: r.publicIPv4, Allocations: map[string]netip.Addr{}})
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, string(data))).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	_, err = r.decodePublicIPPool(result.Responses[0].GetResponseRange().Kvs[0].Value)
	return err
}

func (r *Region) decodePublicIPPool(data []byte) (publicIPPool, error) {
	var pool publicIPPool
	if err := json.Unmarshal(data, &pool); err != nil {
		return pool, err
	}
	if !slices.Equal(pool.Addresses, r.publicIPv4) || pool.Allocations == nil {
		return pool, errors.New("the durable public IPv4 pool differs from the regional configuration")
	}
	allocated := make(map[netip.Addr]bool)
	for owner, address := range pool.Allocations {
		if !strings.HasPrefix(owner, r.root+"/") || !slices.Contains(pool.Addresses, address) || allocated[address] {
			return pool, errors.New("the durable public IPv4 pool contains an invalid allocation")
		}
		allocated[address] = true
	}
	return pool, nil
}

func (r *Region) readPublicIPPool(ctx context.Context, revision int64) (publicIPPool, int64, error) {
	if len(r.publicIPv4) == 0 {
		return publicIPPool{}, 0, arm.ErrPublicIPPoolDisabled
	}
	record, err := r.client.Get(ctx, r.publicIPPoolKey(), clientv3.WithRev(revision))
	if err != nil {
		return publicIPPool{}, 0, err
	}
	if len(record.Kvs) != 1 {
		return publicIPPool{}, 0, errors.New("regional public IPv4 pool is missing")
	}
	item := record.Kvs[0]
	pool, err := r.decodePublicIPPool(item.Value)
	return pool, item.ModRevision, err
}

func isPublicIPAddress(address arm.ResourceAddress) bool {
	separator := strings.LastIndexByte(address.Path, '/')
	return separator > 0 && strings.EqualFold(address.Path[:separator], network.PublicIPType)
}

func (r *Region) publicIPChange(ctx context.Context, owner string, address arm.ResourceAddress, previous, next *arm.InventoryResource, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	if !isPublicIPAddress(address) || (previous == nil) == (next == nil) {
		return nil, nil, nil
	}
	pool, poolRevision, err := r.readPublicIPPool(ctx, revision)
	if err != nil {
		return nil, nil, err
	}
	var properties network.PublicIPAddressProperties
	if next == nil {
		if err := json.Unmarshal(previous.Properties, &properties); err != nil {
			return nil, nil, err
		}
		if assigned, exists := pool.Allocations[owner]; !exists || assigned.String() != properties.Address {
			return nil, nil, errors.New("public IPv4 reservation does not match its resource")
		}
		delete(pool.Allocations, owner)
	} else {
		if err := assignPublicIPv4(pool, owner, next); err != nil {
			return nil, nil, err
		}
	}
	comparison, mutation := r.publicIPPoolUpdate(pool, poolRevision)
	return []clientv3.Cmp{comparison}, []clientv3.Op{mutation}, nil
}

func assignPublicIPv4(pool publicIPPool, owner string, resource *arm.InventoryResource) error {
	var properties network.PublicIPAddressProperties
	if err := json.Unmarshal(resource.Properties, &properties); err != nil {
		return err
	}
	assigned, err := takePublicIPv4(pool, owner)
	if err != nil {
		return err
	}
	properties.Address = assigned.String()
	resource.Properties, _ = json.Marshal(properties)
	return nil
}

func takePublicIPv4(pool publicIPPool, owner string) (netip.Addr, error) {
	if _, exists := pool.Allocations[owner]; exists {
		return netip.Addr{}, errors.New("public IPv4 reservation already exists without a resource")
	}
	used := make(map[netip.Addr]bool, len(pool.Allocations))
	for _, address := range pool.Allocations {
		used[address] = true
	}
	index := slices.IndexFunc(pool.Addresses, func(address netip.Addr) bool { return !used[address] })
	if index < 0 {
		return netip.Addr{}, arm.ErrPublicIPPoolExhausted
	}
	assigned := pool.Addresses[index]
	pool.Allocations[owner] = assigned
	return assigned, nil
}

func (r *Region) releaseGroupPublicIPs(ctx context.Context, scope arm.SubscriptionScope, group string) ([]clientv3.Cmp, []clientv3.Op, error) {
	if len(r.publicIPv4) == 0 {
		// A pool enabled during a rolling deployment cannot be bypassed by a
		// replica whose local configuration still has the feature disabled.
		return []clientv3.Cmp{clientv3.Compare(clientv3.Version(r.publicIPPoolKey()), "=", 0)}, nil, nil
	}
	pool, revision, err := r.readPublicIPPool(ctx, 0)
	if err != nil {
		return nil, nil, err
	}
	count := len(pool.Allocations)
	prefix := r.groupInventoryPrefix(scope, group)
	for owner := range pool.Allocations {
		if strings.HasPrefix(owner, prefix) {
			delete(pool.Allocations, owner)
		}
	}
	if len(pool.Allocations) == count {
		return nil, nil, nil
	}
	comparison, mutation := r.publicIPPoolUpdate(pool, revision)
	return []clientv3.Cmp{comparison}, []clientv3.Op{mutation}, nil
}

func (r *Region) publicIPPoolUpdate(pool publicIPPool, revision int64) (clientv3.Cmp, clientv3.Op) {
	key := r.publicIPPoolKey()
	data, _ := json.Marshal(pool)
	return clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.OpPut(key, string(data))
}
