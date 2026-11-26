package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Weichwolf/ocean/internal/rack"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type rackFeed struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

type rackAssignment struct {
	Asset        rack.Asset   `json:"asset"`
	Address      netip.Prefix `json:"address"`
	DNSName      string       `json:"dnsName"`
	PolicyDigest string       `json:"policyDigest"`
	DNSPublished bool         `json:"dnsPublished"`
}

func (r *Region) rackKey(kind, id string) string { return r.root + "/rack/" + kind + "/" + id }

func (r *Region) acceptRackFeed(ctx context.Context, feed rack.Inventory) (string, error) {
	record, _ := json.Marshal(rackFeed{Revision: feed.Revision, Digest: feed.Digest})
	key := r.rackKey("inventory", "feed")
	for range 8 {
		current, err := r.client.Get(ctx, key)
		if err != nil {
			return "", err
		}
		var revision int64
		if len(current.Kvs) != 0 {
			value := current.Kvs[0]
			if string(value.Value) == string(record) {
				return string(record), nil
			}
			var old rackFeed
			if err := json.Unmarshal(value.Value, &old); err != nil || old.Revision == 0 || len(old.Digest) != sha256.Size*2 {
				return "", errors.New("invalid regional rack inventory checkpoint")
			}
			if feed.Revision <= old.Revision {
				return "", errors.New("signed rack inventory is older than or disagrees with the regional revision")
			}
			revision = value.ModRevision
		}
		res, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision)).
			Then(clientv3.OpPut(key, string(record))).Commit()
		if err != nil {
			return "", err
		}
		if res.Succeeded {
			return string(record), nil
		}
	}
	return "", errors.New("regional rack inventory changed concurrently")
}

func rackPolicyDigest(policy rackPolicy) string {
	// Installation-only inputs and address range expansion preserve assignments.
	policy.BMCCredential = ""
	policy.First, policy.Last = netip.Addr{}, netip.Addr{}
	policy.Resolvers = nil
	data, _ := json.Marshal(policy)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func decodeRackAssignment(data []byte, asset rack.Asset, policy rackPolicy, digest string) (rackAssignment, error) {
	var assignment rackAssignment
	if err := json.Unmarshal(data, &assignment); err != nil {
		return rackAssignment{}, fmt.Errorf("decode rack assignment: %w", err)
	}
	if assignment.Asset != asset || assignment.PolicyDigest != digest || assignment.DNSName != asset.HostID+"."+policy.DNSZone ||
		assignment.Address.Bits() != policy.Network.Bits() || !policy.containsHostAddress(assignment.Address.Addr()) ||
		assignment.Address.Addr() == policy.Gateway {
		return rackAssignment{}, errors.New("existing assignment differs from the approved hardware or rack policy")
	}
	return assignment, nil
}

func (r *Region) loadRackAssignment(ctx context.Context, asset rack.Asset, policy rackPolicy) (rackAssignment, int64, error) {
	result, err := r.client.Get(ctx, r.rackKey("hosts", asset.HostID))
	if err != nil || len(result.Kvs) == 0 {
		return rackAssignment{}, 0, err
	}
	value := result.Kvs[0]
	assignment, err := decodeRackAssignment(value.Value, asset, policy, rackPolicyDigest(policy))
	return assignment, value.ModRevision, err
}

// reserveRackHost runs after the signed hardware binding and its Ironic node
// have been verified. The shared indexes also protect statically enrolled hosts.
func (r *Region) reserveRackHost(ctx context.Context, feed string, asset rack.Asset, policy rackPolicy) (rackAssignment, int64, error) {
	name := asset.HostID + "." + policy.DNSZone
	if len(name) > 253 {
		return rackAssignment{}, 0, errors.New("assigned management DNS name is too long")
	}
	host := r.rackKey("hosts", asset.HostID)
	mac := r.hostKey("mac", asset.BootMAC)
	dns := r.rackKey("dns", name)
	node := r.rackKey("ironic", asset.NodeID)
	system := r.rackKey("systems", asset.UUID)
	cell := r.root + "/cells/" + policy.Cell + "/metadata"
	approval := r.hostKey("inventory", asset.HostID)
	feedKey := r.rackKey("inventory", "feed")
	compare := []clientv3.Cmp{
		clientv3.Compare(clientv3.Version(host), "=", 0), clientv3.Compare(clientv3.Version(mac), "=", 0),
		clientv3.Compare(clientv3.Version(dns), "=", 0), clientv3.Compare(clientv3.Version(node), "=", 0),
		clientv3.Compare(clientv3.Version(system), "=", 0), clientv3.Compare(clientv3.Version(approval), "=", 0),
		clientv3.Compare(clientv3.Version(cell), ">", 0), clientv3.Compare(clientv3.Value(feedKey), "=", feed),
	}
	changes := []clientv3.Op{
		clientv3.OpPut(mac, asset.HostID), clientv3.OpPut(dns, asset.HostID),
		clientv3.OpPut(node, asset.HostID), clientv3.OpPut(system, asset.HostID),
	}
	addressPrefix := r.hostKey("address", "")
	addresses, err := r.client.Get(ctx, addressPrefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return rackAssignment{}, 0, err
	}
	used := make(map[string]bool, len(addresses.Kvs))
	for _, address := range addresses.Kvs {
		used[strings.TrimPrefix(string(address.Key), addressPrefix)] = true
	}
	digest := rackPolicyDigest(policy)
	for address := policy.First; address.Compare(policy.Last) <= 0; address = address.Next() {
		if used[address.String()] {
			continue
		}
		key := r.hostKey("address", address.String())
		assignment := rackAssignment{Asset: asset, Address: netip.PrefixFrom(address, policy.Network.Bits()), DNSName: name, PolicyDigest: digest}
		data, _ := json.Marshal(assignment)
		res, err := r.client.Txn(ctx).If(append(compare, clientv3.Compare(clientv3.Version(key), "=", 0))...).
			Then(append(changes, clientv3.OpPut(host, string(data)), clientv3.OpPut(key, asset.HostID))...).
			Else(clientv3.OpGet(host), clientv3.OpGet(key)).Commit()
		if err != nil {
			return rackAssignment{}, 0, err
		}
		if res.Succeeded {
			return assignment, res.Header.Revision, nil
		}
		if hosts := res.Responses[0].GetResponseRange().Kvs; len(hosts) != 0 {
			assignment, err := decodeRackAssignment(hosts[0].Value, asset, policy, digest)
			return assignment, hosts[0].ModRevision, err
		}
		if len(res.Responses[1].GetResponseRange().Kvs) == 0 {
			return rackAssignment{}, 0, errors.New("rack assignment conflicts with regional inventory, cell or feed")
		}
	}
	if assignment, revision, err := r.loadRackAssignment(ctx, asset, policy); err != nil || revision != 0 {
		return assignment, revision, err
	}
	return rackAssignment{}, 0, errors.New("rack management IPv4 pool is exhausted")
}

func (r *Region) publishRackDNS(ctx context.Context, asset rack.Asset, policy rackPolicy, assignment rackAssignment, revision int64) error {
	if err := r.rack.dns.Publish(ctx, policy.DNSZone, asset.HostID, assignment.Address.Addr()); err != nil {
		return err
	}
	assignment.DNSPublished = true
	data, _ := json.Marshal(assignment)
	key := r.rackKey("hosts", asset.HostID)
	_, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision)).
		Then(clientv3.OpPut(key, string(data))).Commit()
	return err
}
