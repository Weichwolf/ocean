package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type ipsecConfig struct {
	SharedKeyEnvelopeFile string         `json:"sharedKeyEnvelopeFile"`
	ProtectedPrefixes     []netip.Prefix `json:"protectedPrefixes"`
	Slots                 []ipsecSlot    `json:"slots"`
}

// An IPsec slot is an independently provisioned routing namespace. Restrict
// it to a subscription and an attached subnet to preserve isolation on reuse.
type ipsecSlot struct {
	Name           string       `json:"name"`
	Host           string       `json:"host"`
	TenantID       string       `json:"tenantId"`
	SubscriptionID string       `json:"subscriptionId"`
	PublicIPv4     netip.Addr   `json:"publicIPv4"`
	InsideIPv4     netip.Prefix `json:"insideIPv4"`
}

func (slot ipsecSlot) scope() arm.SubscriptionScope {
	return arm.SubscriptionScope{TenantID: slot.TenantID, SubscriptionID: slot.SubscriptionID}
}

type ipsecControl struct {
	sealer    cipher.AEAD
	protected []netip.Prefix
	slots     []ipsecSlot
	manifest  string
}

func openIPsec(cfg *ipsecConfig, pool []netip.Addr) (*ipsecControl, error) {
	if cfg == nil {
		return nil, nil
	}
	if !filepath.IsAbs(cfg.SharedKeyEnvelopeFile) || len(cfg.Slots) == 0 || len(cfg.Slots) > 64 ||
		len(cfg.ProtectedPrefixes) == 0 || len(cfg.ProtectedPrefixes) > 32 {
		return nil, errors.New("IPsec requires a shared key envelope file, protected IPv4 prefixes and one to 64 slots")
	}
	for i, prefix := range cfg.ProtectedPrefixes {
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || slices.ContainsFunc(cfg.ProtectedPrefixes[:i], prefix.Overlaps) {
			return nil, errors.New("IPsec protected prefixes must be disjoint canonical IPv4 networks")
		}
	}
	slots := slices.Clone(cfg.Slots)
	slices.SortFunc(slots, func(a, b ipsecSlot) int { return strings.Compare(a.Name, b.Name) })
	names, addresses := make(map[string]bool, len(slots)), make(map[netip.Addr]bool, len(slots))
	perHost := make(map[string]int)
	for _, slot := range slots {
		inside := slot.InsideIPv4.Masked()
		peer := network.IPsecPeer{Endpoint: slot.PublicIPv4, Prefixes: []netip.Prefix{inside}}
		if !identifier.MatchString(slot.Name) || names[slot.Name] || !identifier.MatchString(slot.Host) ||
			!identifier.MatchString(slot.TenantID) || !identifier.MatchString(slot.SubscriptionID) ||
			addresses[slot.PublicIPv4] || perHost[slot.Host] >= 8 || !slices.Contains(pool, slot.PublicIPv4) || peer.Validate() != nil ||
			slot.InsideIPv4.Addr() == inside.Addr() || !inside.Contains(slot.InsideIPv4.Addr().Next()) ||
			slices.ContainsFunc(cfg.ProtectedPrefixes, func(prefix netip.Prefix) bool {
				return prefix.Overlaps(inside) || prefix.Contains(slot.PublicIPv4)
			}) {
			return nil, errors.New("invalid or duplicate IPsec slot or target network")
		}
		names[slot.Name], addresses[slot.PublicIPv4] = true, true
		perHost[slot.Host]++
	}
	key, err := readSealingKey(cfg.SharedKeyEnvelopeFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sealer, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	protected := slices.Clone(cfg.ProtectedPrefixes)
	slices.SortFunc(protected, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	manifest, err := json.Marshal(struct {
		KeyDigest string
		Slots     []ipsecSlot
		Protected []netip.Prefix
	}{fmt.Sprintf("%x", sha256.Sum256(key)), slots, protected})
	if err != nil {
		return nil, err
	}
	return &ipsecControl{sealer: sealer, protected: protected, slots: slots, manifest: string(manifest)}, nil
}

func (r *Region) bootstrapIPsec(ctx context.Context) error {
	key := r.root + "/ipsec/config"
	if r.ipsec == nil {
		record, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && record.Count != 0 {
			return errors.New("the regional IPsec configuration is required")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.ipsec.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.ipsec.manifest {
		return errors.New("IPsec configuration differs from the regional record")
	}
	return nil
}
