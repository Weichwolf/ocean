package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// FixedEgress is the forwarding policy for one tenant's isolated gateway
// namespace. The active gateway's routed address is managed independently.
type FixedEgress struct {
	Inside, Outside   string
	Address           netip.Addr
	TenantPrefixes    []netip.Prefix
	ProtectedPrefixes []netip.Prefix
}

func (gateway FixedEgress) Apply(ctx context.Context, namespace string) error {
	if !linkName.MatchString(gateway.Inside) || !linkName.MatchString(gateway.Outside) || gateway.Inside == gateway.Outside ||
		!gateway.Address.Is4() || !gateway.Address.IsGlobalUnicast() {
		return errors.New("invalid fixed egress interfaces or public IPv4 address")
	}
	if len(gateway.TenantPrefixes) == 0 || len(gateway.ProtectedPrefixes) == 0 {
		return errors.New("tenant and protected IPv4 prefixes are required")
	}
	for _, prefixes := range [][]netip.Prefix{gateway.TenantPrefixes, gateway.ProtectedPrefixes} {
		for _, prefix := range prefixes {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Contains(gateway.Address) {
				return errors.New("gateway prefixes must be canonical IPv4 and exclude the public address")
			}
		}
	}
	for _, tenant := range gateway.TenantPrefixes {
		if !slices.ContainsFunc(privateBlocks, func(block netip.Prefix) bool {
			return block.Bits() <= tenant.Bits() && block.Contains(tenant.Addr())
		}) || slices.ContainsFunc(gateway.ProtectedPrefixes, tenant.Overlaps) {
			return errors.New("tenant prefixes must be private and disjoint from protected networks")
		}
	}
	policy := nftPolicy{table: "ocean_fixed_egress"}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.prefixSet("tenant_networks", gateway.TenantPrefixes)
	policy.prefixSet("protected_networks", gateway.ProtectedPrefixes)
	policy.command("add chain inet %s forward { type filter hook forward priority filter; policy drop; }", policy.table)
	policy.command("add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", policy.table)

	inside, outside := strconv.Quote(gateway.Inside), strconv.Quote(gateway.Outside)
	policy.rule("forward", "meta nfproto != ipv4 counter drop")
	policy.rule("forward", "ip saddr @protected_networks counter drop")
	policy.rule("forward", "ip daddr @protected_networks counter drop")
	policy.rule("forward", "ct state invalid counter drop")
	// Only connections whose first packet crossed from an attached subnet
	// receive source NAT. The reverse path requires that conntrack state.
	policy.rule("forward", fmt.Sprintf("iifname %s oifname %s ip saddr @tenant_networks counter accept", inside, outside))
	policy.rule("forward", fmt.Sprintf("iifname %s oifname %s ip daddr @tenant_networks ct state established,related ct status snat counter accept", outside, inside))
	policy.rule("postrouting", fmt.Sprintf("iifname %s oifname %s ip saddr @tenant_networks counter snat ip to %s",
		inside, outside, gateway.Address))
	return applyNftRules(ctx, namespace, policy.script.String())
}
