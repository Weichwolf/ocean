package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// FixedEgress is the forwarding policy for one tenant's isolated gateway
// namespace. The active gateway's routed address is managed independently.
type FixedEgress struct {
	Inside            string         `json:"inside"`
	Outside           string         `json:"outside"`
	Address           netip.Addr     `json:"address"`
	TenantPrefixes    []netip.Prefix `json:"tenantPrefixes"`
	ProtectedPrefixes []netip.Prefix `json:"protectedPrefixes"`
	GateOnActivation  bool           `json:"gateOnActivation"`
}

const egressTable = "ocean_fixed_egress"
const activeTenants = "active_tenant_networks"

func (gateway FixedEgress) validate() error {
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
	return nil
}

func (gateway FixedEgress) Apply(ctx context.Context, namespace string) error {
	if err := gateway.validate(); err != nil {
		return err
	}
	policy := nftPolicy{table: egressTable}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.prefixSet("tenant_networks", gateway.TenantPrefixes)
	policy.prefixSet("protected_networks", gateway.ProtectedPrefixes)
	forwarding := "tenant_networks"
	if gateway.GateOnActivation {
		forwarding = activeTenants
		policy.command("add set inet %s %s { type ipv4_addr; flags interval; auto-merge; }", policy.table, forwarding)
	}
	policy.command("add chain inet %s forward { type filter hook forward priority filter; policy drop; }", policy.table)
	policy.command("add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", policy.table)

	inside, outside := strconv.Quote(gateway.Inside), strconv.Quote(gateway.Outside)
	policy.rule("forward", "meta nfproto != ipv4 counter drop")
	policy.rule("forward", "ip saddr @protected_networks counter drop")
	policy.rule("forward", "ip daddr @protected_networks counter drop")
	policy.rule("forward", "ct state invalid counter drop")
	// Only connections whose first packet crossed from an attached subnet
	// receive source NAT. The reverse path requires that conntrack state.
	policy.rule("forward", fmt.Sprintf("iifname %s oifname %s ip saddr @%s counter accept", inside, outside, forwarding))
	policy.rule("forward", fmt.Sprintf("iifname %s oifname %s ip daddr @%s ct state established,related ct status snat counter accept", outside, inside, forwarding))
	policy.rule("postrouting", fmt.Sprintf("iifname %s oifname %s ip saddr @tenant_networks counter snat ip to %s",
		inside, outside, gateway.Address))
	return applyNftRules(ctx, namespace, policy.script.String())
}

// SetActive is called by the gateway's ownership service after a transition.
// A standby keeps its rules installed with an empty forwarding set.
func (gateway FixedEgress) SetActive(ctx context.Context, namespace string, active bool) error {
	if err := gateway.validate(); err != nil {
		return err
	}
	if !gateway.GateOnActivation || !linkName.MatchString(namespace) {
		return errors.New("an isolated activation-gated gateway namespace is required")
	}
	policy := nftPolicy{table: egressTable}
	policy.command("flush set inet %s %s", policy.table, activeTenants)
	if active {
		assigned, err := linkHasIPv4(ctx, namespace, gateway.Outside, gateway.Address)
		if err != nil {
			return errors.Join(err, applyNftRules(ctx, namespace, policy.script.String()))
		}
		if !assigned {
			return errors.Join(errors.New("the public IPv4 address has not been assigned to the external interface"),
				applyNftRules(ctx, namespace, policy.script.String()))
		}
		prefixes := make([]string, 0, len(gateway.TenantPrefixes))
		for _, prefix := range gateway.TenantPrefixes {
			prefixes = append(prefixes, prefix.String())
		}
		policy.command("add element inet %s %s { %s }", policy.table, activeTenants, strings.Join(prefixes, ", "))
	}
	return applyNftRules(ctx, namespace, policy.script.String())
}

func linkHasIPv4(ctx context.Context, namespace, iface string, target netip.Addr) (bool, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/ip", "-n", namespace, "-4", "-j", "address", "show", "dev", iface).Output()
	if err != nil {
		return false, fmt.Errorf("read assigned gateway addresses: %w", err)
	}
	var links []struct {
		Addresses []struct {
			Local netip.Addr `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(output, &links); err != nil {
		return false, err
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			if address.Local == target {
				return true, nil
			}
		}
	}
	return false, nil
}
