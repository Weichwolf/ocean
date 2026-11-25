package network

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var linkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// ValidRoutingLink reports whether a local namespace or interface name is supported.
func ValidRoutingLink(name string) bool {
	return linkName.MatchString(name)
}

// WorkloadFirewall describes the policy on the router side of one workload
// link. Prefixes other than the VNet and security rules are operator policy.
type WorkloadFirewall struct {
	Interface          string
	Address            netip.Addr
	PublicPort         int
	BlockPublicIngress bool
	VNetPrefixes       []netip.Prefix
	ProtectedPrefixes  []netip.Prefix
	InternetPrefixes   []netip.Prefix
	Rules              []SecurityRule
	Lease              time.Duration
}

// Apply installs a complete policy in an existing isolated routing namespace.
// A failed nft transaction leaves the previous policy in place.
func (f WorkloadFirewall) Apply(ctx context.Context, namespace string) error {
	ruleset, err := f.ruleset()
	if err != nil {
		return err
	}
	return applyNftRules(ctx, namespace, ruleset)
}

// Refresh renews an installed firewall's kernel deadline.
func (f WorkloadFirewall) Refresh(ctx context.Context, namespace string) error {
	if !linkName.MatchString(f.Interface) || !f.Address.Is4() || !validFirewallLease(f.Lease) || f.Lease == 0 {
		return errors.New("invalid leased firewall")
	}
	policy := nftPolicy{table: firewallTable(f.Interface)}
	policy.command("flush set inet %s live_address", policy.table)
	policy.command("add element inet %s live_address { %s }", policy.table, f.Address)
	return applyNftRules(ctx, namespace, policy.script.String())
}

// BlockWorkload replaces an endpoint's policy with a persistent drop.
func BlockWorkload(ctx context.Context, namespace, iface string) error {
	if !linkName.MatchString(iface) {
		return errors.New("invalid workload interface")
	}
	policy := nftPolicy{table: firewallTable(iface)}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.baseChain("local_in", "input", "filter")
	policy.baseChain("local_out", "output", "filter")
	policy.baseChain("forwarded", "forward", "filter")
	name := strconv.Quote(iface)
	policy.rule("local_in", "iifname "+name+" counter drop")
	policy.rule("local_out", "oifname "+name+" counter drop")
	policy.rule("forwarded", "iifname "+name+" counter drop")
	policy.rule("forwarded", "oifname "+name+" counter drop")
	return applyNftRules(ctx, namespace, policy.script.String())
}

func firewallTable(iface string) string {
	return "ocean_" + hex.EncodeToString([]byte(iface))
}

func validFirewallLease(duration time.Duration) bool {
	return duration >= 0 && duration <= 15*time.Second && duration%time.Second == 0
}

func applyNftRules(ctx context.Context, namespace, ruleset string) error {
	if !linkName.MatchString(namespace) {
		return errors.New("invalid routing namespace")
	}
	command := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace, "/usr/sbin/nft", "-f", "-")
	command.Stdin = strings.NewReader(ruleset)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("apply nftables policy to %s: %w: %s", namespace, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (f WorkloadFirewall) ruleset() (string, error) {
	public := f.PublicPort != 0
	if !linkName.MatchString(f.Interface) || !f.Address.Is4() || !f.Address.IsGlobalUnicast() ||
		public && (f.PublicPort < 1 || f.PublicPort > 65535) || !public && !f.Address.IsPrivate() {
		return "", errors.New("invalid workload interface or IPv4 address")
	}
	if !public && len(f.VNetPrefixes) == 0 || len(f.ProtectedPrefixes) == 0 {
		return "", errors.New("VNet and protected network prefixes are required")
	}
	if !validFirewallLease(f.Lease) {
		return "", errors.New("invalid firewall lease duration")
	}
	for _, prefixes := range [][]netip.Prefix{f.VNetPrefixes, f.ProtectedPrefixes, f.InternetPrefixes} {
		for _, prefix := range prefixes {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return "", errors.New("firewall prefixes must be canonical IPv4 prefixes")
			}
		}
	}
	if !public && !slices.ContainsFunc(f.VNetPrefixes, func(p netip.Prefix) bool { return p.Contains(f.Address) }) ||
		slices.ContainsFunc(f.ProtectedPrefixes, func(p netip.Prefix) bool { return p.Contains(f.Address) }) {
		return "", errors.New("workload address must belong to its VNet and be outside the protected prefixes")
	}
	group := slices.Clone(f.Rules)
	slices.SortFunc(group, func(a, b SecurityRule) int { return a.Properties.Priority - b.Properties.Priority })
	policy := nftPolicy{table: firewallTable(f.Interface)}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.baseChain("guard", "prerouting", "raw")
	policy.baseChain("local_in", "input", "filter")
	policy.baseChain("local_out", "output", "filter")
	policy.baseChain("forwarded", "forward", "filter")
	policy.command("add chain inet %s ingress", policy.table)
	policy.command("add chain inet %s egress", policy.table)
	iface := strconv.Quote(f.Interface)
	policy.rule("guard", "iifname "+iface+" meta nfproto != ipv4 counter drop")
	policy.rule("guard", fmt.Sprintf("iifname %s ip saddr != %s counter drop", iface, f.Address))
	policy.rule("local_in", "iifname "+iface+" counter drop")
	policy.rule("local_out", "oifname "+iface+" counter drop")
	policy.rule("forwarded", "oifname "+iface+" meta nfproto != ipv4 counter drop")
	policy.rule("forwarded", fmt.Sprintf("oifname %s ip daddr != %s counter drop", iface, f.Address))
	if f.Lease != 0 {
		policy.command("add set inet %s live_address { type ipv4_addr; flags timeout; timeout %ds; elements = { %s }; }",
			policy.table, f.Lease/time.Second, f.Address)
		policy.rule("forwarded", "iifname "+iface+" ip saddr != @live_address counter drop")
		policy.rule("forwarded", "oifname "+iface+" ip daddr != @live_address counter drop")
	}
	policy.rule("forwarded", "iifname "+iface+" jump egress")
	policy.rule("forwarded", "oifname "+iface+" jump ingress")

	policy.prefixSet("protected_networks", f.ProtectedPrefixes)
	if !public {
		policy.prefixSet("virtual_network", f.VNetPrefixes)
	}
	for _, chain := range []string{"ingress", "egress"} {
		policy.rule(chain, "ip saddr @protected_networks counter drop")
		policy.rule(chain, "ip daddr @protected_networks counter drop")
		policy.rule(chain, "ct state invalid counter drop")
		policy.rule(chain, "ct state established,related counter return")
	}
	priorities := make(map[string]bool)
	for _, rule := range group {
		properties := rule.Properties
		properties.ProvisioningState = ""
		if err := properties.Validate(); err != nil {
			return "", fmt.Errorf("invalid security rule %q: %w", rule.Name, err)
		}
		chain := "ingress"
		if properties.Direction == "Outbound" {
			chain = "egress"
		}
		key := chain + "_" + strconv.Itoa(properties.Priority)
		if priorities[key] {
			return "", errors.New("duplicate security rule priority in one direction")
		}
		priorities[key] = true
		policy.securityRule(chain, key, properties)
	}
	if public {
		if !f.BlockPublicIngress {
			policy.rule("ingress", fmt.Sprintf("tcp dport %d ct state new counter return", f.PublicPort))
		}
	} else {
		for _, chain := range []string{"ingress", "egress"} {
			policy.rule(chain, "ip saddr @virtual_network ip daddr @virtual_network counter return")
		}
	}
	if len(f.InternetPrefixes) != 0 {
		policy.prefixSet("internet_routes", f.InternetPrefixes)
		policy.rule("egress", "ip daddr @internet_routes counter return")
	}
	policy.rule("ingress", "counter drop")
	policy.rule("egress", "counter drop")
	return policy.script.String(), nil
}

type nftPolicy struct {
	table  string
	script strings.Builder
}

func (p *nftPolicy) command(format string, arguments ...any) {
	fmt.Fprintf(&p.script, format, arguments...)
	p.script.WriteByte('\n')
}

func (p *nftPolicy) baseChain(chain, hook, priority string) {
	p.command("add chain inet %s %s { type filter hook %s priority %s; policy accept; }", p.table, chain, hook, priority)
}

func (p *nftPolicy) rule(chain, expression string) {
	p.command("add rule inet %s %s %s", p.table, chain, expression)
}

func (p *nftPolicy) intervalSet(name, kind string, elements []string) {
	p.command("add set inet %s %s { type %s; flags interval; auto-merge; elements = { %s } ; }",
		p.table, name, kind, strings.Join(elements, ", "))
}

func (p *nftPolicy) prefixSet(name string, prefixes []netip.Prefix) {
	elements := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		elements[index] = prefix.String()
	}
	p.intervalSet(name, "ipv4_addr", elements)
}

func (p *nftPolicy) securityRule(chain, key string, rule SecurityRuleProperties) {
	var expression []string
	protocol := strings.ToLower(rule.Protocol)
	if protocol != "*" {
		expression = append(expression, "meta l4proto "+protocol)
	}
	selectors := []struct {
		suffix, kind, field, single string
		multiple                    []string
	}{
		{"sa", "ipv4_addr", "ip saddr", rule.SourceAddressPrefix, rule.SourceAddressPrefixes},
		{"da", "ipv4_addr", "ip daddr", rule.DestinationAddressPrefix, rule.DestinationAddressPrefixes},
		{"sp", "inet_service", protocol + " sport", rule.SourcePortRange, rule.SourcePortRanges},
		{"dp", "inet_service", protocol + " dport", rule.DestinationPortRange, rule.DestinationPortRanges},
	}
	for _, selector := range selectors {
		if wildcardSelector(selector.single, selector.multiple) {
			continue
		}
		elements := selector.multiple
		if selector.single != "" {
			elements = []string{selector.single}
		}
		if selector.kind == "inet_service" {
			elements = slices.Clone(elements)
			for index := range elements {
				parts := strings.Split(elements[index], "-")
				for part := range parts {
					port, _ := strconv.ParseUint(parts[part], 10, 16)
					parts[part] = strconv.FormatUint(port, 10)
				}
				elements[index] = strings.Join(parts, "-")
			}
		}
		name := key + "_" + selector.suffix
		p.intervalSet(name, selector.kind, elements)
		expression = append(expression, selector.field+" @"+name)
	}
	verdict := "counter drop"
	if rule.Access == "Allow" {
		verdict = "counter return"
	}
	expression = append(expression, verdict)
	p.rule(chain, strings.Join(expression, " "))
}
