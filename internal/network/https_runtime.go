package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const httpsGatewayTable = "ocean_https_gateway"

// HTTPSGatewaySlot describes operator-owned links for an isolated HTTPS role.
type HTTPSGatewaySlot struct {
	Namespace        string       `json:"namespace"`
	PublicInterface  string       `json:"publicInterface"`
	BackendInterface string       `json:"backendInterface"`
	PublicLink       netip.Prefix `json:"publicLink"`
	PeerAddress      netip.Addr   `json:"peerAddress"`
	PeerMAC          string       `json:"peerMac"`
	Priority         uint8        `json:"priority"`
	VRRPID           uint8        `json:"vrrpId"`
}

func (slot HTTPSGatewaySlot) Validate() error {
	if !ValidRoutingLink(slot.Namespace) || !ValidRoutingLink(slot.PublicInterface) ||
		!ValidRoutingLink(slot.BackendInterface) || slot.PublicInterface == slot.BackendInterface ||
		slot.PublicInterface == "lo" || slot.BackendInterface == "lo" {
		return errors.New("HTTPS gateway slots require a dedicated namespace and two separate network interfaces")
	}
	mac, err := net.ParseMAC(slot.PeerMAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slot.Priority == 0 || slot.Priority == 255 || slot.VRRPID == 0 ||
		!slot.PublicLink.Addr().Is4() || !slot.PublicLink.Addr().IsGlobalUnicast() || slot.PublicLink.Bits() > 29 ||
		!slot.PeerAddress.IsGlobalUnicast() || !slot.PublicLink.Contains(slot.PeerAddress) || slot.PeerAddress == slot.PublicLink.Addr() {
		return errors.New("HTTPS gateway slots require distinct on-link peers and valid VRRP settings")
	}
	return nil
}

func (slot HTTPSGatewaySlot) validateAddress(address netip.Addr) error {
	if err := slot.Validate(); err != nil {
		return err
	}
	if !address.IsGlobalUnicast() || !slot.PublicLink.Contains(address) || address == slot.PeerAddress ||
		address == slot.PublicLink.Addr() || address == slot.PublicLink.Masked().Addr() || !slot.PublicLink.Contains(address.Next()) {
		return errors.New("the public IPv4 address must belong to the slot's public link")
	}
	return nil
}

// InstallLease installs the namespace guard with a kernel expiry on public
// HTTPS and DNS access. The caller renews the lease while its assignment is valid.
func (slot HTTPSGatewaySlot) InstallLease(ctx context.Context, publicIPv4 netip.Addr) error {
	if err := slot.validateAddress(publicIPv4); err != nil {
		return err
	}
	policy := nftPolicy{table: httpsGatewayTable}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.command("add set inet %s active_addresses { type ipv4_addr; flags timeout; timeout 8s; elements = { %s, %s }; }",
		policy.table, publicIPv4, slot.PublicLink.Addr())
	policy.command("add chain inet %s incoming { type filter hook input priority filter; policy drop; }", policy.table)
	policy.command("add chain inet %s forwarded { type filter hook forward priority filter; policy drop; }", policy.table)
	publicInterface, backendInterface := strconv.Quote(slot.PublicInterface), strconv.Quote(slot.BackendInterface)
	policy.rule("incoming", `iifname "lo" accept`)
	policy.rule("incoming", fmt.Sprintf("iifname %s ct state established,related accept", backendInterface))
	peerMAC, _ := net.ParseMAC(slot.PeerMAC)
	policy.rule("incoming", fmt.Sprintf("iifname %s ether saddr %s ip saddr %s ip daddr %s ip ttl 255 ip protocol vrrp accept",
		publicInterface, peerMAC, slot.PeerAddress, slot.PublicLink.Addr()))
	policy.rule("incoming", fmt.Sprintf("iifname %s ip daddr @active_addresses ip daddr %s tcp dport 443 accept", publicInterface, publicIPv4))
	policy.rule("incoming", fmt.Sprintf("iifname %s ip daddr @active_addresses ip daddr %s meta l4proto { tcp, udp } th dport 53 accept",
		publicInterface, slot.PublicLink.Addr()))
	return applyNftRules(ctx, slot.Namespace, policy.script.String())
}

func (slot HTTPSGatewaySlot) RefreshLease(ctx context.Context, publicIPv4 netip.Addr) error {
	if err := slot.validateAddress(publicIPv4); err != nil {
		return err
	}
	policy := nftPolicy{table: httpsGatewayTable}
	policy.command("flush set inet %s active_addresses", policy.table)
	policy.command("add element inet %s active_addresses { %s, %s }", policy.table, publicIPv4, slot.PublicLink.Addr())
	return applyNftRules(ctx, slot.Namespace, policy.script.String())
}

func (slot HTTPSGatewaySlot) RevokeLease(ctx context.Context) error {
	return applyNftRules(ctx, slot.Namespace, "flush set inet "+httpsGatewayTable+" active_addresses\n")
}

func (slot HTTPSGatewaySlot) OwnsAddress(ctx context.Context, address netip.Addr) (bool, error) {
	if err := slot.validateAddress(address); err != nil {
		return false, err
	}
	return linkHasIPv4(ctx, slot.Namespace, slot.PublicInterface, address)
}

// Keepalived configures an exclusive public address on the two approved peers.
func (slot HTTPSGatewaySlot) Keepalived(address netip.Addr, backend netip.AddrPort, additional ...netip.AddrPort) (string, error) {
	if err := slot.validateAddress(address); err != nil {
		return "", err
	}
	if len(additional) >= MaxHTTPSBackends {
		return "", errors.New("the gateway readiness pool exceeds its size limit")
	}
	targets := []string{"/usr/libexec/ocean/https-ready", address.String()}
	for _, target := range slices.Concat([]netip.AddrPort{backend}, additional) {
		if !target.Addr().Is4() || !target.Addr().IsPrivate() || target.Port() == 0 {
			return "", errors.New("the gateway needs private IPv4 readiness targets")
		}
		targets = append(targets, target.String())
	}
	check := strings.Join(targets, " ")
	return renderGatewayVRRP(check, slot.PublicInterface, slot.VRRPID, slot.Priority,
		slot.PublicLink.Addr(), slot.PeerAddress, netip.PrefixFrom(address, slot.PublicLink.Bits())), nil
}

func renderGatewayVRRP(command, iface string, id, priority uint8, source, peer netip.Addr, address netip.Prefix) string {
	return fmt.Sprintf(`global_defs {
  script_user root
  enable_script_security
}
vrrp_script ingress_ready {
  script "%s"
  interval 1
  timeout 2
  rise 1
  fall 2
  init_fail
}
vrrp_instance OCEAN_GATEWAY {
  state BACKUP
  interface %s
  virtual_router_id %d
  priority %d
  nopreempt
  advert_int 1
  unicast_src_ip %s
  unicast_peer {
    %s min_ttl 255 max_ttl 255
  }
  garp_master_delay 0
  track_script {
    ingress_ready
  }
  virtual_ipaddress {
    %s dev %s
  }
}
`, command, iface, id, priority, source, peer, address, iface)
}
