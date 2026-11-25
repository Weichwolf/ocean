package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// WireGuardGateway configures one side of a routed site-to-site tunnel in a
// dedicated namespace. The two physical links must already be attached.
type WireGuardGateway struct {
	Tunnel            string         `json:"tunnel"`
	Underlay          string         `json:"underlay"`
	Inside            string         `json:"inside"`
	LocalTunnel       netip.Prefix   `json:"localTunnel"`
	PeerTunnel        netip.Addr     `json:"peerTunnel"`
	ListenPort        uint16         `json:"listenPort"`
	PeerEndpoint      netip.AddrPort `json:"peerEndpoint"`
	PeerPublicKey     string         `json:"peerPublicKey"`
	PrivateKeyFile    string         `json:"privateKeyFile"`
	LocalPrefixes     []netip.Prefix `json:"localPrefixes"`
	RemotePrefixes    []netip.Prefix `json:"remotePrefixes"`
	ProtectedPrefixes []netip.Prefix `json:"protectedPrefixes"`
	Redundancy        *WireGuardVRRP `json:"redundancy,omitempty"`
	LeaseControlled   bool           `json:"leaseControlled,omitempty"`
}

// WireGuardVRRP identifies a trusted unicast peer on the inside routing link.
type WireGuardVRRP struct {
	Address netip.Addr `json:"address"`
	Peer    netip.Addr `json:"peer"`
	PeerMAC string     `json:"peerMac"`
}

const (
	wireGuardTable = "ocean_wireguard"
	vpnRouteMarker = "99"
)

func (g WireGuardGateway) validate(namespace string) error {
	if !linkName.MatchString(namespace) || !linkName.MatchString(g.Tunnel) || !linkName.MatchString(g.Underlay) ||
		!linkName.MatchString(g.Inside) || g.Tunnel == g.Underlay || g.Tunnel == g.Inside || g.Underlay == g.Inside ||
		g.Tunnel == "lo" || g.Underlay == "lo" || g.Inside == "lo" {
		return errors.New("an isolated WireGuard namespace and three different interfaces are required")
	}
	if !g.LocalTunnel.Addr().Is4() || !g.LocalTunnel.Addr().IsPrivate() ||
		g.LocalTunnel.Bits() != 31 || g.LocalTunnel.Addr() == g.PeerTunnel || !g.LocalTunnel.Contains(g.PeerTunnel) {
		return errors.New("local and peer tunnel addresses must share a private IPv4 /31")
	}
	if g.ListenPort == 0 || g.PeerEndpoint.Port() == 0 || !g.PeerEndpoint.Addr().Is4() ||
		!g.PeerEndpoint.Addr().IsGlobalUnicast() || !validWireGuardKey(g.PeerPublicKey) || !filepath.IsAbs(g.PrivateKeyFile) {
		return errors.New("the WireGuard gateway requires UDP ports, a peer endpoint, and valid key configuration")
	}
	all := []netip.Prefix{g.LocalTunnel.Masked(), netip.PrefixFrom(g.PeerEndpoint.Addr(), 32)}
	for _, group := range []struct {
		prefixes []netip.Prefix
		private  bool
	}{{g.LocalPrefixes, true}, {g.RemotePrefixes, true}, {g.ProtectedPrefixes, false}} {
		if len(group.prefixes) == 0 || len(group.prefixes) > 32 {
			return errors.New("one to 32 local, remote, and protected prefixes are required")
		}
		for _, prefix := range group.prefixes {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() ||
				group.private && !privateNetworkPrefix(prefix) || slices.ContainsFunc(all, prefix.Overlaps) {
				return errors.New("VPN prefixes and the underlay endpoint must be disjoint, and routed prefixes must be private IPv4")
			}
			all = append(all, prefix)
		}
	}
	if g.LocalTunnel.Contains(g.PeerEndpoint.Addr()) {
		return errors.New("the WireGuard peer endpoint overlaps the tunnel addresses")
	}
	if peer := g.Redundancy; peer != nil {
		mac, err := net.ParseMAC(peer.PeerMAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || peer.Address == peer.Peer ||
			!slices.ContainsFunc(g.LocalPrefixes, func(prefix netip.Prefix) bool {
				return prefix.Contains(peer.Address) && prefix.Contains(peer.Peer)
			}) {
			return errors.New("the redundant gateway peer must have a distinct local IPv4 address and a unicast MAC")
		}
	}
	return nil
}

func validWireGuardKey(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32 && strings.TrimSpace(value) == value &&
		base64.StdEncoding.EncodeToString(raw) == value && !bytes.Equal(raw, make([]byte, 32))
}

func readWireGuardKey(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 || info.Size() > 64 {
		return "", errors.New("the WireGuard private key must be a small root-owned private file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return "", err
	}
	key := strings.TrimSuffix(string(data), "\n")
	if !validWireGuardKey(key) {
		return "", errors.New("the WireGuard private key file must contain one key")
	}
	return key, nil
}

// Apply programs the tunnel and its forwarding allowlist. An incomplete
// reconfiguration leaves the dedicated namespace with forwarding blocked.
func (g WireGuardGateway) Apply(ctx context.Context, namespace string) error {
	if err := g.validate(namespace); err != nil {
		return err
	}
	if err := g.applyRules(ctx, namespace, false); err != nil {
		return err
	}
	key, err := readWireGuardKey(g.PrivateKeyFile)
	if err != nil {
		return err
	}
	if err := g.checkUnderlay(ctx, namespace); err != nil {
		return err
	}
	if _, err := vpnIP(ctx, namespace, "link", "show", "dev", g.Inside); err != nil {
		return err
	}
	exists, err := g.tunnelExists(ctx, namespace)
	if err != nil {
		return err
	}
	if !exists {
		if _, err := vpnIP(ctx, namespace, "link", "add", "dev", g.Tunnel, "type", "wireguard"); err != nil {
			return err
		}
	}
	if err := g.configureTunnel(ctx, namespace, key); err != nil {
		return err
	}
	if _, err := vpnIP(ctx, namespace, "link", "set", "dev", g.Tunnel, "up"); err != nil {
		return err
	}
	if err := g.reconcileRoutes(ctx, namespace); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace,
		"/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("enable IPv4 VPN forwarding: %w: %s", err, bytes.TrimSpace(output))
	}
	return g.applyRules(ctx, namespace, true)
}

// Remove closes forwarding and removes the owned tunnel and its routes.
func (g WireGuardGateway) Remove(ctx context.Context, namespace string) error {
	if err := g.validate(namespace); err != nil {
		return err
	}
	return RemoveWireGuardTunnel(ctx, namespace, g.Tunnel)
}

// RemoveWireGuardTunnel closes the slot and withdraws its owned tunnel device.
func RemoveWireGuardTunnel(ctx context.Context, namespace, tunnel string) error {
	if !linkName.MatchString(namespace) || !linkName.MatchString(tunnel) || tunnel == "lo" {
		return errors.New("invalid WireGuard namespace or tunnel")
	}
	g := WireGuardGateway{Tunnel: tunnel}
	if err := g.applyRules(ctx, namespace, false); err != nil {
		return err
	}
	exists, err := g.tunnelExists(ctx, namespace)
	if err != nil || !exists {
		return err
	}
	_, err = vpnIP(ctx, namespace, "link", "delete", "dev", g.Tunnel)
	return err
}

// RefreshLease renews the kernel gate on a previously applied tunnel.
func (g WireGuardGateway) RefreshLease(ctx context.Context, namespace string) error {
	if !g.LeaseControlled || !linkName.MatchString(g.Tunnel) {
		return errors.New("the WireGuard tunnel does not have a forwarding lease")
	}
	policy := nftPolicy{table: wireGuardTable}
	policy.command("flush set inet %s live_tunnel", policy.table)
	policy.command("add element inet %s live_tunnel { %q }", policy.table, g.Tunnel)
	return applyNftRules(ctx, namespace, policy.script.String())
}

// Probe checks the authenticated tunnel path for a local routing supervisor.
func (g WireGuardGateway) Probe(ctx context.Context, namespace string) error {
	if err := g.validate(namespace); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace,
		"/usr/bin/ping", "-n", "-c", "1", "-W", "1", "-I", g.LocalTunnel.Addr().String(), g.PeerTunnel.String())
	if err := command.Run(); err != nil {
		return fmt.Errorf("probe the authenticated WireGuard peer: %w", err)
	}
	return nil
}

// Keepalived follows the encrypted tunnel probe when selecting the LAN router.
func (g WireGuardGateway) Keepalived(namespace string, address netip.Prefix, id, priority uint8) (string, error) {
	if err := g.validate(namespace); err != nil {
		return "", err
	}
	if g.Redundancy == nil || id == 0 || priority == 0 || priority == 255 || address == address.Masked() ||
		!slices.Contains(g.LocalPrefixes, address.Masked()) || !address.Contains(address.Addr().Next()) ||
		address.Addr() == g.Redundancy.Address || address.Addr() == g.Redundancy.Peer {
		return "", errors.New("the redundant WireGuard router address must be on an approved inside subnet")
	}
	probe := fmt.Sprintf("/usr/bin/ping -n -q -c 1 -W 1 -I %s %s", g.LocalTunnel.Addr(), g.PeerTunnel)
	return renderGatewayVRRP(probe, g.Inside, id, priority, g.Redundancy.Address, g.Redundancy.Peer, address), nil
}

func (g WireGuardGateway) OwnsAddress(ctx context.Context, namespace string, address netip.Addr) (bool, error) {
	return WireGuardOwnsAddress(ctx, namespace, g.Inside, address)
}

// WireGuardOwnsAddress reports whether the named LAN interface still has a virtual address.
func WireGuardOwnsAddress(ctx context.Context, namespace, inside string, address netip.Addr) (bool, error) {
	if !linkName.MatchString(namespace) || !linkName.MatchString(inside) || !address.Is4() {
		return false, errors.New("invalid WireGuard LAN endpoint")
	}
	return linkHasIPv4(ctx, namespace, inside, address)
}

func (g WireGuardGateway) checkUnderlay(ctx context.Context, namespace string) error {
	raw, err := vpnIP(ctx, namespace, "-4", "-j", "route", "get", g.PeerEndpoint.Addr().String())
	if err != nil {
		return err
	}
	var routes []struct {
		Device string     `json:"dev"`
		Source netip.Addr `json:"prefsrc"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return err
	}
	if len(routes) != 1 || routes[0].Device != g.Underlay || !routes[0].Source.IsGlobalUnicast() {
		return errors.New("the WireGuard endpoint must be reachable over the configured underlay")
	}
	for _, prefixes := range [][]netip.Prefix{g.LocalPrefixes, g.RemotePrefixes, g.ProtectedPrefixes, {g.LocalTunnel.Masked()}} {
		if slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(routes[0].Source) }) {
			return errors.New("the WireGuard underlay source overlaps a routed or protected network")
		}
	}
	return nil
}

func (g WireGuardGateway) tunnelExists(ctx context.Context, namespace string) (bool, error) {
	raw, err := vpnIP(ctx, namespace, "-details", "-json", "link", "show")
	if err != nil {
		return false, err
	}
	var links []struct {
		Name string `json:"ifname"`
		Info struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(raw, &links); err != nil {
		return false, err
	}
	for _, link := range links {
		if link.Name == g.Tunnel {
			if link.Info.Kind != "wireguard" {
				return false, errors.New("the configured tunnel name belongs to a different device type")
			}
			return true, nil
		}
	}
	return false, nil
}

func (g WireGuardGateway) configureTunnel(ctx context.Context, namespace, privateKey string) error {
	allowed := []string{netip.PrefixFrom(g.PeerTunnel, 32).String()}
	for _, prefix := range g.RemotePrefixes {
		allowed = append(allowed, prefix.String())
	}
	command := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace,
		"/usr/bin/wg", "syncconf", g.Tunnel, "/dev/stdin")
	command.Stdin = strings.NewReader(fmt.Sprintf(
		"[Interface]\nPrivateKey = %s\nListenPort = %d\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n",
		privateKey, g.ListenPort, g.PeerPublicKey, g.PeerEndpoint, strings.Join(allowed, ", ")))
	// WireGuard can echo malformed configuration lines. Keep its output private.
	if err := command.Run(); err != nil {
		return fmt.Errorf("configure WireGuard peer: %w", err)
	}
	if _, err := vpnIP(ctx, namespace, "-4", "address", "replace", g.LocalTunnel.String(), "dev", g.Tunnel); err != nil {
		return err
	}
	raw, err := vpnIP(ctx, namespace, "-4", "-j", "address", "show", "dev", g.Tunnel)
	if err != nil {
		return err
	}
	var links []struct {
		Addresses []struct {
			Local     netip.Addr `json:"local"`
			PrefixLen int        `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(raw, &links); err != nil {
		return err
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			prefix := netip.PrefixFrom(address.Local, address.PrefixLen)
			if prefix != g.LocalTunnel {
				if _, err := vpnIP(ctx, namespace, "-4", "address", "delete", prefix.String(), "dev", g.Tunnel); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (g WireGuardGateway) reconcileRoutes(ctx context.Context, namespace string) error {
	raw, err := vpnIP(ctx, namespace, "-4", "-j", "route", "show", "dev", g.Tunnel, "proto", vpnRouteMarker)
	if err != nil {
		return err
	}
	var routes []struct {
		Destination string `json:"dst"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return err
	}
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			address, addressErr := netip.ParseAddr(route.Destination)
			if addressErr != nil {
				return errors.New("invalid managed WireGuard route")
			}
			prefix = netip.PrefixFrom(address, 32)
		}
		if !slices.Contains(g.RemotePrefixes, prefix) {
			if _, err := vpnIP(ctx, namespace, "-4", "route", "delete", prefix.String(), "dev", g.Tunnel, "proto", vpnRouteMarker); err != nil {
				return err
			}
		}
	}
	for _, prefix := range g.RemotePrefixes {
		if _, err := vpnIP(ctx, namespace, "-4", "route", "replace", prefix.String(), "dev", g.Tunnel, "proto", vpnRouteMarker); err != nil {
			return err
		}
	}
	return nil
}

func vpnIP(ctx context.Context, namespace string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/ip", append([]string{"-n", namespace}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("configure VPN namespace %s: %w: %s", namespace, err, bytes.TrimSpace(output))
	}
	return output, nil
}

func (g WireGuardGateway) applyRules(ctx context.Context, namespace string, active bool) error {
	policy := nftPolicy{table: wireGuardTable}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.command("add chain inet %s forwarded { type filter hook forward priority filter; policy drop; }", policy.table)
	policy.command("add chain inet %s local_in { type filter hook input priority filter; policy drop; }", policy.table)
	tunnel, underlay, inside := strconv.Quote(g.Tunnel), strconv.Quote(g.Underlay), strconv.Quote(g.Inside)
	policy.rule("local_in", `iifname "lo" counter accept`)
	if active {
		policy.prefixSet("local_networks", g.LocalPrefixes)
		policy.prefixSet("remote_networks", g.RemotePrefixes)
		policy.prefixSet("protected_networks", g.ProtectedPrefixes)
		if g.LeaseControlled {
			policy.command("add set inet %s live_tunnel { type ifname; flags timeout; timeout 8s; elements = { %s }; }",
				policy.table, tunnel)
			tunnel = "@live_tunnel"
		}
		policy.rule("forwarded", "ip saddr @protected_networks counter drop")
		policy.rule("forwarded", "ip daddr @protected_networks counter drop")
		// Requests and replies can traverse different healthy tunnels.
		// Peer authentication and the prefix rules apply to each direction.
		policy.rule("forwarded", fmt.Sprintf("iifname %s oifname %s ip saddr @remote_networks ip daddr @local_networks counter accept", tunnel, inside))
		policy.rule("forwarded", fmt.Sprintf("iifname %s oifname %s ip saddr @local_networks ip daddr @remote_networks counter accept", inside, tunnel))
		policy.rule("local_in", fmt.Sprintf("iifname %s ip saddr %s udp dport %d counter accept", underlay, g.PeerEndpoint.Addr(), g.ListenPort))
		policy.rule("local_in", fmt.Sprintf("iifname %s ip saddr %s ip daddr %s icmp type { echo-request, echo-reply } counter accept",
			tunnel, g.PeerTunnel, g.LocalTunnel.Addr()))
		if peer := g.Redundancy; peer != nil {
			mac, _ := net.ParseMAC(peer.PeerMAC)
			policy.rule("local_in", fmt.Sprintf("iifname %s ether saddr %s ip saddr %s ip daddr %s ip ttl 255 ip protocol vrrp counter accept",
				inside, mac, peer.Peer, peer.Address))
		}
	}
	return applyNftRules(ctx, namespace, policy.script.String())
}
