package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	for _, group := range [][]netip.Prefix{g.LocalPrefixes, g.RemotePrefixes, g.ProtectedPrefixes} {
		if len(group) == 0 || len(group) > 32 {
			return errors.New("one to 32 local, remote, and protected prefixes are required")
		}
		for _, prefix := range group {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() || !slices.ContainsFunc(privateBlocks, func(block netip.Prefix) bool {
				return block.Bits() <= prefix.Bits() && block.Contains(prefix.Addr())
			}) || slices.ContainsFunc(all, prefix.Overlaps) {
				return errors.New("VPN prefixes and underlay endpoint must be disjoint, with canonical private IPv4 networks")
			}
			all = append(all, prefix)
		}
	}
	if g.LocalTunnel.Contains(g.PeerEndpoint.Addr()) {
		return errors.New("the WireGuard peer endpoint overlaps the tunnel addresses")
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
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0077 != 0 || info.Size() > 64 {
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
		policy.rule("forwarded", "ip saddr @protected_networks counter drop")
		policy.rule("forwarded", "ip daddr @protected_networks counter drop")
		policy.rule("forwarded", "ct state invalid counter drop")
		policy.rule("forwarded", fmt.Sprintf("iifname %s oifname %s ip saddr @remote_networks ip daddr @local_networks counter accept", tunnel, inside))
		policy.rule("forwarded", fmt.Sprintf("iifname %s oifname %s ip saddr @local_networks ip daddr @remote_networks counter accept", inside, tunnel))
		policy.rule("local_in", fmt.Sprintf("iifname %s ip saddr %s udp dport %d counter accept", underlay, g.PeerEndpoint.Addr(), g.ListenPort))
		policy.rule("local_in", fmt.Sprintf("iifname %s ip saddr %s ip daddr %s icmp type { echo-request, echo-reply } counter accept",
			tunnel, g.PeerTunnel, g.LocalTunnel.Addr()))
	}
	return applyNftRules(ctx, namespace, policy.script.String())
}
