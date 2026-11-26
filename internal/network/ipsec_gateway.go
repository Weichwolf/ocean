package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ipsecTable = "ocean_ipsec"
	ipsecIKE   = "ocean-site"
	ipsecChild = "ocean-net"
	ipsecIfID  = 42
)

// IPsecGateway applies the single-peer IKEv2 profile in a dedicated network
// namespace. The namespace owns its interfaces and a private charon socket.
type IPsecGateway struct {
	Tunnel, Underlay, Inside      string
	LocalEndpoint, RemoteEndpoint netip.Addr
	LocalPrefixes, RemotePrefixes []netip.Prefix
	ProtectedPrefixes             []netip.Prefix
	Socket                        string
}

type IPsecPeer struct {
	Endpoint netip.Addr
	Prefixes []netip.Prefix
}

func (p IPsecPeer) Validate() error {
	if !p.Endpoint.Is4() || !p.Endpoint.IsGlobalUnicast() || len(p.Prefixes) == 0 || len(p.Prefixes) > 32 {
		return errors.New("the IPsec peer requires an IPv4 endpoint and one to 32 customer prefixes")
	}
	for index, prefix := range p.Prefixes {
		if !privateNetworkPrefix(prefix) || prefix.Contains(p.Endpoint) || slices.ContainsFunc(p.Prefixes[:index], prefix.Overlaps) {
			return errors.New("IPsec customer prefixes must be disjoint canonical private IPv4 networks outside the peer endpoint")
		}
	}
	return nil
}

func (g IPsecGateway) validate(namespace string) error {
	links := []string{namespace, g.Tunnel, g.Underlay, g.Inside}
	for _, link := range links {
		if !linkName.MatchString(link) || link == "lo" {
			return errors.New("IPsec requires a named namespace and three non-loopback interfaces")
		}
	}
	if g.Tunnel == g.Underlay || g.Tunnel == g.Inside || g.Underlay == g.Inside {
		return errors.New("IPsec interfaces must be distinct")
	}
	if !g.LocalEndpoint.Is4() || !g.LocalEndpoint.IsGlobalUnicast() || !g.RemoteEndpoint.Is4() ||
		!g.RemoteEndpoint.IsGlobalUnicast() || g.LocalEndpoint == g.RemoteEndpoint || !filepath.IsAbs(g.Socket) ||
		filepath.Clean(g.Socket) != g.Socket || strings.ContainsAny(g.Socket, "\x00\r\n") {
		return errors.New("IPsec requires two distinct IPv4 endpoints and a private absolute charon socket")
	}
	all := []netip.Prefix{netip.PrefixFrom(g.LocalEndpoint, 32), netip.PrefixFrom(g.RemoteEndpoint, 32)}
	for _, group := range []struct {
		prefixes []netip.Prefix
		private  bool
	}{{g.LocalPrefixes, true}, {g.RemotePrefixes, true}, {g.ProtectedPrefixes, false}} {
		if len(group.prefixes) == 0 || len(group.prefixes) > 32 {
			return errors.New("IPsec requires one to 32 prefixes in each network set")
		}
		for _, prefix := range group.prefixes {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() || group.private && !privateNetworkPrefix(prefix) ||
				slices.ContainsFunc(all, prefix.Overlaps) {
				return errors.New("IPsec selectors, endpoints and protected networks must be disjoint")
			}
			all = append(all, prefix)
		}
	}
	return nil
}

// Apply establishes the desired IKE configuration and installs routes through
// XFRM. Forwarding is closed until the whole configuration is staged.
func (g IPsecGateway) Apply(ctx context.Context, namespace string, secret []byte) (err error) {
	if err := g.validate(namespace); err != nil {
		return err
	}
	if len(secret) < 16 || len(secret) > 128 {
		return errors.New("the IPsec shared secret must contain 16 to 128 bytes")
	}
	if err := g.verifyUnderlay(ctx, namespace); err != nil {
		return err
	}
	if _, err := vpnIP(ctx, namespace, "link", "show", "dev", g.Inside); err != nil {
		return err
	}
	if err := g.Remove(ctx, namespace); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
			defer cancel()
			err = errors.Join(err, g.Remove(cleanup, namespace))
		}
	}()
	if _, err := vpnIP(ctx, namespace, "link", "add", g.Tunnel, "type", "xfrm", "dev", g.Underlay, "if_id", strconv.Itoa(ipsecIfID)); err != nil {
		return err
	}
	if _, err := vpnIP(ctx, namespace, "link", "set", "dev", g.Tunnel, "up"); err != nil {
		return err
	}
	for _, prefix := range g.RemotePrefixes {
		if _, err := vpnIP(ctx, namespace, "-4", "route", "add", prefix.String(), "dev", g.Tunnel, "proto", vpnRouteMarker); err != nil {
			return err
		}
	}
	forwarding := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
	if err := forwarding.Run(); err != nil {
		return fmt.Errorf("enable IPsec namespace forwarding: %w", err)
	}
	configuration := g.configuration(secret)
	defer clear(configuration)
	if err := g.applyIPsecRules(ctx, namespace, true); err != nil {
		return err
	}
	if err := g.load(ctx, namespace, configuration); err != nil {
		return err
	}
	return g.RefreshLease(ctx, namespace)
}

// Remove closes forwarding, clears the isolated daemon's configuration and
// withdraws the owned XFRM interface and its routes.
func (g IPsecGateway) Remove(ctx context.Context, namespace string) error {
	if err := g.validate(namespace); err != nil {
		return err
	}
	if err := g.applyIPsecRules(ctx, namespace, false); err != nil {
		return err
	}
	if err := g.load(ctx, namespace, []byte("connections {}\nsecrets {}\n")); err != nil {
		return err
	}
	associations, err := g.associations(ctx, namespace)
	if err != nil {
		return err
	}
	if len(associations) != 0 {
		if _, err := g.swanctl(ctx, namespace, "--terminate", "--ike", ipsecIKE, "--force", "--timeout", "3"); err != nil {
			return fmt.Errorf("terminate IPsec security associations: %w", err)
		}
		remaining, err := g.associations(ctx, namespace)
		if err != nil {
			return err
		}
		if len(remaining) != 0 {
			return errors.New("IPsec security associations are still active")
		}
	}
	exists, err := g.tunnelPresent(ctx, namespace)
	if err != nil || !exists {
		return err
	}
	_, err = vpnIP(ctx, namespace, "link", "delete", "dev", g.Tunnel)
	return err
}

// Connected requires confirmed kernel forwarding and installed IPsec state.
func (g IPsecGateway) Connected(ctx context.Context, namespace string) (bool, error) {
	if err := g.validate(namespace); err != nil {
		return false, err
	}
	up, err := g.tunnelPresent(ctx, namespace)
	if err != nil || !up {
		return false, err
	}
	if live, err := g.forwardingLive(ctx, namespace); err != nil || !live {
		return false, err
	}
	associations, err := g.associations(ctx, namespace)
	if err != nil {
		return false, err
	}
	for _, line := range associations {
		if strings.Contains(line, "state=ESTABLISHED ") && strings.Contains(line, "name="+ipsecChild+" ") &&
			strings.Contains(line, "state=INSTALLED ") {
			return true, nil
		}
	}
	return false, nil
}

func (g IPsecGateway) forwardingLive(ctx context.Context, namespace string) (bool, error) {
	command := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace, "/usr/sbin/nft", "-j", "list", "table", "inet", ipsecTable)
	output, err := command.Output()
	if err != nil {
		return false, fmt.Errorf("inspect the IPsec forwarding lease: %w", err)
	}
	var rules struct {
		Objects []struct {
			Set struct {
				Name     string          `json:"name"`
				Elements json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &rules); err != nil {
		return false, fmt.Errorf("decode the IPsec forwarding lease: %w", err)
	}
	for _, object := range rules.Objects {
		if object.Set.Name != "live_tunnel" || len(object.Set.Elements) == 0 {
			continue
		}
		var elements []struct {
			Element struct {
				Interface string `json:"val"`
				Expires   int    `json:"expires"`
			} `json:"elem"`
		}
		if err := json.Unmarshal(object.Set.Elements, &elements); err != nil {
			return false, fmt.Errorf("decode timed IPsec forwarding elements: %w", err)
		}
		for _, entry := range elements {
			if entry.Element.Interface == g.Tunnel && entry.Element.Expires > 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// RefreshLease keeps packet forwarding enabled while the regional assignment
// is available. The tunnel otherwise stops forwarding in the kernel.
func (g IPsecGateway) RefreshLease(ctx context.Context, namespace string) error {
	if err := g.validate(namespace); err != nil {
		return err
	}
	policy := nftPolicy{table: ipsecTable}
	policy.command("flush set inet %s live_tunnel", policy.table)
	policy.command("add element inet %s live_tunnel { %q }", policy.table, g.Tunnel)
	return applyNftRules(ctx, namespace, policy.script.String())
}

func (g IPsecGateway) applyIPsecRules(ctx context.Context, namespace string, active bool) error {
	policy := nftPolicy{table: ipsecTable}
	policy.command("destroy table inet %s", policy.table)
	policy.command("add table inet %s", policy.table)
	policy.command("add chain inet %s forwarded { type filter hook forward priority filter; policy drop; }", policy.table)
	policy.command("add chain inet %s local_in { type filter hook input priority filter; policy drop; }", policy.table)
	policy.rule("local_in", `iifname "lo" accept`)
	if active {
		policy.prefixSet("local_networks", g.LocalPrefixes)
		policy.prefixSet("remote_networks", g.RemotePrefixes)
		policy.prefixSet("protected_networks", g.ProtectedPrefixes)
		policy.command("add set inet %s live_tunnel { type ifname; flags timeout; timeout 8s; }", policy.table)
		policy.rule("forwarded", "ip saddr @protected_networks counter drop")
		policy.rule("forwarded", "ip daddr @protected_networks counter drop")
		policy.rule("forwarded", fmt.Sprintf("iifname @live_tunnel oifname %q ip saddr @remote_networks ip daddr @local_networks counter accept", g.Inside))
		policy.rule("forwarded", fmt.Sprintf("iifname %q oifname @live_tunnel ip saddr @local_networks ip daddr @remote_networks counter accept", g.Inside))
		peer := fmt.Sprintf("iifname %q ip saddr %s ip daddr %s", g.Underlay, g.RemoteEndpoint, g.LocalEndpoint)
		policy.rule("local_in", peer+" udp dport { 500, 4500 } counter accept")
		policy.rule("local_in", peer+" ip protocol esp counter accept")
	}
	return applyNftRules(ctx, namespace, policy.script.String())
}

func (g IPsecGateway) swanctl(ctx context.Context, namespace string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "/usr/bin/ip", append([]string{"netns", "exec", namespace, "/usr/sbin/swanctl"}, args...)...)
	command.Args = append(command.Args, "--uri", "unix://"+g.Socket)
	return command.CombinedOutput()
}

func (g IPsecGateway) load(ctx context.Context, namespace string, configuration []byte) (err error) {
	root := filepath.Dir(g.Socket)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("the IPsec daemon requires a private runtime directory")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(root, &filesystem); err != nil || filesystem.Type != unix.TMPFS_MAGIC {
		return errors.New("the IPsec runtime directory must use tmpfs")
	}
	dir, err := os.MkdirTemp(root, "swanctl-")
	if err != nil {
		return err
	}
	defer func() {
		if cleanup := os.RemoveAll(dir); cleanup != nil {
			err = errors.Join(err, fmt.Errorf("clear staged IPsec configuration: %w", cleanup))
		}
	}()
	path := filepath.Join(dir, "swanctl.conf")
	if err := os.WriteFile(path, configuration, 0600); err != nil {
		return err
	}
	// swanctl output can contain credential material. Keep it out of errors.
	if _, err := g.swanctl(ctx, namespace, "--load-all", "--clear", "--noprompt", "--file", path); err != nil {
		return fmt.Errorf("load isolated IPsec configuration: %w", err)
	}
	return nil
}

func (g IPsecGateway) associations(ctx context.Context, namespace string) ([]string, error) {
	output, err := g.swanctl(ctx, namespace, "--list-sas", "--ike", ipsecIKE, "--raw")
	if err != nil {
		return nil, fmt.Errorf("inspect IPsec security associations: %w", err)
	}
	var associations []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.Contains(line, ipsecIKE+" {") {
			associations = append(associations, line)
		}
	}
	return associations, nil
}

func (g IPsecGateway) verifyUnderlay(ctx context.Context, namespace string) error {
	output, err := vpnIP(ctx, namespace, "-j", "-4", "route", "get", g.RemoteEndpoint.String(), "from", g.LocalEndpoint.String())
	if err != nil {
		return err
	}
	var routes []struct{ Dev string }
	if json.Unmarshal(output, &routes) != nil || len(routes) != 1 || routes[0].Dev != g.Underlay {
		return errors.New("the IPsec peer must be reachable through the expected underlay interface")
	}
	return nil
}

func (g IPsecGateway) tunnelPresent(ctx context.Context, namespace string) (bool, error) {
	output, err := vpnIP(ctx, namespace, "-j", "-d", "link", "show")
	if err != nil {
		return false, err
	}
	var links []struct {
		Name string `json:"ifname"`
		Info struct {
			Kind string `json:"info_kind"`
			Data struct {
				ID string `json:"if_id"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(output, &links); err != nil {
		return false, err
	}
	for _, link := range links {
		if link.Name == g.Tunnel {
			if id, err := strconv.ParseUint(link.Info.Data.ID, 0, 32); link.Info.Kind != "xfrm" || err != nil || id != ipsecIfID {
				return false, errors.New("the IPsec interface name belongs to another link")
			}
			return true, nil
		}
	}
	return false, nil
}

func (g IPsecGateway) configuration(secret []byte) []byte {
	selectors := func(prefixes []netip.Prefix) string {
		values := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			values = append(values, prefix.String())
		}
		return strings.Join(values, ",")
	}
	var conf bytes.Buffer
	fmt.Fprintf(&conf, `connections {
  %s {
    version = 2
    local_addrs = %s
    remote_addrs = %s
    proposals = aes256-sha256-modp2048
    dpd_delay = 10s
    local {
      auth = psk
      id = %s
    }
    remote {
      auth = psk
      id = %s
    }
    children {
      %s {
        local_ts = %s
        remote_ts = %s
        esp_proposals = aes256-sha256-modp2048
        if_id_in = %d
        if_id_out = %d
        start_action = start
        dpd_action = restart
      }
    }
  }
}
secrets {
  ike-ocean {
    id-local = %s
    id-remote = %s
    secret = 0x`, ipsecIKE, g.LocalEndpoint, g.RemoteEndpoint, g.LocalEndpoint, g.RemoteEndpoint,
		ipsecChild, selectors(g.LocalPrefixes), selectors(g.RemotePrefixes), ipsecIfID, ipsecIfID, g.LocalEndpoint, g.RemoteEndpoint)
	encoded := make([]byte, hex.EncodedLen(len(secret)))
	hex.Encode(encoded, secret)
	conf.Write(encoded)
	clear(encoded)
	conf.WriteString("\n  }\n}\n")
	return conf.Bytes()
}
