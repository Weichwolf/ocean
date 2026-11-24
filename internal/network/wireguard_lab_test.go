//go:build e2e

package network

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRoutedWireGuard(t *testing.T) {
	if os.Getenv("OCEAN_E2E_WIREGUARD") != "1" {
		t.Skip("requires an isolated Debian guest with root, WireGuard, nftables, and ping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	run := func(command string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %q: %v: %s", command, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	stamp := strconv.Itoa(os.Getpid())
	cloud, site := "wgcloud"+stamp, "wgsite"+stamp
	workload, customer := "wgwork"+stamp, "wgcust"+stamp
	for _, namespace := range []string{cloud, site, workload, customer} {
		run("ip", "netns", "add", namespace)
		t.Cleanup(func() {
			cleanup, clear := context.WithTimeout(context.Background(), 5*time.Second)
			defer clear()
			if out, err := exec.CommandContext(cleanup, "ip", "netns", "delete", namespace).CombinedOutput(); err != nil {
				t.Errorf("delete namespace %s: %v: %s", namespace, err, out)
			}
		})
		run("ip", "-n", namespace, "link", "set", "lo", "up")
	}
	attach := func(leftNS, left, leftAddr, rightNS, right, rightAddr string) {
		t.Helper()
		run("ip", "-n", leftNS, "link", "add", left, "type", "veth", "peer", "name", right, "netns", rightNS)
		run("ip", "-n", leftNS, "-4", "address", "add", leftAddr, "dev", left)
		run("ip", "-n", rightNS, "-4", "address", "add", rightAddr, "dev", right)
		run("ip", "-n", leftNS, "link", "set", left, "up")
		run("ip", "-n", rightNS, "link", "set", right, "up")
	}
	attach(cloud, "wan0", "198.18.24.1/30", site, "wan0", "198.18.24.2/30")
	attach(cloud, "lan0", "10.91.1.1/24", workload, "eth0", "10.91.1.4/24")
	attach(site, "lan0", "10.92.1.1/24", customer, "eth0", "10.92.1.4/24")
	run("ip", "-n", workload, "route", "add", "default", "via", "10.91.1.1")
	run("ip", "-n", customer, "route", "add", "default", "via", "10.92.1.1")
	run("ip", "-n", customer, "addr", "add", "10.92.2.4/32", "dev", "lo")
	run("ip", "-n", workload, "addr", "add", "10.231.1.11/32", "dev", "lo")
	run("ip", "-n", cloud, "route", "add", "10.231.1.11/32", "via", "10.91.1.4")

	keys := t.TempDir()
	newKey := func(name string) (string, string) {
		t.Helper()
		private, err := exec.CommandContext(ctx, "wg", "genkey").Output()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "wg", "pubkey")
		command.Stdin = bytes.NewReader(private)
		public, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(keys, name)
		if err := os.WriteFile(path, private, 0600); err != nil {
			t.Fatal(err)
		}
		return path, strings.TrimSpace(string(public))
	}
	cloudKey, cloudPublic := newKey("cloud.key")
	siteKey, sitePublic := newKey("site.key")
	prefix := netip.MustParsePrefix
	cloudConfig := WireGuardGateway{
		Tunnel: "wg0", Underlay: "wan0", Inside: "lan0", ListenPort: 51820,
		LocalTunnel: prefix("10.99.1.0/31"), PeerTunnel: netip.MustParseAddr("10.99.1.1"),
		PeerEndpoint:   netip.MustParseAddrPort("198.18.24.2:51820"),
		PrivateKeyFile: cloudKey, PeerPublicKey: sitePublic,
		LocalPrefixes: []netip.Prefix{prefix("10.91.1.0/24")}, RemotePrefixes: []netip.Prefix{prefix("10.92.1.0/24")},
		ProtectedPrefixes: []netip.Prefix{prefix("10.231.1.0/24")},
	}
	siteConfig := cloudConfig
	siteConfig.LocalTunnel, siteConfig.PeerTunnel = prefix("10.99.1.1/31"), netip.MustParseAddr("10.99.1.0")
	siteConfig.PeerEndpoint = netip.MustParseAddrPort("198.18.24.1:51820")
	siteConfig.PrivateKeyFile, siteConfig.PeerPublicKey = siteKey, cloudPublic
	siteConfig.LocalPrefixes, siteConfig.RemotePrefixes = cloudConfig.RemotePrefixes, cloudConfig.LocalPrefixes

	apply := func(namespace string, config WireGuardGateway) {
		t.Helper()
		if err := config.Apply(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}
	ping := func(namespace, source, dest string, allowed bool) {
		t.Helper()
		args := []string{"netns", "exec", namespace, "ping", "-n", "-c", "1", "-W", "2"}
		if source != "" {
			args = append(args, "-I", source)
		}
		out, err := exec.CommandContext(ctx, "ip", append(args, dest)...).CombinedOutput()
		if (err == nil) != allowed {
			t.Fatalf("unexpected ping result from %s to %s: %v: %s", namespace, dest, err, out)
		}
	}
	apply(cloud, cloudConfig)
	apply(site, siteConfig)
	if err := siteConfig.Probe(ctx, site); err != nil {
		t.Fatal(err)
	}
	ping(customer, "", "10.91.1.4", true)
	ping(workload, "", "10.92.1.4", true)
	ping(customer, "10.92.2.4", "10.91.1.4", false)
	ping(workload, "", "10.231.1.11", true)
	ping(customer, "", "10.231.1.11", false)
	t.Log("WireGuard encrypted bidirectional traffic between approved networks and blocked unapproved and protected paths")

	apply(cloud, cloudConfig)
	ping(customer, "", "10.91.1.4", true)
	revised := cloudConfig
	revised.RemotePrefixes = []netip.Prefix{prefix("10.92.2.0/24")}
	apply(cloud, revised)
	if routes := run("ip", "-n", cloud, "-4", "route", "show", "dev", "wg0"); strings.Contains(routes, "10.92.1.0/24") ||
		!strings.Contains(routes, "10.92.2.0/24") {
		t.Fatalf("the updated gateway retained an obsolete route: %s", routes)
	}
	ping(customer, "", "10.91.1.4", false)
	apply(cloud, cloudConfig)
	ping(customer, "", "10.91.1.4", true)

	broken := cloudConfig
	broken.PrivateKeyFile = filepath.Join(keys, "missing.key")
	if err := broken.Apply(ctx, cloud); err == nil {
		t.Fatal("a gateway with a missing private key was accepted")
	}
	ping(customer, "", "10.91.1.4", false)
	leased := cloudConfig
	leased.LeaseControlled = true
	apply(cloud, leased)
	ping(customer, "", "10.91.1.4", true)
	time.Sleep(9 * time.Second)
	ping(customer, "", "10.91.1.4", false)
	if err := leased.RefreshLease(ctx, cloud); err != nil {
		t.Fatal(err)
	}
	ping(customer, "", "10.91.1.4", true)
	run("ip", "-n", cloud, "link", "delete", "dev", "lan0")
	for range 2 {
		if err := cloudConfig.Remove(ctx, cloud); err != nil {
			t.Fatal(err)
		}
	}
	if links := run("ip", "-n", cloud, "-brief", "link", "show"); strings.Contains(links, "wg0") {
		t.Fatal("removing the gateway left its WireGuard interface behind")
	}
	if err := siteConfig.Probe(ctx, site); err == nil {
		t.Fatal("the probe reported a removed gateway as reachable")
	}
	ping(customer, "", "10.91.1.4", false)
	t.Log("WireGuard retries preserved reachability, prefix changes withdrew old routes, and expiry, failed apply, and removal blocked forwarding")
}
