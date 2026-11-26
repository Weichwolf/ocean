//go:build e2e

package network

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRoutedIPsec(t *testing.T) {
	if os.Getenv("OCEAN_E2E_IPSEC_GATEWAY") != "1" {
		t.Skip("requires an isolated Debian guest with root, strongSwan, nftables and ping")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
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
	cloud, site, workload, customer := "isc"+stamp, "iss"+stamp, "isw"+stamp, "isu"+stamp
	for _, namespace := range []string{cloud, site, workload, customer} {
		run("ip", "netns", "add", namespace)
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if out, err := exec.CommandContext(cleanup, "ip", "netns", "delete", namespace).CombinedOutput(); err != nil {
				t.Errorf("delete disposable namespace %s: %v: %s", namespace, err, out)
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
	attach(cloud, "wan0", "198.18.24.9/32", site, "wan0", "198.18.24.2/30")
	run("ip", "-n", cloud, "route", "add", "198.18.24.2/32", "dev", "wan0", "scope", "link")
	attach(cloud, "lan0", "10.91.1.1/24", workload, "eth0", "10.91.1.4/24")
	attach(site, "lan0", "10.92.1.1/24", customer, "eth0", "10.92.1.4/24")
	run("ip", "-n", workload, "route", "add", "default", "via", "10.91.1.1")
	run("ip", "-n", customer, "route", "add", "default", "via", "10.92.1.1")
	run("ip", "-n", customer, "addr", "add", "10.92.2.4/32", "dev", "lo")
	run("ip", "-n", workload, "addr", "add", "10.231.1.11/32", "dev", "lo")
	run("ip", "-n", cloud, "route", "add", "10.231.1.11/32", "via", "10.91.1.4")

	prefix := netip.MustParsePrefix
	cloudSide := IPsecGateway{Tunnel: "xfrm42", Underlay: "wan0", Inside: "lan0",
		LocalEndpoint: netip.MustParseAddr("198.18.24.1"), RemoteEndpoint: netip.MustParseAddr("198.18.24.2"),
		LocalPrefixes: []netip.Prefix{prefix("10.91.1.0/24")}, RemotePrefixes: []netip.Prefix{prefix("10.92.1.0/24")},
		ProtectedPrefixes: []netip.Prefix{prefix("10.231.1.0/24")}, Socket: startIPsecLabDaemon(t, ctx, cloud)}
	siteSide := cloudSide
	siteSide.LocalEndpoint, siteSide.RemoteEndpoint = cloudSide.RemoteEndpoint, cloudSide.LocalEndpoint
	siteSide.LocalPrefixes, siteSide.RemotePrefixes = cloudSide.RemotePrefixes, cloudSide.LocalPrefixes
	siteSide.Socket = startIPsecLabDaemon(t, ctx, site)
	if err := cloudSide.SetPublicAddress(ctx, cloud, true); err != nil {
		t.Fatal(err)
	}
	if err := cloudSide.CheckAttachment(ctx, cloud, prefix("10.91.1.1/24")); err != nil {
		t.Fatal(err)
	}
	key, wrong := make([]byte, 32), make([]byte, 32)
	rand.Read(key)
	rand.Read(wrong)
	defer clear(key)
	defer clear(wrong)
	apply := func(gateway IPsecGateway, namespace string, secret []byte) {
		t.Helper()
		if err := gateway.Apply(ctx, namespace, secret); err != nil {
			t.Fatal(err)
		}
	}
	ping := func(namespace, source, destination string, allowed bool) {
		t.Helper()
		args := []string{"netns", "exec", namespace, "ping", "-n", "-c", "1", "-W", "1"}
		if source != "" {
			args = append(args, "-I", source)
		}
		out, err := exec.CommandContext(ctx, "ip", append(args, destination)...).CombinedOutput()
		var exit *exec.ExitError
		if allowed && err != nil || !allowed && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			t.Fatalf("expected reachability %t from %s to %s: %v: %s", allowed, namespace, destination, err, out)
		}
	}
	apply(cloudSide, cloud, key)
	apply(siteSide, site, wrong)
	ping(customer, "", "10.91.1.4", false)
	if active, err := cloudSide.Connected(ctx, cloud); err != nil || active {
		t.Fatalf("mismatched credentials established a tunnel: %v", err)
	}

	started := time.Now()
	apply(siteSide, site, key)
	waitIPsecLab(t, ctx, 18*time.Second, "both IKEv2 CHILD SAs", func() bool {
		for namespace, gateway := range map[string]IPsecGateway{cloud: cloudSide, site: siteSide} {
			if err := gateway.RefreshLease(ctx, namespace); err != nil {
				t.Fatal(err)
			}
			active, err := gateway.Connected(ctx, namespace)
			if err != nil {
				t.Fatal(err)
			}
			if !active {
				return false
			}
		}
		return true
	})
	ping(customer, "", "10.91.1.4", true)
	ping(workload, "", "10.92.1.4", true)
	t.Logf("Both peers established working IKEv2 and CHILD SAs within %d ms after applying the shared key.", time.Since(started).Milliseconds())
	ping(customer, "10.92.2.4", "10.91.1.4", false)
	ping(customer, "", "10.231.1.11", false)
	t.Log("Bidirectional tenant traffic passed. The mismatched key, foreign source and protected destination were blocked.")

	// Both peers lose their timed forwarding permission without any worker.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(9 * time.Second):
	}
	for namespace, gateway := range map[string]IPsecGateway{cloud: cloudSide, site: siteSide} {
		if active, err := gateway.Connected(ctx, namespace); err != nil || active {
			t.Fatalf("an expired forwarding lease was reported as connected: %v", err)
		}
	}
	ping(customer, "", "10.91.1.4", false)
	if err := cloudSide.RefreshLease(ctx, cloud); err != nil {
		t.Fatal(err)
	}
	ping(customer, "", "10.91.1.4", false)
	if err := siteSide.RefreshLease(ctx, site); err != nil {
		t.Fatal(err)
	}
	ping(customer, "", "10.91.1.4", true)
	for range 2 {
		if err := cloudSide.Remove(ctx, cloud); err != nil {
			t.Fatal(err)
		}
	}
	if routes := run("ip", "-n", cloud, "-4", "route", "show", "proto", vpnRouteMarker); routes != "" {
		t.Fatalf("IPsec removal left a managed route: %s", routes)
	}
	if exists, err := cloudSide.tunnelPresent(ctx, cloud); err != nil || exists {
		t.Fatalf("IPsec removal left a tunnel interface: %v", err)
	}
	if err := cloudSide.SetPublicAddress(ctx, cloud, false); err != nil {
		t.Fatal(err)
	}
	if err := cloudSide.CheckAttachment(ctx, cloud, prefix("10.91.1.1/24")); err == nil {
		t.Fatal("IPsec removal left its published address attached")
	}
	ping(customer, "", "10.91.1.4", false)
	t.Log("Kernel lease expiry blocked forwarding, renewal restored traffic, and repeatable removal withdrew the association, route, XFRM interface and public IPv4 address.")
}

func startIPsecLabDaemon(t *testing.T, ctx context.Context, namespace string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "ocean-ipsec-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	socket, config := filepath.Join(dir, "vici.sock"), filepath.Join(dir, "strongswan.conf")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(`charon {
  load = random nonce openssl aes sha2 hmac kdf kernel-netlink socket-default vici
  install_routes = no
  plugins {
    vici {
      socket = "unix://%s"
    }
  }
}
`, socket)), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(dir, "charon.log"), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	child, stop := context.WithCancel(ctx)
	command := exec.CommandContext(child, "/usr/bin/ip", "netns", "exec", namespace,
		"/usr/bin/unshare", "--mount", "--propagation", "private", "/bin/sh", "-ceu",
		"mount -t tmpfs -o mode=755 tmpfs /run\nexec /usr/lib/ipsec/charon")
	command.Env = append(os.Environ(), "STRONGSWAN_CONF="+config)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		stop()
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		_ = command.Wait()
		if err := log.Close(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			data, err := os.ReadFile(log.Name())
			if err == nil {
				t.Logf("charon %s:\n%s", namespace, data[max(0, len(data)-9000):])
			}
		}
	})
	waitIPsecLab(t, ctx, 8*time.Second, "the private VICI socket", func() bool {
		info, err := os.Stat(socket)
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
	return socket
}

func waitIPsecLab(t *testing.T, ctx context.Context, timeout time.Duration, name string, check func() bool) {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for wait.Err() == nil {
		if check() {
			return
		}
		select {
		case <-wait.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s: %v", name, wait.Err())
}
