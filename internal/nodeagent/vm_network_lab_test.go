//go:build e2e

package nodeagent

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
)

func TestVMNetworkOnDebianWorker(t *testing.T) {
	if os.Getenv("OCEAN_E2E_VM_TAP") == "" {
		t.Skip("requires a disposable Debian VM worker with private work0 fabric and curl")
	}
	account, err := user.Lookup(vmAccount)
	if err != nil {
		t.Fatal(err)
	}
	task := workload.VMTask{MachineID: "88a30278-9f37-4e9e-97b7-8df50026d4d0", Network: &network.SubnetPolicy{
		Revision: 1, VNetID: "isolated-lab", Prefixes: []string{"10.232.1.160/28"},
		Address: netip.MustParsePrefix("10.232.1.164/28"), Gateway: netip.MustParseAddr("10.232.1.161"),
	}}
	w := vmWorker{account: account, network: containerNetworkConfig{PrivateFabric: "work0", ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.231.0.0/16")}}}
	ns := vmNamespace(task.MachineID)
	if _, err := os.Stat(filepath.Join("/run/netns", ns)); !os.IsNotExist(err) {
		t.Fatal("disposable VM network test namespace must be absent at entry")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := removeVMNetwork(ctx, ns); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	if err := w.prepareVMNetwork(ctx, task); err != nil {
		t.Fatal(err)
	}
	route, err := exec.CommandContext(ctx, "/usr/bin/ip", "-n", ns, "route", "get", task.Network.Address.Addr().String(),
		"from", "10.232.1.165", "iif", containerFabricLink).CombinedOutput()
	if err != nil || !strings.Contains(string(route), "dev "+vmTap+" ") || strings.HasPrefix(string(route), "local ") {
		t.Fatalf("private fabric packets must be routed to the guest TAP: %v: %s", err, route)
	}
	rules, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", ns, "/usr/sbin/nft", "list", "ruleset").CombinedOutput()
	if err != nil || !strings.Contains(string(rules), "udp sport 68 udp dport 67") || !strings.Contains(string(rules), "protected_networks") {
		t.Fatalf("the private VM policy or its local DHCP exception is missing: %v: %s", err, rules)
	}
	probeVMOutsideVNet(t, ctx, ns)
	processes, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "pids", ns).Output()
	pids := strings.Fields(string(processes))
	if err != nil || len(pids) != 1 {
		t.Fatalf("expected one DHCP process in the private VM namespace: %v: %s", err, processes)
	}
	if err := removeVMNetwork(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/run/netns", ns)); !os.IsNotExist(err) {
		t.Fatal("VM network cleanup left the named namespace behind")
	}
	for {
		_, err := os.Stat(filepath.Join("/proc", pids[0], "ns/net"))
		if os.IsNotExist(err) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("VM network cleanup left the DHCP process running")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func probeVMOutsideVNet(t *testing.T, ctx context.Context, vm string) {
	t.Helper()
	const peer = "ov-lab-foreign"
	if err := callIP(ctx, "netns", "add", peer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err := callIP(cleanup, "netns", "delete", peer); err != nil {
			t.Error(err)
		}
	})
	for _, args := range [][]string{
		{"link", "add", "link", "work0", "name", "alien0", "netns", peer, "type", "macvlan", "mode", "bridge"},
		{"-n", peer, "addr", "add", "10.232.1.180/32", "dev", "alien0"},
		{"-n", peer, "link", "set", "dev", "alien0", "up"},
		{"-n", peer, "route", "add", "10.232.1.164/32", "dev", "alien0", "src", "10.232.1.180"},
		// Address the VM's fabric MAC so this exercise reaches its L3 policy.
		{"-n", peer, "neigh", "replace", "10.232.1.164", "lladdr", "02:6f:0a:e8:01:a4", "nud", "permanent", "dev", "alien0"},
	} {
		if err := callIP(ctx, args...); err != nil {
			t.Fatal(err)
		}
	}
	before := vmIngressDrops(t, ctx, vm)
	output, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", peer, "/usr/bin/curl", "--noproxy", "*", "--connect-timeout", "1",
		"--max-time", "2", "-sS", "telnet://10.232.1.164:445").CombinedOutput()
	if err == nil {
		t.Fatalf("a peer outside the VM VNet reached the workload listener: %s", output)
	}
	if after := vmIngressDrops(t, ctx, vm); after <= before {
		t.Fatalf("the VM's ingress policy did not account for the denied packets: %d → %d: %s", before, after, output)
	}
}

func vmIngressDrops(t *testing.T, ctx context.Context, namespace string) int64 {
	t.Helper()
	output, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", namespace, "/usr/sbin/nft", "list", "chain", "inet", "ocean_6f6365616e30", "ingress").CombinedOutput()
	if err != nil {
		t.Fatalf("read VM ingress policy: %v: %s", err, output)
	}
	for line := range strings.Lines(string(output)) {
		parts := strings.Fields(line)
		if len(parts) == 6 && parts[0] == "counter" && parts[1] == "packets" && parts[3] == "bytes" && parts[5] == "drop" {
			count, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return count
		}
	}
	t.Fatalf("no default drop counter in the VM ingress policy: %s", output)
	return 0
}
