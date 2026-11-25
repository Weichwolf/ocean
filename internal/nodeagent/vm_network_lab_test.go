//go:build e2e

package nodeagent

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
)

func TestVMNetworkOnDebianWorker(t *testing.T) {
	if os.Getenv("OCEAN_E2E_VM_TAP") == "" {
		t.Skip("requires a disposable Debian VM worker with private work0 fabric")
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
	rules, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", ns, "/usr/sbin/nft", "list", "ruleset").CombinedOutput()
	if err != nil || !strings.Contains(string(rules), "udp sport 68 udp dport 67") || !strings.Contains(string(rules), "protected_networks") {
		t.Fatalf("the private VM policy or its local DHCP exception is missing: %v: %s", err, rules)
	}
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
