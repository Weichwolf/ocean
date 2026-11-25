package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/qemu"
	"github.com/Weichwolf/ocean/internal/workload"
)

const vmTap = "ocean0"

func vmNamespace(id string) string {
	return fmt.Sprintf("ov%x", sha256.Sum256([]byte(id)))[:15]
}

func (w vmWorker) firewall(task workload.VMTask) (network.WorkloadFirewall, error) {
	if task.Network == nil {
		return network.WorkloadFirewall{}, errors.New("a running VM requires a private subnet policy")
	}
	policy, _, _, _, err := w.network.planContainerNetwork(workload.Task{Address: task.Network.Address.Addr(), Policy: task.Network})
	policy.Interface = vmTap
	policy.DHCPServer = task.Network.Gateway.Next()
	return policy, err
}

func (w vmWorker) prepareVMNetwork(ctx context.Context, task workload.VMTask) error {
	ns := vmNamespace(task.MachineID)
	if err := removeVMNetwork(ctx, ns); err != nil {
		return err
	}
	if err := callIP(ctx, "netns", "add", ns); err != nil {
		return err
	}
	if err := network.BlockWorkload(ctx, ns, vmTap); err != nil {
		return err
	}
	policy, err := w.firewall(task)
	if err != nil {
		return err
	}
	address, subnet, gateway := policy.Address, task.Network.Address.Masked(), task.Network.Gateway
	octets := address.As4()
	fabricMAC := fmt.Sprintf("02:6f:%02x:%02x:%02x:%02x", octets[0], octets[1], octets[2], octets[3])
	commands := [][]string{
		{"link", "add", "link", w.network.PrivateFabric, "name", containerFabricLink, "address", fabricMAC, "netns", ns, "type", "macvlan", "mode", "bridge"},
		{"-n", ns, "tuntap", "add", "dev", vmTap, "mode", "tap", "user", w.account.Username},
		// The next reserved address serves DHCP locally. The subnet gateway
		// remains a remote next hop on the private fabric.
		{"-n", ns, "addr", "add", netip.PrefixFrom(policy.DHCPServer, subnet.Bits()).String(), "dev", vmTap, "noprefixroute"},
		{"-n", ns, "link", "set", "dev", vmTap, "up"},
		{"-n", ns, "link", "set", "dev", containerFabricLink, "up"},
		{"netns", "exec", ns, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.arp_ignore=1",
			"net.ipv4.conf.fabric0.proxy_arp=1", "net.ipv4.conf." + vmTap + ".proxy_arp=1", "net.ipv4.conf.all.send_redirects=0",
			"net.ipv4.conf.fabric0.send_redirects=0", "net.ipv4.conf." + vmTap + ".send_redirects=0"},
		// Use the guest address for fabric ARP only after bringing up the
		// interface. Link-up would otherwise re-create the kernel local route.
		{"-n", ns, "addr", "add", address.String() + "/32", "dev", containerFabricLink, "noprefixroute"},
		{"-n", ns, "route", "delete", "local", address.String() + "/32", "dev", containerFabricLink, "table", "local"},
		{"-n", ns, "route", "replace", subnet.String(), "dev", containerFabricLink},
		{"-n", ns, "route", "replace", address.String() + "/32", "dev", vmTap},
		{"-n", ns, "route", "replace", "default", "via", gateway.String(), "dev", containerFabricLink, "onlink"},
		{"-n", ns, "neigh", "add", "proxy", address.String(), "dev", containerFabricLink},
	}
	for _, args := range commands {
		if err := callIP(ctx, args...); err != nil {
			return err
		}
	}
	if err := policy.Apply(ctx, ns); err != nil {
		return err
	}
	return w.startVMDHCP(ctx, ns, task, subnet)
}

func (w vmWorker) startVMDHCP(ctx context.Context, ns string, task workload.VMTask, subnet netip.Prefix) error {
	mask := ^uint32(0) << (32 - subnet.Bits())
	netmask := netip.AddrFrom4([4]byte{byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask)})
	address, gateway := task.Network.Address.Addr().String(), task.Network.Gateway.String()
	args := []string{"netns", "exec", ns, "/usr/sbin/dnsmasq", "--conf-file=/dev/null", "--port=0",
		"--interface=" + vmTap, "--bind-interfaces", "--no-ping", "--dhcp-authoritative", "--leasefile-ro", "--pid-file=",
		"--dhcp-range=" + subnet.Addr().String() + ",static," + netmask.String(), "--dhcp-host=" + qemu.MAC(task.MachineID) + ",id:*," + address,
		"--dhcp-option=option:router," + gateway, "--dhcp-option=option:dns-server"}
	if len(w.DNS) != 0 {
		servers := make([]string, 0, len(w.DNS))
		for _, server := range w.DNS {
			servers = append(servers, server.String())
		}
		args[len(args)-1] += "," + strings.Join(servers, ",")
	}
	return callIP(ctx, args...)
}

func removeVMNetwork(ctx context.Context, namespace string) error {
	namespaceInfo, err := os.Stat(filepath.Join("/run/netns", namespace))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := network.BlockWorkload(ctx, namespace, vmTap); err != nil {
		return err
	}
	// The network namespace is used only by the VM and its DHCP server. A
	// live or unidentified process blocks deletion of the named namespace.
	data, err := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "pids", namespace).Output()
	if err != nil {
		return err
	}
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 1 {
			return errors.New("invalid process in VM network namespace")
		}
		if err := stopVMDHCP(pid, namespaceInfo); err != nil {
			return err
		}
	}
	// Release the stable fabric MAC before dropping the namespace name.
	// A terminating DHCP process may still hold the namespace open.
	data, err = exec.CommandContext(ctx, "/usr/bin/ip", "-n", namespace, "-j", "link", "show").Output()
	if err != nil {
		return fmt.Errorf("list VM interfaces: %w", err)
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return err
	}
	for _, link := range links {
		if link.Name == containerFabricLink {
			if err := callIP(ctx, "-n", namespace, "link", "delete", "dev", containerFabricLink); err != nil {
				return err
			}
			break
		}
	}
	return callIP(ctx, "netns", "delete", namespace)
}

func stopVMDHCP(pid int, namespace os.FileInfo) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer func() { _ = process.Release() }()
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	attached, err := os.Stat(filepath.Join(proc, "ns/net"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(namespace, attached) {
		return nil
	}
	exe, err := os.Readlink(filepath.Join(proc, "exe"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || exe != "/usr/sbin/dnsmasq" {
		return errors.New("VM network namespace has an active workload")
	}
	if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func waitVMNetwork(ctx context.Context, task workload.VMTask) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		probe := exec.CommandContext(ctx, "/usr/bin/ip", "netns", "exec", vmNamespace(task.MachineID), "/usr/bin/arping", "-I", vmTap, "-c", "1", "-w", "2", task.Network.Address.Addr().String())
		output, err := probe.CombinedOutput()
		if err == nil && strings.Contains(strings.ToLower(string(output)), "["+qemu.MAC(task.MachineID)+"]") {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("VM private interface did not answer the assigned address and MAC probe")
		case <-time.After(time.Second):
		}
	}
}
