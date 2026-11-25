package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
)

const (
	containerRouterLink = "workload0"
	containerFabricLink = "fabric0"
	containerLink       = "ocean0"
	containerNextHop    = "169.254.255.1"
)

type containerNetworkConfig struct {
	PrivateFabric     string         `json:"privateFabric"`
	PublicFabric      string         `json:"publicFabric"`
	PublicPrefixes    []netip.Prefix `json:"publicPrefixes"`
	PublicGateway     netip.Addr     `json:"publicGateway"`
	ProtectedPrefixes []netip.Prefix `json:"protectedPrefixes"`
	InternetPrefixes  []netip.Prefix `json:"internetPrefixes"`
}

type containerLinkState struct {
	process int
	policy  network.WorkloadFirewall
}

func (c containerNetworkConfig) validate() error {
	if !network.ValidRoutingLink(c.PrivateFabric) || len(c.ProtectedPrefixes) == 0 ||
		(c.PublicFabric == "") != (len(c.PublicPrefixes) == 0) || c.PublicFabric != "" && !network.ValidRoutingLink(c.PublicFabric) {
		return errors.New("workload routing requires an operator-supplied fabric and management prefixes")
	}
	for _, prefixes := range [][]netip.Prefix{c.PublicPrefixes, c.ProtectedPrefixes, c.InternetPrefixes} {
		for _, prefix := range prefixes {
			if !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return errors.New("workload routing requires canonical IPv4 CIDRs")
			}
		}
	}
	if c.PublicGateway.IsValid() && !slices.ContainsFunc(c.PublicPrefixes, func(p netip.Prefix) bool { return p.Contains(c.PublicGateway) }) {
		return errors.New("the public gateway must be on the public fabric")
	}
	return nil
}

// RunContainerNetwork reconciles operator-owned bridges separately from the
// rootless runtime. Tenant processes never receive the router namespace.
func RunContainerNetwork(ctx context.Context, settingsPath, agentPath string, logger *slog.Logger) error {
	cfg, err := config.Load(settingsPath, containerNetworkConfig{})
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	account, err := user.Lookup("ocean-agent")
	if err != nil {
		return err
	}
	asWorker := func(ctx context.Context, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", append([]string{"-u", account.Username, "--", "/usr/bin/env",
			"XDG_RUNTIME_DIR=/run/user/" + account.Uid, "/usr/bin/podman"}, args...)...)
		cmd.Dir = account.HomeDir
		return cmd
	}
	if err := os.MkdirAll(workloadRuntimeDirectory, 0755); err != nil {
		return err
	}
	installed := make(map[string]containerLinkState)
	entries, err := os.ReadDir(workloadRuntimeDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if name, found := strings.CutSuffix(entry.Name(), ".network"); found && validRuntimeName(name) {
			installed[name] = containerLinkState{}
		}
	}
	availablePath := filepath.Join(workloadRuntimeDirectory, ".available")
	defer func() { _ = os.Remove(availablePath) }()
	ticker := time.NewTicker(650 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 4*time.Second)
		tasks, err := client.containerTasks(round, true)
		if err == nil {
			directories, directoryErr := client.directoryTasks(round)
			if directoryErr != nil && ctx.Err() == nil {
				logger.Warn("directory network assignments will retry", "error", directoryErr)
			}
			for _, directory := range directories {
				if !directory.NetworkUnavailable && directory.Network != nil {
					tasks = append(tasks, workload.Task{AssignmentID: directoryTaskID(directory), State: workload.Running,
						Address: directory.PrivateIPv4, Policy: directory.Network})
				}
			}
			err = cfg.syncContainerNetwork(round, tasks, installed, account.Uid, asWorker)
		}
		if err == nil {
			now := time.Now()
			if err = os.Chtimes(availablePath, now, now); errors.Is(err, os.ErrNotExist) {
				err = publishFile(availablePath, nil)
			}
		} else {
			_ = os.Remove(availablePath)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("container network reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var errorsSeen []error
	for name := range installed {
		errorsSeen = append(errorsSeen, removeContainerNetwork(shutdown, name))
	}
	return errors.Join(errorsSeen...)
}

func validRuntimeName(name string) bool {
	return strings.HasPrefix(name, "ocean-") && len(name) == len("ocean-")+32 && taskIdentityPattern.MatchString(name)
}

func (cfg containerNetworkConfig) syncContainerNetwork(ctx context.Context, tasks []workload.Task, installed map[string]containerLinkState,
	uid string, podman func(context.Context, ...string) *exec.Cmd) error {
	pinned := make(map[string]bool)
	var failures []error
	for _, task := range tasks {
		name := containerName(task.AssignmentID)
		if task.State != workload.Running {
			continue
		}
		process, exists, err := inspectContainer(ctx, name, podman)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !exists || !process.Running {
			continue
		}
		pinned[name] = true
		current := installed[name]
		setup := current.process != process.Pid || current.policy.Address != task.Address
		policy, fabric, prefixes, gateway, err := cfg.planContainerNetwork(task)
		if err != nil {
			failures = append(failures, err, removeContainerNetwork(ctx, name))
			delete(installed, name)
			continue
		}
		_, router := containerNamespaces(name)
		if setup {
			// Record the pending setup locally before starting mutating
			// commands, so any later reconcile can remove partial state.
			if err = removeContainerNetwork(ctx, name); err == nil {
				installed[name] = containerLinkState{}
				err = attachContainerNetwork(ctx, name, process.Pid, uid, task.Address, fabric, prefixes, gateway)
			}
		}
		if err == nil {
			if setup || !reflect.DeepEqual(current.policy, policy) {
				err = policy.Apply(ctx, router)
			} else if err = policy.Refresh(ctx, router); err != nil {
				err = policy.Apply(ctx, router)
			}
		}
		if err == nil {
			installed[name] = containerLinkState{process.Pid, policy}
			readyPath := filepath.Join(workloadRuntimeDirectory, name+".ready")
			if setup || !networkReady(name, process.Pid) {
				err = publishFile(readyPath, []byte(strconv.Itoa(process.Pid)))
				if err == nil {
					err = os.Chmod(readyPath, 0644)
				}
			} else {
				now := time.Now()
				err = os.Chtimes(readyPath, now, now)
			}
		}
		if err != nil {
			failures = append(failures, err, removeContainerNetwork(ctx, name))
		}
	}
	for name := range installed {
		if pinned[name] {
			continue
		}
		if err := removeContainerNetwork(ctx, name); err != nil {
			failures = append(failures, err)
		} else {
			delete(installed, name)
		}
	}
	return errors.Join(failures...)
}

func (c containerNetworkConfig) planContainerNetwork(task workload.Task) (network.WorkloadFirewall, string, []netip.Prefix, netip.Addr, error) {
	policy := network.WorkloadFirewall{Interface: containerRouterLink, Address: task.Address, ProtectedPrefixes: c.ProtectedPrefixes, Lease: policyLease}
	if task.Policy == nil {
		if c.PublicFabric == "" || !slices.ContainsFunc(c.PublicPrefixes, func(p netip.Prefix) bool { return p.Contains(task.Address) }) {
			return policy, "", nil, netip.Addr{}, errors.New("the workload IP is outside the public fabric")
		}
		policy.PublicPort = task.Port
		policy.BlockPublicIngress = task.BlockPublicIngress
		return policy, c.PublicFabric, c.PublicPrefixes, c.PublicGateway, nil
	}
	if !task.Policy.ValidFor(task.Address) {
		return policy, "", nil, netip.Addr{}, errors.New("the workload requires a valid private subnet policy")
	}
	for _, value := range task.Policy.Prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return policy, "", nil, netip.Addr{}, err
		}
		policy.VNetPrefixes = append(policy.VNetPrefixes, prefix)
	}
	policy.Rules = task.Policy.SecurityRules
	if task.Policy.PublicIPv4.IsValid() {
		policy.InternetPrefixes = c.InternetPrefixes
	}
	return policy, c.PrivateFabric, []netip.Prefix{task.Policy.Address.Masked()}, task.Policy.Gateway, nil
}

func containerNamespaces(name string) (string, string) {
	suffix := strings.TrimPrefix(name, "ocean-")[:13]
	return "ow" + suffix, "or" + suffix
}

func attachContainerNetwork(ctx context.Context, name string, pid int, uid string, address netip.Addr, fabric string,
	prefixes []netip.Prefix, gateway netip.Addr) error {
	process := filepath.Join("/proc", strconv.Itoa(pid))
	mapping, err := os.ReadFile(filepath.Join(process, "uid_map"))
	parts := strings.Fields(string(mapping))
	if err != nil || len(parts) < 3 || parts[0] != "0" || parts[1] != uid || parts[2] != "1" {
		return errors.New("the assigned Podman process does not have the expected rootless UID map")
	}
	netns, err := os.Stat(filepath.Join(process, "ns/net"))
	if err != nil {
		return err
	}
	host, err := os.Stat("/proc/self/ns/net")
	if err != nil || os.SameFile(host, netns) {
		return errors.New("the assigned process requires an isolated network namespace")
	}
	marker := filepath.Join(workloadRuntimeDirectory, name+".network")
	if err := publishFile(marker, nil); err != nil {
		return err
	}
	pod, router := containerNamespaces(name)
	if err := callIP(ctx, "netns", "attach", pod, strconv.Itoa(pid)); err != nil {
		return err
	}
	attached, err := os.Stat(filepath.Join("/run/netns", pod))
	if err != nil || !os.SameFile(attached, netns) {
		return errors.New("the assigned network namespace changed before attachment")
	}
	if err := callIP(ctx, "netns", "add", router); err != nil {
		return err
	}
	if err := network.BlockWorkload(ctx, router, containerRouterLink); err != nil {
		return err
	}
	// Keep the fabric MAC stable across container restarts. A client can
	// continue to use its cached neighbor entry while the route is rebuilt.
	octets := address.As4()
	mac := fmt.Sprintf("02:6f:%02x:%02x:%02x:%02x", octets[0], octets[1], octets[2], octets[3])
	commands := [][]string{
		{"link", "add", "link", fabric, "name", containerFabricLink, "address", mac, "netns", router, "type", "macvlan", "mode", "bridge"},
		{"-n", router, "link", "add", containerRouterLink, "type", "veth", "peer", "name", containerLink, "netns", pod},
		{"-n", router, "addr", "add", containerNextHop + "/32", "dev", containerRouterLink},
		{"-n", router, "link", "set", "dev", containerRouterLink, "up"},
		{"-n", router, "link", "set", "dev", containerFabricLink, "up"},
		// Advertise the endpoint IPv4 address as the source of fabric ARP
		// requests. Its unicast route still leads to the container veth.
		{"-n", router, "addr", "add", address.String() + "/32", "dev", containerFabricLink, "noprefixroute"},
		{"-n", router, "route", "delete", "local", address.String() + "/32", "dev", containerFabricLink, "table", "local"},
		{"-n", router, "route", "replace", address.String() + "/32", "dev", containerRouterLink},
		{"-n", router, "neigh", "add", "proxy", address.String(), "dev", containerFabricLink},
		{"netns", "exec", router, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf.fabric0.proxy_arp=1"},
		{"-n", pod, "addr", "add", address.String() + "/32", "dev", containerLink},
		{"-n", pod, "link", "set", "dev", containerLink, "up"},
		{"-n", pod, "route", "replace", "default", "via", containerNextHop, "dev", containerLink, "onlink"},
	}
	for _, prefix := range prefixes {
		commands = append(commands, []string{"-n", router, "route", "replace", prefix.String(), "dev", containerFabricLink})
	}
	if gateway.IsValid() {
		commands = append(commands, []string{"-n", router, "route", "replace", "default", "via", gateway.String(), "dev", containerFabricLink, "onlink"})
	}
	for _, args := range commands {
		if err := callIP(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

func removeContainerNetwork(ctx context.Context, name string) error {
	marker := filepath.Join(workloadRuntimeDirectory, name+".network")
	_ = os.Remove(filepath.Join(workloadRuntimeDirectory, name+".ready"))
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	pod, router := containerNamespaces(name)
	if _, err := os.Stat(filepath.Join("/run/netns", router)); err == nil {
		_ = network.BlockWorkload(ctx, router, containerRouterLink)
	}
	for _, namespace := range []string{router, pod} {
		if _, err := os.Stat(filepath.Join("/run/netns", namespace)); err == nil {
			if err := callIP(ctx, "netns", "delete", namespace); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(marker)
}

func callIP(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "/usr/bin/ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("container network command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
