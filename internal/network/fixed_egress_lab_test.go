//go:build e2e

package network

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFixedEgressFailover(t *testing.T) {
	address, image := os.Getenv("OCEAN_E2E_PUBLIC_ADDRESS"), os.Getenv("OCEAN_E2E_BUSYBOX_IMAGE")
	if address == "" || image == "" {
		t.Skip("requires the prepared Debian guest and the reserved ARM address")
	}
	publicIP, err := netip.ParseAddr(address)
	if err != nil || !netip.MustParsePrefix("198.51.100.16/28").Contains(publicIP) {
		t.Fatal("the fixed egress fixture requires an isolated documentation address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(command string, args ...string) string {
		t.Helper()
		output, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %q: %v: %s", command, args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	clean := func(command string, args ...string) {
		t.Cleanup(func() {
			call, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if output, err := exec.CommandContext(call, command, args...).CombinedOutput(); err != nil {
				t.Errorf("clean up %s: %v: %s", command, err, output)
			}
		})
	}
	ip := func(args ...string) { run("ip", args...) }
	suffix := strconv.Itoa(os.Getpid())
	fabric, first, second, observer := "onf"+suffix, "ona"+suffix, "onb"+suffix, "ono"+suffix
	for _, namespace := range []string{fabric, first, second, observer} {
		ip("netns", "add", namespace)
		clean("ip", "netns", "del", namespace)
	}
	for _, bridge := range []string{"tenants", "public"} {
		ip("-n", fabric, "link", "add", bridge, "type", "bridge")
		ip("-n", fabric, "link", "set", bridge, "up")
	}
	link := func(name, bridge, destination, peer string) {
		ip("-n", fabric, "link", "add", name, "type", "veth", "peer", "name", peer, "netns", destination)
		ip("-n", fabric, "link", "set", name, "master", bridge)
		ip("-n", fabric, "link", "set", name, "up")
	}
	configure := func(namespace, device, prefix string) {
		ip("-n", namespace, "addr", "add", prefix, "dev", device)
		ip("-n", namespace, "link", "set", device, "up")
	}
	policy := FixedEgress{Inside: "inside0", Outside: "outside0", Address: publicIP,
		TenantPrefixes:    []netip.Prefix{netip.MustParsePrefix("10.84.1.0/24")},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.231.1.0/24")}}
	for index, namespace := range []string{first, second} {
		link("in"+strconv.Itoa(index), "tenants", namespace, "inside0")
		link("out"+strconv.Itoa(index), "public", namespace, "outside0")
		configure(namespace, "inside0", fmt.Sprintf("10.84.1.%d/24", 2+index))
		configure(namespace, "outside0", fmt.Sprintf("198.51.100.%d/24", 2+index))
		run("ip", "netns", "exec", namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
		if err := policy.Apply(ctx, namespace); err != nil {
			t.Fatal(err)
		}
	}

	link("probe0", "public", observer, "eth0")
	configure(observer, "eth0", "198.51.100.30/24")
	uid := run("id", "-u", "ocean-agent")
	podman := []string{"-u", "ocean-agent", "--", "env", "XDG_RUNTIME_DIR=/run/user/" + uid, "nice", "-n", "10", "podman"}
	workload := "oc-fixed-egress-" + suffix
	pod := func(args ...string) string { return run("runuser", append(slices.Clone(podman), args...)...) }
	clean("runuser", append(slices.Clone(podman), "rm", "-f", "--time=0", "--ignore", workload)...)
	pod("run", "--detach", "--name", workload, "--network", "none", "--memory", "32m", image, "sleep", "90")
	pid := pod("inspect", "--format", "{{.State.Pid}}", workload)
	if rootless := pod("info", "--format", "{{.Host.Security.Rootless}}"); rootless != "true" || run("ps", "-o", "ni=", "-p", pid) != "10" {
		t.Fatal("the fixed egress workload must use rootless Podman and nice 10")
	}
	link("client0", "tenants", pid, "eth0")
	run("nsenter", "-t", pid, "-n", "ip", "addr", "add", "10.84.1.4/24", "dev", "eth0")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "eth0", "up")
	run("nsenter", "-t", pid, "-n", "ip", "route", "add", "default", "via", "10.84.1.1")

	files := t.TempDir()
	start := func(name, program string, args ...string) {
		t.Helper()
		logPath := filepath.Join(files, name+".log")
		logFile, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(program, args...)
		command.Stdout, command.Stderr = logFile, logFile
		err = command.Start()
		_ = logFile.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = command.Process.Signal(os.Interrupt)
			finished := make(chan struct{})
			go func() {
				_ = command.Wait() // The test stops the observer by signal.
				close(finished)
			}()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				_ = command.Process.Kill()
				<-finished
			}
			if t.Failed() {
				data, _ := os.ReadFile(logPath)
				t.Logf("%s: %s", name, data)
			}
		})
	}
	start("observer", "ip", "netns", "exec", observer, "python3", "-u", "-c", `
from http.server import BaseHTTPRequestHandler, HTTPServer

class Source(BaseHTTPRequestHandler):
    def do_GET(self):
        source = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(source)))
        self.end_headers()
        self.wfile.write(source)

HTTPServer(("198.51.100.30", 8080), Source).serve_forever()
`)
	startGateway := func(namespace string, index, priority int) {
		base := filepath.Join(files, namespace)
		config := fmt.Sprintf(`
global_defs {
  router_id %s
}
vrrp_instance EGRESS {
  state BACKUP
  interface inside0
  virtual_router_id 74
  priority %d
  advert_int 1
  unicast_src_ip 10.84.1.%d
  unicast_peer {
    10.84.1.%d
  }
  track_interface {
    outside0
  }
  garp_master_delay 0
  garp_master_repeat 3
  virtual_ipaddress {
    10.84.1.1/24 dev inside0
    %s/24 dev outside0
  }
}
`, namespace, priority, 2+index, 3-index, address)
		if err := os.WriteFile(base+".conf", []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		start(namespace, "ip", "netns", "exec", namespace, "/usr/sbin/keepalived",
			"--dont-fork", "--log-console", "--use-file", base+".conf",
			"--pid", base+".pid", "--vrrp_pid", base+".vrrp.pid")
	}
	hasAddress := func(namespace string) bool {
		return strings.Contains(run("ip", "-n", namespace, "-4", "-o", "addr", "show", "dev", "outside0"), address+"/24")
	}
	source := func() string {
		out, err := exec.CommandContext(ctx, "nsenter", "-t", pid, "-n", "curl", "--noproxy", "*", "--fail", "--silent",
			"--max-time", "1", "http://198.51.100.30:8080/source").Output()
		if err != nil {
			return ""
		}
		return string(out)
	}
	wait := func(limit time.Duration, ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for !ready() {
			if time.Now().After(deadline) {
				t.Fatalf("egress did not converge within %v", limit)
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	startGateway(first, 0, 150)
	wait(8*time.Second, func() bool { return hasAddress(first) && source() == address })
	startGateway(second, 1, 100)
	wait(6*time.Second, func() bool {
		log, _ := os.ReadFile(filepath.Join(files, second+".log"))
		return strings.Contains(string(log), "Entering BACKUP STATE") && hasAddress(first) && !hasAddress(second)
	})
	t.Logf("the outside observer saw %s through the first gateway", address)
	failure := time.Now()
	ip("-n", first, "link", "set", "outside0", "down")
	wait(8*time.Second, func() bool { return !hasAddress(first) && hasAddress(second) && source() == address })
	t.Logf("the outside observer still saw %s after the active uplink loss; a fresh connection recovered in %d ms",
		address, time.Since(failure).Milliseconds())
}
