//go:build e2e

package network

import (
	"context"
	"encoding/json"
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

func TestRoutedPodmanFirewall(t *testing.T) {
	fixture := os.Getenv("OCEAN_E2E_GATEWAY_POLICY")
	image := os.Getenv("OCEAN_E2E_BUSYBOX_IMAGE")
	if fixture == "" || image == "" {
		t.Skip("requires the prepared Debian guest and CLI policy fixture")
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var group SecurityGroupProperties
	if err := json.Unmarshal(data, &group); err != nil {
		t.Fatal(err)
	}
	if len(group.SecurityRules) != 4 {
		t.Fatalf("expected four tested security rules, got %d", len(group.SecurityRules))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	run := func(command string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %q: %v: %s", command, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	cleanup := func(command string, args ...string) {
		t.Cleanup(func() {
			cleanupCtx, clear := context.WithTimeout(context.Background(), 12*time.Second)
			defer clear()
			if out, err := exec.CommandContext(cleanupCtx, command, args...).CombinedOutput(); err != nil {
				t.Errorf("clean up %s %q: %v: %s", command, args, err, out)
			}
		})
	}
	uid := run("id", "-u", "ocean-agent")
	podman := []string{"-u", "ocean-agent", "--", "env", "XDG_RUNTIME_DIR=/run/user/" + uid, "nice", "-n", "10", "podman"}
	if rootless := run("runuser", append(slices.Clone(podman), "info", "--format", "{{.Host.Security.Rootless}}")...); rootless != "true" {
		t.Fatal("the fixture requires rootless Podman")
	}
	stamp := strconv.Itoa(os.Getpid())
	ip := func(args ...string) { run("ip", args...) }
	workload := "oc-fw-" + stamp
	pod := func(args ...string) string { return run("runuser", append(slices.Clone(podman), args...)...) }
	cleanup("runuser", append(slices.Clone(podman), "rm", "-f", "--ignore", workload)...)
	pod("run", "--detach", "--name", workload, "--network", "none", "--memory", "32m", image, "sh", "-ec",
		"mkdir /www; echo ocean-firewall > /www/index.html; httpd -p 8081 -h /www; exec httpd -f -p 8080 -h /www")
	pid := pod("inspect", "--format", "{{.State.Pid}}", workload)
	if nice := run("ps", "-o", "ni=", "-p", pid); nice != "10" {
		t.Fatalf("expected workload nice 10, got %s", nice)
	}
	router, client, other := "ofr"+stamp, "ofc"+stamp, "oft"+stamp
	for _, namespace := range []string{router, client, other} {
		ip("netns", "add", namespace)
		cleanup("ip", "netns", "delete", namespace)
	}
	veth := func(leftName, leftNS, rightName, rightNS string) {
		ip("-n", leftNS, "link", "add", leftName, "type", "veth", "peer", "name", rightName, "netns", rightNS)
	}
	configure := func(namespace, link, address string) {
		ip("-n", namespace, "addr", "add", address, "dev", link)
		ip("-n", namespace, "link", "set", link, "up")
	}
	veth("work0", router, "eth0", pid)
	configure(router, "work0", "10.72.1.1/24")
	run("nsenter", "-t", pid, "-n", "ip", "addr", "add", "10.72.1.4/24", "dev", "eth0")
	run("nsenter", "-t", pid, "-n", "ip", "link", "set", "eth0", "up")
	run("nsenter", "-t", pid, "-n", "ip", "route", "add", "default", "via", "10.72.1.1")
	veth("probe0", router, "eth0", client)
	configure(router, "probe0", "10.77.2.1/24")
	configure(client, "eth0", "10.77.2.4/24")
	ip("-n", client, "route", "add", "10.72.1.0/24", "via", "10.77.2.1")
	ip("-n", client, "link", "set", "lo", "up")
	ip("-n", client, "addr", "add", "10.231.1.77/32", "dev", "lo")
	ip("-n", router, "route", "add", "10.231.1.77/32", "via", "10.77.2.4")
	run("ip", "netns", "exec", router, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

	body := t.TempDir()
	if err := os.WriteFile(filepath.Join(body, "index.html"), []byte("ocean-egress\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"8080", "8081"} {
		server := exec.Command("ip", "netns", "exec", client, "python3", "-m", "http.server", port,
			"--bind", "0.0.0.0", "--directory", body)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = server.Process.Kill()
			_ = server.Wait()
		})
	}
	// /proc shows the listener as soon as bind and listen have completed.
	deadline := time.Now().Add(4 * time.Second)
	for {
		sockets := run("ip", "netns", "exec", client, "ss", "-lntH")
		if strings.Contains(sockets, ":8080 ") && strings.Contains(sockets, ":8081 ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("probe listeners did not open")
		}
		time.Sleep(50 * time.Millisecond)
	}
	probe := func(namespace, host, port string, allowed bool) {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "curl", "--noproxy", "*", "-sS",
			"--max-time", "2", "http://"+host+":"+port+"/").CombinedOutput()
		if allowed {
			if err != nil || string(out) != "ocean-firewall\n" {
				t.Fatalf("ingress %s:%s should reach the fixture: %v: %s", host, port, err, out)
			}
		} else if failure, ok := err.(*exec.ExitError); !ok || failure.ExitCode() != 28 {
			t.Fatalf("ingress %s:%s should time out: %v: %s", host, port, err, out)
		}
	}
	egress := func(host, port string, allowed bool, options ...string) {
		t.Helper()
		args := []string{"-t", pid, "-n", "curl", "--noproxy", "*", "-sS", "--fail", "--max-time", "2"}
		args = append(args, options...)
		args = append(args, "http://"+host+":"+port+"/")
		out, err := exec.CommandContext(ctx, "nsenter", args...).CombinedOutput()
		if allowed && (err != nil || string(out) != "ocean-egress\n") {
			t.Fatalf("egress %s:%s should receive an HTTP response: %v: %s", host, port, err, out)
		}
		if !allowed {
			if failure, ok := err.(*exec.ExitError); !ok || failure.ExitCode() != 28 {
				t.Fatalf("egress %s:%s should time out: %v: %s", host, port, err, out)
			}
		}
	}
	probe(client, "10.72.1.4", "8080", true)
	probe(client, "10.72.1.4", "8081", true)
	egress("10.77.2.4", "8081", true)
	egress("10.231.1.77", "8080", true)
	run("nsenter", "-t", pid, "-n", "ip", "addr", "add", "10.72.1.5/32", "dev", "eth0")
	egress("10.77.2.4", "8080", true, "--interface", "10.72.1.5")

	firewall := WorkloadFirewall{Interface: "work0", Address: netip.MustParseAddr("10.72.1.4"),
		VNetPrefixes:      []netip.Prefix{netip.MustParsePrefix("10.72.0.0/16")},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.231.1.0/24")}, Rules: group.SecurityRules}
	if err := firewall.Apply(ctx, router); err != nil {
		t.Fatal(err)
	}
	probe(client, "10.72.1.4", "8080", true)
	probe(client, "10.72.1.4", "8081", false)
	egress("10.77.2.4", "8080", true)
	egress("10.77.2.4", "8081", false)
	egress("10.231.1.77", "8080", false)
	egress("10.77.2.4", "8080", false, "--interface", "10.72.1.5")

	// Retrying the transaction preserves the selected rules. Removing only
	// the configured denials makes the broader lower-priority permits apply.
	if err := firewall.Apply(ctx, router); err != nil {
		t.Fatal(err)
	}
	invalid := firewall
	invalid.Rules = append(slices.Clone(firewall.Rules), firewall.Rules[0])
	if err := invalid.Apply(ctx, router); err == nil {
		t.Fatal("an invalid policy replaced the previously committed firewall")
	}
	probe(client, "10.72.1.4", "8081", false)
	firewall.Rules = slices.DeleteFunc(slices.Clone(group.SecurityRules), func(rule SecurityRule) bool {
		return rule.Properties.Access == "Deny"
	})
	if err := firewall.Apply(ctx, router); err != nil {
		t.Fatal(err)
	}
	probe(client, "10.72.1.4", "8081", true)
	egress("10.77.2.4", "8081", true)
	egress("10.231.1.77", "8080", false)

	veth("tenant0", other, "tenant1", other)
	configure(other, "tenant0", "10.72.1.7/24")
	configure(other, "tenant1", "10.72.1.8/24")
	probe(other, "10.72.1.4", "8080", false)
	t.Log("CLI-created policies enforced ingress and egress priority, blocked unassigned workload addresses and a reachable management-prefix fixture, and kept overlapping tenant namespaces isolated")
}
