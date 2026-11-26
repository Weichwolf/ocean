//go:build e2e

package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const desktopRDPObserver = "farm-1-node-07"
const desktopRDPEndpoint = "10.232.1.20:3389"

func prepareDesktopVMRecovery(t *testing.T, ctx context.Context, worker directoryKVMHosts, desktop *packagedDesktopClient) vmRecoveryProbe {
	t.Helper()
	worker.run(ctx, desktopRDPObserver, "command -v xfreerdp3 && command -v xvfb-run && command -v xauth", nil)
	bootID := func() (string, error) {
		call, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		output, err := desktop.run(call, "cat /proc/sys/kernel/random/boot_id", nil)
		return strings.TrimSpace(string(output)), err
	}
	before, err := bootID()
	if err != nil || !identifier.MatchString(before) {
		t.Fatalf("read initial Debian boot ID: %v", err)
	}
	pemBytes, err := desktop.run(ctx, "sudo -n cat /etc/xrdp/cert.pem", nil)
	if err != nil {
		t.Fatalf("read the guest's XRDP certificate over pinned SSH: %v", err)
	}
	cert, _ := pem.Decode(pemBytes)
	if cert == nil || cert.Type != "CERTIFICATE" {
		t.Fatal("the guest did not return its XRDP certificate")
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Bytes))
	password := operationID() + operationID()
	if output, err := desktop.run(ctx, "sudo -n chpasswd", strings.NewReader("debian:"+password+"\n")); err != nil {
		t.Fatalf("enable the disposable fixture account for native RDP: %v: %s", err, output)
	}
	marker := operationID()
	script := fmt.Sprintf(`#!/bin/sh
set -eu
umask 077
test -n "$DISPLAY"
boot=$(cat /proc/sys/kernel/random/boot_id)
profile="$HOME/.config/ocean-desktop"
if [ "$boot" = '%s' ]; then
    mkdir -p "$profile"
    printf '%%s\n' '%s' >"$profile/fence-checkpoint"
    sync -f "$profile/fence-checkpoint"
fi
{
    id -un
    printf '%%s\n' "$boot"
    cat "$profile/fence-checkpoint"
} >"$profile/fence-session"
exec openbox-session
`, before, marker)
	if output, err := desktop.run(ctx, "umask 077 && cat > ~/.xsession", strings.NewReader(script)); err != nil {
		t.Fatalf("install the disposable RDP profile probe: %v: %s", err, output)
	}
	openSession := func(boot string) time.Time {
		t.Helper()
		want := "debian\n" + boot + "\n" + marker
		return probeDesktopRDP(t, ctx, worker, desktop, password, fingerprint, want)
	}
	openSession(before)
	t.Log("native FreeRDP opened Openbox on the private NIC and wrote the user profile checkpoint")
	return vmRecoveryProbe{
		unreachable: func() bool {
			call, cancel := context.WithTimeout(ctx, 7*time.Second)
			defer cancel()
			// A successful observer command must confirm inability to connect.
			result, err := worker.ssh(call, desktopRDPObserver, "command -v nc >/dev/null || exit 2; if nc -z -w 3 10.232.1.20 3389; then echo reachable; else echo unavailable; fi", nil)
			return err == nil && strings.TrimSpace(string(result)) == "unavailable"
		},
		reconnect: func(_ time.Time) time.Time {
			var after string
			pollVMWorker(t, ctx, 60*time.Second, "a fresh Debian boot on the replacement VM worker", func() bool {
				observed, err := bootID()
				after = observed
				return err == nil && identifier.MatchString(after) && after != before
			})
			observedAt := openSession(after)
			t.Log("native FreeRDP opened Openbox after a new boot and read the saved profile checkpoint")
			return observedAt
		},
	}
}

func probeDesktopRDP(t *testing.T, ctx context.Context, worker directoryKVMHosts, desktop *packagedDesktopClient,
	password, fingerprint, want string) time.Time {
	t.Helper()
	clientCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	done := make(chan struct{})
	var output []byte
	var clientErr error
	go func() {
		defer close(done)
		command := "timeout -k 2s 24s xvfb-run -a xfreerdp3 /v:" + desktopRDPEndpoint +
			" /u:debian /from-stdin:force /sec:tls /cert:fingerprint:sha256:" + fingerprint + " /size:800x600 /log-level:WARN"
		output, clientErr = worker.ssh(clientCtx, desktopRDPObserver, command, strings.NewReader(password+"\n"))
	}()
	defer func() {
		stop()
		<-done
	}()
	var observedAt time.Time
	pollVMWorker(t, clientCtx, 28*time.Second, "the authenticated native RDP profile probe", func() bool {
		call, cancel := context.WithTimeout(clientCtx, 5*time.Second)
		defer cancel()
		observed, err := desktop.run(call, `cat ~/.config/ocean-desktop/fence-session && pgrep -u "$(id -u)" -x openbox >/dev/null`, nil)
		if err == nil && strings.TrimSpace(string(observed)) == want {
			observedAt = time.Now()
			return true
		}
		select {
		case <-done:
			t.Fatalf("the native RDP client exited before the profile was observed: %v: %s", clientErr, output)
		default:
		}
		return false
	})
	return observedAt
}

func writeDesktopFenceEvidence(t *testing.T, state string, result vmFenceTimings) {
	t.Helper()
	evidence := filepath.Join(state, "evidence")
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	report := fmt.Sprintf("event\tstatus\tduration_ms\n"+
		"management partition to placement lease expiry\tPASS\t%d\n"+
		"lease expiry retains original writer and closes private RDP\tPASS\t\n"+
		"forged fence\tHTTP 403\t\n"+
		"verified fence and idempotent replay\tHTTP 204\t\n"+
		"worker power cut to replacement Running\tPASS\t%d\n"+
		"worker power cut to native RDP and recovered profile\tPASS\t%d\n"+
		"returning worker has no assignment or writable RBD mapping\tPASS\t\n",
		result.partitionToLease.Milliseconds(), result.powerToRunning.Milliseconds(), result.powerToReconnect.Milliseconds())
	if err := os.WriteFile(filepath.Join(evidence, "desktop-vm-fence.tsv"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
}
