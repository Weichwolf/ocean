//go:build e2e

package qemu

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The lab supplies a private network namespace, an attached TAP interface and
// a disposable raw copy of the installed guest disk and firmware variables.
func TestKVMGuestPowerLifecycle(t *testing.T) {
	state := os.Getenv("OCEAN_KVM_SMOKE_STATE")
	if state == "" {
		t.Skip("requires a disposable KVM guest in an isolated lab network")
	}
	guest := Guest{
		ID: "b37273e0-dfd5-4d9b-90d0-c57f5ec24abc", Generation: "b2cebfb4-5fbf-450e-beed-8d5da137e7c8",
		Size: "Standard_B2s", Directory: filepath.Join(state, "runtime"), Disk: filepath.Join(state, "disk.raw"),
		FirmwareCode: "/usr/share/OVMF/OVMF_CODE_4M.fd", FirmwareVars: filepath.Join(state, "OVMF_VARS.fd"),
		Tap: "oceanvmtest",
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := guest.Stop(cleanup, true); err != nil {
			t.Error(err)
		}
	})
	assertState := func(expected PowerState) {
		t.Helper()
		if actual, err := guest.Status(ctx); err != nil || actual != expected {
			t.Fatalf("KVM guest power state is %q, expected %q: %v", actual, expected, err)
		}
	}
	assertState(PowerOff)
	for range 2 {
		if err := guest.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	assertState(PowerRunning)
	var acceleration struct {
		Enabled bool `json:"enabled"`
	}
	if err := Call(ctx, guest.socket(), guest.name(), "query-kvm", &acceleration); err != nil || !acceleration.Enabled {
		t.Fatalf("KVM acceleration is unavailable: %v", err)
	}
	var identity struct {
		UUID string `json:"UUID"`
	}
	if err := Call(ctx, guest.socket(), guest.name(), "query-uuid", &identity); err != nil || identity.UUID != guest.ID {
		t.Fatalf("unexpected KVM firmware UUID %q: %v", identity.UUID, err)
	}
	wrong := guest
	wrong.Generation = "48171025-9053-48ad-adea-27b5591a8e8f"
	if err := wrong.Start(ctx); err == nil {
		t.Fatal("accepted a second generation while the original QEMU process was running")
	}
	monitor := guest.socket()
	away := monitor + ".temporary"
	if err := os.Rename(monitor, away); err != nil {
		t.Fatal(err)
	}
	_, statusErr := guest.Status(ctx)
	startErr := guest.Start(ctx)
	if err := os.Rename(away, monitor); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(statusErr, errMonitorUnavailable) || !errors.Is(startErr, errMonitorUnavailable) {
		t.Fatalf("the live local writer must survive lost monitor access: status %v, start %v", statusErr, startErr)
	}
	t.Log("the writer lock rejected a second start while the primary monitor was unreachable")
	peer := os.Getenv("OCEAN_KVM_SMOKE_PRIVATE_IP")
	stopMode := os.Getenv("OCEAN_KVM_SMOKE_STOP_MODE")
	if stopMode != "" && stopMode != "force" {
		t.Fatal("the KVM smoke stop mode must be empty (ACPI) or force")
	}
	force := peer == "" || stopMode == "force"
	if peer != "" {
		if address, err := netip.ParseAddr(peer); err != nil || !address.Is4() {
			t.Fatal("the private KVM smoke probe requires a guest IPv4 address")
		}
	}
	probeGuest := func() {
		t.Helper()
		if peer == "" {
			return
		}
		started := time.Now()
		for {
			result, err := exec.CommandContext(ctx, "/usr/bin/busybox", "arping", "-I", guest.Tap, "-c", "1", "-w", "1", peer).CombinedOutput()
			if err == nil && strings.Contains(strings.ToLower(string(result)), "["+MAC(guest.ID)+"]") {
				t.Logf("private address %s responded at %s after %s", peer, MAC(guest.ID), time.Since(started).Round(time.Millisecond))
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("private ARP probe for %s did not return the guest NIC identity: %v: %s", peer, err, result)
			case <-time.After(time.Second):
			}
		}
	}
	probeGuest()
	stopStarted := time.Now()
	if err := guest.Stop(ctx, force); err != nil {
		t.Fatal(err)
	}
	t.Logf("writer lock released after %s (forced stop: %t)", time.Since(stopStarted).Round(time.Millisecond), force)
	assertState(PowerOff)
	if err := guest.Start(ctx); err != nil {
		t.Fatal(err)
	}
	assertState(PowerRunning)
	if err := Call(ctx, guest.socket(), guest.name(), "query-uuid", &identity); err != nil || identity.UUID != guest.ID {
		t.Fatalf("unexpected KVM firmware UUID after restart %q: %v", identity.UUID, err)
	}
	probeGuest()
	if err := guest.Stop(ctx, force); err != nil {
		t.Fatal(err)
	}
	assertState(PowerOff)
}
