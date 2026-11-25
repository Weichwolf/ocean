//go:build e2e

package nodeagent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

func TestDirectoryControllerRuntimeHandoff(t *testing.T) {
	image := os.Getenv("OCEAN_E2E_SAMBA_IMAGE")
	if image == "" {
		t.Skip("requires a local Samba controller image in rootless Podman")
	}
	address := netip.MustParseAddr("10.254.247.11")
	generation := strings.ToLower(rand.Text())
	const tenant = "0ccef74a-66da-4f20-bffb-73875b79be57"
	a := enrollment.Assignment{ID: "directory-test", Generation: generation, TenantID: tenant,
		SubscriptionID: "92c64582-7cfe-43c4-a121-b04519f71815", PrivateIPv4: address,
		Resources: enrollment.Capacity{CPUMillis: 300, MemoryMiB: 768},
		Directory: &enrollment.DirectoryAssignment{DirectoryID: "398994bd-dd01-46e9-a2b0-c1290d70b25d",
			DNSName: "ad.runtime.test", NetBIOSName: "OCEANRUN", ControllerIndex: 1},
	}
	name := containerName(directoryTaskID(a))
	check := func() {
		t.Helper()
		stat, present, err := inspectContainer(t.Context(), name, localPodman)
		if err != nil || !present || !stat.Running {
			t.Fatalf("expected directory container waiting for the assigned private address: %v", err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = podmanAction(ctx, "rm", "--force", "--ignore", name)
		_ = podmanAction(ctx, "secret", "rm", name)
		_ = podmanAction(ctx, "volume", "rm", name)
	})
	private := "Ocn9-" + rand.Text()
	const establishedSID = "S-1-5-21-123-456-789"
	var reads, reports atomic.Int32
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/ocean/hosts/node/directories/" + tenant + "/" + generation
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base+"/bootstrap":
			if reads.Add(1) == 1 {
				w.Header().Set(enrollment.DirectoryDomainSIDHeader, "")
				_, _ = fmt.Fprint(w, private)
			} else {
				w.Header().Set(enrollment.DirectoryDomainSIDHeader, establishedSID)
				w.WriteHeader(http.StatusOK)
			}
		case r.Method == http.MethodPost && r.URL.Path == base+"/health":
			if body, err := io.ReadAll(r.Body); err != nil || string(body) != `{"ready":false}` || r.TLS == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reports.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuer.Close()
	j := joinClient{config: joinConfig{DirectoryImage: image, Origin: issuer.URL, HostID: "node"}, client: issuer.Client()}
	if !j.directoryRuntimeAvailable(t.Context()) {
		t.Fatal("the local image or Podman maps do not qualify for directory placement")
	}
	if err := j.syncDirectoryContainer(t.Context(), name, a); err != nil {
		t.Fatal(err)
	}
	check()
	if health := directoryControllerHealth(t.Context(), name); health.Ready {
		t.Fatal("starting container reported ready without a private address")
	}
	if err := j.reportDirectoryHealth(t.Context(), a, enrollment.DirectoryHealth{}); err != nil || reports.Load() != 1 {
		t.Fatalf("the agent did not report the unavailable controller: %v", err)
	}
	data, err := localPodman(t.Context(), "inspect", name).Output()
	if err != nil || strings.Contains(string(data), private) {
		t.Fatal("bootstrap secret appeared in process configuration")
	}
	if err := j.syncDirectoryContainer(t.Context(), name, a); err != nil || reads.Load() != 1 {
		t.Fatal("an already running controller requested another bootstrap")
	}
	// A stopped container's launch configuration is stale, while its volume
	// still belongs to the same generation.
	if err := podmanAction(t.Context(), "stop", "--time", "1", name); err != nil {
		t.Fatal(err)
	}
	if err := j.syncDirectoryContainer(t.Context(), name, a); err != nil || reads.Load() != 2 {
		t.Fatalf("the agent did not reopen an existing directory volume: %v", err)
	}
	check()
	data, err = localPodman(t.Context(), "inspect", name).Output()
	if err != nil || !strings.Contains(string(data), "OCEAN_AD_EXPECTED_SID="+establishedSID) ||
		strings.Contains(string(data), "ocean-directory-bootstrap") {
		t.Fatal("the replacement container did not receive the established SID without a credential mount")
	}
}

func TestDirectoryRecoveryRuntimeIsolation(t *testing.T) {
	image := os.Getenv("OCEAN_E2E_SAMBA_IMAGE")
	if image == "" {
		t.Skip("requires a local Samba controller image in rootless Podman")
	}
	const recovery = "7832c08a-92e9-4c36-bec5-d5a44b6b4b84"
	const sid = "S-1-5-21-123-456-789"
	address := netip.MustParseAddr("10.254.247.11")
	directory := &enrollment.DirectoryAssignment{
		DirectoryID: "398994bd-dd01-46e9-a2b0-c1290d70b25d", DNSName: "ad.runtime.test", NetBIOSName: "OCEANRUN",
		ControllerIndex: 1, ControllerIPv4: [2]netip.Addr{address, netip.MustParseAddr("10.254.247.12")},
		ControllerNames: [2]string{"dc-recovery", "dc-recovery2"}, RecoveryID: recovery, RecoverySHA256: strings.Repeat("a", 64),
	}
	a := enrollment.Assignment{ID: "directory-restore-test", Generation: strings.ToLower(rand.Text()),
		TenantID: "0ccef74a-66da-4f20-bffb-73875b79be57", SubscriptionID: "92c64582-7cfe-43c4-a121-b04519f71815",
		PrivateIPv4: address, Resources: enrollment.Capacity{CPUMillis: 500, MemoryMiB: 768}, Directory: directory}
	name := containerName(directoryTaskID(a))
	restorer := name + directoryRestoreSuffix
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = podmanAction(ctx, "rm", "--force", "--ignore", name, restorer)
		_ = podmanAction(ctx, "secret", "rm", "--ignore", name)
		_ = podmanAction(ctx, "volume", "rm", name)
	})
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ocean/hosts/node/directories/"+a.TenantID+"/"+a.Generation+"/bootstrap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(enrollment.DirectoryDomainSIDHeader, sid)
		_, _ = fmt.Fprint(w, "Ocn9-"+strings.Repeat("A", 32))
	}))
	defer issuer.Close()
	state := t.TempDir()
	j := joinClient{config: joinConfig{DirectoryImage: image, Origin: issuer.URL, HostID: "node",
		StateDirectory: state}, client: issuer.Client()}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := j.syncDirectoryContainer(ctx, name, a); !errors.Is(err, errDirectoryRestorePending) {
		t.Fatalf("a missing archive did not wait: %v", err)
	}
	folder := filepath.Join(state, "directory-recovery")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(folder, recovery+".tar")
	if err := os.WriteFile(archive, []byte("corrupt recovery archive"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := j.syncDirectoryContainer(ctx, name, a); err == nil || errors.Is(err, errDirectoryRestorePending) {
		t.Fatalf("an archive readable by other users could enter the restore container: %v", err)
	}
	if err := os.Chmod(archive, 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.syncDirectoryContainer(ctx, name, a); !errors.Is(err, errDirectoryRestorePending) {
		t.Fatalf("did not start the offline restore job: %v", err)
	}
	networkMode, err := localPodman(ctx, "inspect", "--format", "{{.HostConfig.NetworkMode}}", restorer).Output()
	if err != nil || strings.TrimSpace(string(networkMode)) != "none" {
		t.Fatalf("the restore may have been attached to a network: %q %v", networkMode, err)
	}
	for {
		status, exists, err := inspectContainer(ctx, restorer, localPodman)
		if err != nil || !exists {
			t.Fatalf("the agent did not retain its offline recovery status: %v", err)
		}
		if !status.Running {
			if status.ExitCode == 0 {
				t.Fatal("a corrupt archive was accepted")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, exists, err := inspectContainer(ctx, name, localPodman); err != nil || exists {
		t.Fatalf("the agent started Samba after a failed offline restore: %v", err)
	}
}
