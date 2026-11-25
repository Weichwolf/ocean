//go:build e2e

package nodeagent

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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
	var reads atomic.Int32
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/ocean/hosts/node/directories/"+tenant+"/"+generation+"/bootstrap" {
			http.NotFound(w, r)
			return
		}
		reads.Add(1)
		_, _ = fmt.Fprint(w, private)
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
	data, err := localPodman(t.Context(), "inspect", name).Output()
	if err != nil || strings.Contains(string(data), private) {
		t.Fatal("bootstrap secret appeared in process configuration")
	}
	if err := j.syncDirectoryContainer(t.Context(), name, a); err != nil || reads.Load() != 1 {
		t.Fatal("an already running controller requested another bootstrap")
	}
	// Removing the container leaves the operator's generation-specific volume.
	// The normal agent path must reopen it and must not try to create it again.
	if err := podmanAction(t.Context(), "rm", "--force", "--time", "1", name); err != nil {
		t.Fatal(err)
	}
	if err := j.syncDirectoryContainer(t.Context(), name, a); err != nil || reads.Load() != 2 {
		t.Fatalf("the agent did not reopen an existing directory volume: %v", err)
	}
	check()
}
