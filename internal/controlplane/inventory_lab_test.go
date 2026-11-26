//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
)

// TestPublishLabInventory runs in the operator guest with its dedicated etcd
// identity. It publishes fixture projections through the same store as providers.
func TestPublishLabInventory(t *testing.T) {
	region := openLabRegion(t)
	var fixture []struct {
		Scope    arm.SubscriptionScope
		Resource arm.InventoryResource
	}
	if err := json.NewDecoder(os.Stdin).Decode(&fixture); err != nil || len(fixture) == 0 {
		t.Fatalf("invalid inventory lab fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, entry := range fixture {
		if err := region.PutInventoryResource(ctx, entry.Scope, entry.Resource); err != nil {
			t.Fatalf("publish inventory fixture: %v", err)
		}
	}
}

func openLabRegion(t *testing.T) *Region {
	t.Helper()
	return openNamedLabRegion(t, "farm-1")
}

func openNamedLabRegion(t *testing.T, name string) *Region {
	t.Helper()
	endpoints := os.Getenv("OCEAN_E2E_ETCD_ENDPOINTS")
	if endpoints == "" {
		t.Skip("requires the isolated regional inventory lab")
	}
	pki := os.Getenv("OCEAN_E2E_ETCD_PKI")
	region, err := openRegion(regionConfig{Name: name, InitialCell: "cell-1", Etcd: etcdConfig{
		Endpoints: strings.Split(endpoints, ","), CAFile: filepath.Join(pki, "storage-ca.pem"),
		CertificateFile: filepath.Join(pki, "lab-operator.pem"), KeyFile: filepath.Join(pki, "lab-operator.key"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = region.client.Close() })
	return region
}
