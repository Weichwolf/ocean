//go:build e2e

package controlplane

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRevokeLabHost(t *testing.T) {
	id := os.Getenv("OCEAN_E2E_REVOKE_HOST")
	if id == "" {
		t.Skip("requires a disposable enrolled host")
	}
	region := openLabRegion(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := region.RevokeHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, host, _, err := region.Enrollment(ctx, id)
	if err != nil || host == nil || host.RevokedAt == nil {
		t.Fatalf("the host revocation did not persist: %v", err)
	}
}
