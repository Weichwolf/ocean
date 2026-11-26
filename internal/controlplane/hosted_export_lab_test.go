//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const exportFixtureResources = 71

func seedHostedExportFixture(t *testing.T, ctx context.Context, r *Region, other, owner identity.TenantReservation) {
	t.Helper()
	scope := arm.SubscriptionScope{TenantID: owner.TenantID, SubscriptionID: owner.SubscriptionID}
	for i := range exportFixtureResources {
		address := arm.ResourceAddress{Group: "retained-fixture", Path: fmt.Sprintf("Ocean.Compute/artifacts/sample-%03d", i)}
		if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: address, Location: r.name, APIVersion: "2026-11-01",
			Properties: json.RawMessage(`{"internal":"export-fixture-secret"}`), Tags: map[string]string{"fixture": "export-fixture-secret"}}); err != nil {
			t.Fatal(err)
		}
	}
	foreign := arm.SubscriptionScope{TenantID: other.TenantID, SubscriptionID: other.SubscriptionID}
	if err := r.PutInventoryResource(ctx, foreign, arm.InventoryResource{Address: arm.ResourceAddress{Group: "retained-fixture", Path: "Ocean.Compute/artifacts/foreign-export-fixture"},
		Location: r.name, APIVersion: "2026-11-01"}); err != nil {
		t.Fatal(err)
	}
	app := identity.Application{TenantID: owner.TenantID, ID: operationID(), ClientID: operationID(), PrincipalID: operationID(),
		DisplayName: "export fixture application", Credentials: []identity.ClientCredential{{ID: operationID(), Verifier: "export-fixture-secret"}}}
	if ok, err := r.SaveApplication(ctx, app, 0); !ok || err != nil {
		t.Fatalf("seed tenant application: %v", err)
	}
	if _, _, err := r.PutAssignment(ctx, scope, arm.RoleAssignment{ID: operationID(), Group: "retained-fixture", PrincipalID: app.PrincipalID,
		PrincipalType: "ServicePrincipal", RoleID: arm.ReaderRoleID, CreatedBy: owner.Administrator, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	directory := identity.ManagedDirectory{TenantID: owner.TenantID, SubscriptionID: owner.SubscriptionID, ID: operationID(), RequestedAt: time.Now().UTC(),
		Spec: identity.DirectorySpec{DNSName: "export-fixture.ocean.test", NetBIOSName: "EXPORTLAB", SubnetID: "isolated-fixture"}}
	if _, err := r.client.Do(ctx, putJSON(r.managedDirectoryKey(owner.TenantID), directory)); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordAudit(ctx, scope, arm.AuditEvent{Time: time.Now().UTC().Add(-2 * time.Hour), Actor: app.PrincipalID,
		Action: "expired-export-fixture", Target: "/subscriptions/" + scope.SubscriptionID, Outcome: "Succeeded"}); err != nil {
		t.Fatal(err)
	}
}

func verifyHostedTenantExport(t *testing.T, ctx context.Context, restored *Region, az func(string, string, string, string, string) []byte,
	origin string, other, owner identity.TenantReservation, operatorClient, operatorRealm, operator string, sign func(string, string, string, string) string) {
	t.Helper()
	started := time.Now().UTC()
	pathFor := func(tenant string) string { return "/ocean/tenants/" + tenant + "/dataExport?api-version=2026-11-01" }
	path := pathFor(owner.TenantID)
	admin := sign(owner.TenantID, operatorClient, owner.Administrator, origin)
	member := sign(owner.TenantID, operatorClient, operationID(), origin)
	az("get", path, "", member, "AuthorizationFailed")
	az("get", pathFor(other.TenantID), "", admin, "AuthorizationFailed")
	az("get", pathFor(other.TenantID), "", sign(other.TenantID, operatorClient, other.Administrator, origin), "InvalidAuthenticationToken")
	az("get", path, "", sign(operatorRealm, operatorClient, operator, origin), "InvalidAuthenticationToken")
	az("get", path+"&scope=foreign", "", admin, "InvalidQueryParameter")
	scope := arm.SubscriptionScope{TenantID: owner.TenantID, SubscriptionID: owner.SubscriptionID}
	var originalContinuation string
	var capturedAt time.Time
	types := make(map[string]int)
	resourceIDs := make(map[string]bool)
	pageCount := 0
	for next := path; next != ""; {
		pageCount++
		if pageCount > 8 {
			t.Fatal("tenant export continuation did not terminate")
		}
		raw := az("get", next, "", admin, "")
		for _, excluded := range []string{"expired-export-fixture", "foreign-export-fixture", "export-fixture-secret", "\"verifier\"", "\"credentials\"", other.SubscriptionID} {
			if bytes.Contains(raw, []byte(excluded)) {
				t.Fatal("tenant export included foreign, expired or credential data")
			}
		}
		var page struct {
			Format         string
			TenantID       string
			SubscriptionID string
			CapturedAt     time.Time
			NextLink       string
			Records        []struct {
				Kind string
				Data json.RawMessage
			}
		}
		if err := json.Unmarshal(raw, &page); err != nil || page.Format != "ocean-hosted-export-v1" ||
			page.TenantID != scope.TenantID || page.SubscriptionID != scope.SubscriptionID || page.CapturedAt.IsZero() || len(page.Records) > hostedExportPageSize {
			t.Fatalf("invalid export projection: %v", err)
		}
		if pageCount == 1 {
			capturedAt = page.CapturedAt
			if page.NextLink == "" {
				t.Fatal("expected the fixture inventory to require multiple pages")
			}
			late := arm.ResourceAddress{Group: "retained-fixture", Path: "Ocean.Compute/artifacts/after-snapshot"}
			if err := restored.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: late, Location: restored.name, APIVersion: "2026-11-01"}); err != nil {
				t.Fatal(err)
			}
		} else if !page.CapturedAt.Equal(capturedAt) {
			t.Fatal("continuation changed the export snapshot")
		}
		for _, row := range page.Records {
			types[row.Kind]++
			if row.Kind != "resource" {
				continue
			}
			var record struct{ ID string }
			if err := json.Unmarshal(row.Data, &record); err != nil || !strings.HasPrefix(record.ID, "/subscriptions/"+scope.SubscriptionID+"/") ||
				strings.Contains(record.ID, "after-snapshot") || resourceIDs[record.ID] {
				t.Fatalf("resource was outside the captured tenant inventory: %v", err)
			}
			resourceIDs[record.ID] = true
		}
		next = ""
		if page.NextLink != "" {
			var sameOrigin bool
			next, sameOrigin = strings.CutPrefix(page.NextLink, origin+"/")
			if !sameOrigin || !strings.HasPrefix(next, strings.TrimPrefix(path, "/")) {
				t.Fatal("untrusted export continuation URL")
			}
			next = "/" + next
			if pageCount == 1 {
				originalContinuation = next
				az("get", next, "", member, "AuthorizationFailed")
				az("get", next+"a", "", admin, "AuthorizationFailed")
			}
		}
	}
	if len(resourceIDs) != exportFixtureResources || types["activity"] == 0 {
		t.Fatalf("pagination did not include the complete authorized fixture: %v", types)
	}
	for _, kind := range []string{"subscription", "placement", "managedDirectory", "resourceGroup", "roleAssignment", "application"} {
		if types[kind] != 1 {
			t.Fatalf("expected exactly one exported %s record: %v", kind, types)
		}
	}
	_, subKey := restored.tenantKeys(scope.TenantID)
	rows, err := restored.client.Get(ctx, subKey, clientv3.WithCountOnly())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.client.Compact(ctx, rows.Header.Revision); err != nil {
		t.Fatal(err)
	}
	az("get", originalContinuation, "", admin, "ExportSnapshotExpired")
	filter := arm.ActivityFilter{Start: started, End: time.Now().UTC(), Caller: owner.Administrator}
	audited, err := restored.ListActivity(ctx, scope, "", filter, 64)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range audited {
		if row.Action == "Ocean.Hosted/dataExports/read" && row.Outcome == "Succeeded" {
			count++
		}
	}
	if count != pageCount {
		t.Fatalf("expected one scoped audit event per successful export page: %d of %d", count, pageCount)
	}
	if query, err := url.ParseRequestURI(originalContinuation); err != nil || query.Query().Get("cursor") == "" {
		t.Fatalf("expected an opaque export continuation: %v", err)
	}
	t.Logf("Azure CLI 2.93.0 returned %d tenant inventory records over %d consistent, audited pages. Foreign scope, credentials, expired events, a changed cursor and a compacted snapshot were withheld. Verification took %d ms.", len(resourceIDs), pageCount, time.Since(started).Milliseconds())
}
