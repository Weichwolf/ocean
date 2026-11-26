//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

func TestHostedSupportGrants(t *testing.T) {
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if archive == "" || cli == "" {
		t.Skip("requires pinned etcd and Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-support")
	operatorRealm, managementClient, supportClient, person := operationID(), operationID(), operationID(), operationID()
	cfg.HostedWorkplace.OperatorPools["partner"] = "NL"
	cfg.HostedWorkplace.Support = &hostedSupportPolicy{ClientID: supportClient, AuthContext: "ocean-support", Pools: map[string][]netip.Prefix{
		"primary": {netip.MustParsePrefix("127.0.0.1/32")},
		"partner": {netip.MustParsePrefix("127.0.0.2/32")},
	}}
	r := openHostedLabRegion(t, ctx, cfg)
	owner, neighbor := seedHostedRestoreTenant(t, ctx, r), seedHostedRestoreTenant(t, ctx, r)
	scope := arm.SubscriptionScope{TenantID: owner.TenantID, SubscriptionID: owner.SubscriptionID}
	foreign := arm.SubscriptionScope{TenantID: neighbor.TenantID, SubscriptionID: neighbor.SubscriptionID}
	quota := enrollment.Capacity{CPUMillis: 4000, MemoryMiB: 2048}
	allow := func(pools ...string) {
		t.Helper()
		if err := r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: pools, Quota: quota}); err != nil {
			t.Fatal(err)
		}
	}
	allow("primary", "partner")
	issuer, sign := hostedClaimsIssuer(t, operatorRealm, owner.TenantID, neighbor.TenantID)
	workers := hostedLabInventory(cfg)
	origin, httpClient, az, _ := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, managementClient, issuer.URL, issuer.Certificate(), workers...)
	ownerToken := sign(owner.TenantID, managementClient, owner.Administrator, origin, nil)
	otherOwner := sign(neighbor.TenantID, managementClient, neighbor.Administrator, origin, nil)
	supportToken := func(origin, client, actor, assurance string, at time.Time) string {
		return sign(operatorRealm, client, actor, origin, map[string]any{"acr": assurance, "auth_time": at.Unix()})
	}
	support := supportToken(origin, supportClient, person, "ocean-support", time.Now())
	address := arm.ResourceAddress{Group: "retained-fixture", Path: "Microsoft.Network/virtualNetworks/support-fixture"}
	resourceID := address.ID(scope)
	resourcePath := resourceID + "?api-version=2025-07-01"
	const hiddenTag = "support-fixture-tag-must-stay-private"
	provisioningBody := `{"location":"hosted-support","tags":{"fixture":"` + hiddenTag + `"},"properties":{"addressSpace":{"addressPrefixes":["10.80.0.0/24"]}}}`
	az("put", resourcePath, provisioningBody, ownerToken, "")
	buildGrant := func(pool, target string, expires time.Time) string {
		t.Helper()
		body, err := json.Marshal(identity.HostedSupportRequest{PrincipalID: person, OperatorPool: pool, ResourceID: target, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	path := func(tenant, grant, suffix string) string {
		return "/ocean/tenants/" + tenant + "/supportGrants/" + grant + suffix + "?api-version=2026-11-01"
	}
	started := time.Now().UTC()
	deadline := started.Add(time.Minute)
	grantID := operationID()
	decision, diagnostic := path(owner.TenantID, grantID, ""), path(owner.TenantID, grantID, "/diagnostic")
	body := buildGrant("primary", resourceID, deadline)
	az("get", diagnostic, "", support, "AuthorizationFailed")
	az("put", decision, body, otherOwner, "AuthorizationFailed")
	nonAdmin := sign(owner.TenantID, managementClient, operationID(), origin, nil)
	az("put", decision, body, nonAdmin, "AuthorizationFailed")
	az("put", decision, buildGrant("outside", resourceID, deadline), ownerToken, "InvalidSupportGrant")
	az("put", decision, buildGrant("primary", address.ID(foreign), deadline), ownerToken, "InvalidSupportGrant")
	first := readHostedSupportGrant(t, az("put", decision, body, ownerToken, ""))
	retry := readHostedSupportGrant(t, az("put", decision, body, ownerToken, ""))
	if first.ID != grantID || first.ApprovedBy != owner.Administrator || !first.ExpiresAt.Equal(deadline) || !first.ApprovedAt.Equal(retry.ApprovedAt) {
		t.Fatal("a support approval did not preserve the original named tenant approver")
	}
	az("put", decision, buildGrant("primary", resourceID, deadline.Add(time.Second)), ownerToken, "SupportGrantConflict")
	for _, token := range []string{
		supportToken(origin, supportClient, operationID(), "ocean-support", time.Now()),
		supportToken(origin, supportClient, person, "1", time.Now()),
		supportToken(origin, supportClient, person, "ocean-support", time.Now().Add(-20*time.Minute)),
		supportToken(origin, managementClient, person, "ocean-support", time.Now()),
	} {
		az("get", diagnostic, "", token, "AuthorizationFailed")
	}
	az("get", path(neighbor.TenantID, grantID, "/diagnostic"), "", support, "AuthorizationFailed")
	az("get", resourcePath, "", support, "InvalidAuthenticationToken")
	response := az("get", diagnostic, "", support, "")
	var state identity.HostedSupportDiagnostic
	if err := json.Unmarshal(response, &state); err != nil || state.GrantID != grantID || state.ResourceID != resourceID ||
		state.ProvisioningState != arm.OperationSucceeded || bytes.Contains(response, []byte(hiddenTag)) || bytes.Contains(response, []byte("10.80.0.0")) {
		t.Fatalf("the support response must include only the approved resource state: %v", err)
	}
	partner := operationID()
	az("put", path(owner.TenantID, partner, ""), buildGrant("partner", resourceID, deadline), ownerToken, "")
	partnerPath := path(owner.TenantID, partner, "/diagnostic")
	az("get", partnerPath, "", support, "AuthorizationFailed")
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+partnerPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe.Header.Set("Authorization", "Bearer "+support)
	probe.Header.Set("X-Forwarded-For", "127.0.0.2")
	spoofed, err := httpClient.Do(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := spoofed.Body.Close(); err != nil || spoofed.StatusCode != http.StatusForbidden {
		t.Fatalf("an untrusted forwarded source passed the support pool check: %v", err)
	}
	allow("partner")
	az("get", diagnostic, "", support, "AuthorizationFailed")
	allow("primary", "partner")
	snapshot := takeHostedSMBLabSnapshot(t, ctx, r)
	revoked := readHostedSupportGrant(t, az("delete", decision, "", ownerToken, ""))
	if revoked.RevokedAt.IsZero() || revoked.RevokedBy != owner.Administrator {
		t.Fatal("the revocation did not record the actor and time")
	}
	az("delete", decision, "", ownerToken, "")
	az("put", decision, body, ownerToken, "")
	az("get", diagnostic, "", support, "AuthorizationFailed")
	verifyHostedSupportAudit(t, az, scope, grantID, owner.Administrator, person, resourceID, ownerToken, started,
		"grant/Succeeded", "read/Failed", "read/Failed", "read/Succeeded", "revoke/Succeeded")
	revokedDurability := time.Since(revoked.RevokedAt)

	restoredCfg := restoreHostedSMBLabSnapshot(t, ctx, cfg, archive, snapshot)
	restoredOrigin, _, restoredAz, _ := startHostedRestoreAPI(t, ctx, restoredCfg, cli, operatorRealm, managementClient, issuer.URL, issuer.Certificate(), workers...)
	restoredSupport := supportToken(restoredOrigin, supportClient, person, "ocean-support", time.Now())
	restoredOwner := sign(owner.TenantID, managementClient, owner.Administrator, restoredOrigin, nil)
	restoredAz("get", diagnostic, "", restoredSupport, "AuthorizationFailed")
	recovered := readHostedSupportGrant(t, restoredAz("get", decision, "", restoredOwner, ""))
	if !revoked.RevokedAt.Equal(recovered.RevokedAt) {
		t.Fatal("recovery changed the ledger revocation")
	}
	expires := time.Now().Add(8 * time.Second)
	expiring := operationID()
	restoredAz("put", path(owner.TenantID, expiring, ""), buildGrant("primary", resourceID, expires), restoredOwner, "")
	expiringPath := path(owner.TenantID, expiring, "/diagnostic")
	restoredAz("get", expiringPath, "", restoredSupport, "")
	pollVMWorker(t, ctx, 12*time.Second, "support approval expiry", func() bool { return !time.Now().Before(expires) })
	restoredAz("get", expiringPath, "", restoredSupport, "AuthorizationFailed")
	replaced := operationID()
	restoredAz("put", path(owner.TenantID, replaced, ""), buildGrant("primary", resourceID, time.Now().Add(time.Minute)), restoredOwner, "")
	replacedPath := path(owner.TenantID, replaced, "/diagnostic")
	restoredAz("get", replacedPath, "", restoredSupport, "")
	restoredAz("delete", resourcePath, "", restoredOwner, "")
	restoredAz("put", resourcePath, provisioningBody, restoredOwner, "")
	restoredAz("get", replacedPath, "", restoredSupport, "AuthorizationFailed")
	t.Logf("Azure CLI used one tenant-approved resource diagnostic. Source address, assurance, placement and audience checks limited access. The revocation and attributed activity were observed within %d ms, and an older regional snapshot preserved the revocation. Grants also expired on schedule and could not read a replacement resource with the same ID.", revokedDurability.Milliseconds())
}

func readHostedSupportGrant(t *testing.T, raw []byte) identity.HostedSupportGrant {
	t.Helper()
	var grant identity.HostedSupportGrant
	if err := json.Unmarshal(raw, &grant); err != nil || grant.ID == "" {
		t.Fatalf("invalid hosted support receipt: %v", err)
	}
	return grant
}

func verifyHostedSupportAudit(t *testing.T, az func(string, string, string, string, string) []byte, scope arm.SubscriptionScope,
	id, owner, support, resource, token string, started time.Time, expected ...string) {
	t.Helper()
	query := "eventTimestamp ge '" + started.Add(-time.Second).Format(time.RFC3339Nano) + "' and eventTimestamp le '" +
		time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano) + "' and resourceId eq '" + resource + "'"
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&%%24filter=%s",
		scope.SubscriptionID, url.QueryEscape(query))
	var activity struct {
		Value []struct {
			CorrelationID string
			Caller        string
			ResourceID    string
			OperationName struct{ Value string }
			Status        struct{ Value string }
		}
	}
	if err := json.Unmarshal(az("get", path, "", token, ""), &activity); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, row := range activity.Value {
		if row.CorrelationID != id {
			continue
		}
		action := strings.TrimPrefix(row.OperationName.Value, "Ocean.Hosted/support/")
		actor := owner
		if action == "read" {
			actor = support
		}
		if row.Caller != actor || row.ResourceID != resource {
			t.Fatal("support activity was attributed to a different identity or resource")
		}
		actions = append(actions, action+"/"+row.Status.Value)
	}
	slices.Sort(actions)
	if !slices.Equal(actions, expected) {
		t.Fatalf("the support grant lacks its attributed activity: %v", actions)
	}
}
