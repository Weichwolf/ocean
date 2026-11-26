//go:build e2e

package controlplane

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

func TestHostedOperatorPlacement(t *testing.T) {
	client, cli := hostedLabEtcd(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	quota := enrollment.Capacity{CPUMillis: 800, MemoryMiB: 512}
	defaults := PlacementPolicy{Pools: []string{"partner", "primary"}, Quota: quota}
	r := &Region{client: client, root: hostedLabRoot(t, client, "hosted-operator"), name: "hosted", cell: "cell-1",
		hosted:    &hostedRegionPolicy{Country: "DE", OperatorPools: map[string]string{"primary": "DE", "partner": "NL"}},
		workloads: &workloadControl{defaultPlacement: defaults}}
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DisplayName: "Hosted fixture", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	seedHostedPlacementWorker(t, ctx, r, "a-partner", "partner")
	seedHostedPlacementWorker(t, ctx, r, "b-primary", "primary")
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.TenantID)
	api, az := hostedOperatorLabAPI(t, ctx, r, cli, operatorRealm, operatorClient, issuer)
	armOrigin := api.URL
	started := time.Now()
	operatorToken := sign(operatorRealm, operatorClient, operator, armOrigin)
	path := "/ocean/tenants/" + tenant.TenantID + "/placementPolicy?api-version=2026-11-01"
	primaryOnly := `{"pools":["primary"],"quota":{"cpuMillis":800,"memoryMiB":512}}`
	partnerOnly := `{"pools":["partner"],"quota":{"cpuMillis":800,"memoryMiB":512}}`
	az("put", path, primaryOnly, sign(tenant.TenantID, operatorClient, tenant.Administrator, armOrigin), "AuthorizationFailed")
	az("put", path, primaryOnly, sign(operatorRealm, operationID(), operator, armOrigin), "AuthorizationFailed")
	az("get", path, "", sign(operatorRealm, operatorClient, operator, "https://graph.ocean.test"), "InvalidAuthenticationToken")
	az("get", path, "", operatorToken+"x", "InvalidAuthenticationToken")
	az("get", strings.Replace(path, tenant.TenantID, operationID(), 1), "", operatorToken, "ResourceNotFound")
	az("put", path, strings.Replace(primaryOnly, "primary", "outside", 1), operatorToken, "InvalidPlacementPolicy")
	az("put", path, strings.Replace(primaryOnly, `"primary"`, `"primary","primary"`, 1), operatorToken, "InvalidPlacementPolicy")
	az("put", path, strings.Replace(primaryOnly, `"quota"`, `"extra":true,"quota"`, 1), operatorToken, "InvalidRequestContent")
	checkPolicy := func(raw []byte, pools ...string) {
		t.Helper()
		var actual PlacementPolicy
		if err := json.Unmarshal(raw, &actual); err != nil || actual.Quota != quota || !slices.Equal(actual.Pools, pools) {
			t.Fatalf("unexpected placement policy response: %s (%v)", raw, err)
		}
	}
	checkPolicy(az("get", path, "", operatorToken, ""), "partner", "primary")
	checkPolicy(az("put", path, primaryOnly, operatorToken, ""), "primary")
	key := r.armPrefix(scope) + "placement-policy"
	_, revision, err := r.placementPolicy(ctx, key, true)
	if err != nil || revision == 0 {
		t.Fatalf("operator write did not persist the tenant policy: %v", err)
	}
	checkPolicy(az("put", path, primaryOnly, operatorToken, ""), "primary")
	_, replay, err := r.placementPolicy(ctx, key, true)
	if err != nil || revision != replay {
		t.Fatalf("policy replay changed its revision: %v", err)
	}
	guest := PlacementRequest{ID: "guest-test", Cell: r.cell, Role: "compute", Resources: quota, NeedsVMRuntime: true}
	placed, err := r.ReservePlacement(ctx, scope, guest)
	if err != nil || placed.HostID != "b-primary" {
		t.Fatalf("the scheduler did not apply the operator policy: %+v %v", placed, err)
	}
	az("put", path, partnerOnly, operatorToken, "PlacementPolicyInUse")
	az("put", path, strings.Replace(primaryOnly, "800", "799", 1), operatorToken, "QuotaExceeded")
	if err := r.ReleasePlacement(ctx, scope, guest.Cell, guest.ID, placed.Generation); err != nil {
		t.Fatal(err)
	}
	// Simulate the persisted index of an active SMB share without staging data.
	marker := r.smbGroupPrefix(scope, "test") + "existing"
	if _, err := r.client.Put(ctx, marker, "vol-existing"); err != nil {
		t.Fatal(err)
	}
	az("put", path, partnerOnly, operatorToken, "PlacementPolicyInUse")
	if _, err := r.client.Delete(ctx, marker); err != nil {
		t.Fatal(err)
	}
	checkPolicy(az("put", path, partnerOnly, operatorToken, ""), "partner")
	checkPolicy(az("get", path, "", operatorToken, ""), "partner")
	rows, err := r.ListActivity(ctx, scope, "", arm.ActivityFilter{Start: started, End: time.Now()}, 20)
	if err != nil || len(rows) != 4 {
		t.Fatalf("expected two reads and two unique writes in the operator audit: %d %v", len(rows), err)
	}
	actions := make(map[string]int)
	for _, row := range rows {
		if row.Actor != operator || row.Outcome != "Succeeded" || row.Target != "/subscriptions/"+scope.SubscriptionID+"/providers/Ocean.Hosted/placementPolicies/default" {
			t.Fatal("operator audit did not preserve the authorized subject and subscription scope")
		}
		actions[row.Action]++
	}
	if actions["Ocean.Hosted/placementPolicies/read"] != 2 || actions["Ocean.Hosted/placementPolicies/write"] != 2 {
		t.Fatalf("unexpected policy audit actions: %v", actions)
	}
	t.Logf("Azure CLI 2.93.0 applied the pool, validated operator signature, client and audience, and preserved four scoped audit outcomes and one idempotent policy revision. Verification took %d ms.", time.Since(started).Milliseconds())
}

func hostedOperatorLabAPI(t *testing.T, ctx context.Context, r *Region, cli, operatorRealm, operatorClient string,
	issuer *httptest.Server) (*httptest.Server, func(string, string, string, string, string) []byte) {
	t.Helper()
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	armOrigin := "https://" + api.Listener.Addr().String()
	credentials := t.TempDir()
	writePrivate := func(name string, contents []byte) string {
		t.Helper()
		path := filepath.Join(credentials, name)
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	private := writePrivate("onboarding.key", []byte(rand.Text()+rand.Text()))
	compat, err := (identity.Config{Authority: issuer.URL, Provider: issuer.URL,
		ProviderCAFile: writePrivate("issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})),
		Cloud:          &identity.CloudEndpoints{ResourceManager: armOrigin, MicrosoftGraph: "https://graph.ocean.test"}}).OpenCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	compat.EnableSubscriptions(r.name, r.lookupSubscription)
	if err := compat.EnableOnboarding(identity.OnboardingConfig{OperatorTenant: operatorRealm, OperatorClient: operatorClient,
		AdminEndpoints: []string{"https://admin.ocean.test"}, AdminClient: "fixture", AdminSecretFile: private, RegionalKeyFile: private}, r); err != nil {
		t.Fatal(err)
	}
	if err := compat.EnablePlacementPolicies(r); err != nil {
		t.Fatal(err)
	}
	if r.deletionLedger != nil {
		if err := compat.EnableHostedOffboarding(r); err != nil {
			t.Fatal(err)
		}
		if r.storage != nil {
			if err := compat.EnableHostedFilePurge(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	api.Config.Handler = (arm.Server{Origin: armOrigin, Authenticate: compat.AuthenticateARM, Groups: r, Roles: r}).Handler(compat.Handler())
	api.StartTLS()
	apiCA := writePrivate("api.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}))
	return api, regionalWorkerCLI(t, ctx, armOrigin, apiCA, cli)
}

func hostedOperatorIssuer(t *testing.T, realms ...string) (*httptest.Server, func(string, string, string, string) string) {
	t.Helper()
	issuer, sign := hostedClaimsIssuer(t, realms...)
	return issuer, func(realm, client, subject, audience string) string {
		return sign(realm, client, subject, audience, nil)
	}
}

func hostedClaimsIssuer(t *testing.T, realms ...string) (*httptest.Server, func(string, string, string, string, map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, realm := range realms {
			if req.URL.Path != "/realms/"+realm+"/protocol/openid-connect/certs" {
				continue
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string][]map[string]string{"keys": {
				{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture", "n": encode(key.N.Bytes()), "e": "AQAB"},
			}})
			return
		}
		http.NotFound(w, req)
	}))
	t.Cleanup(issuer.Close)
	return issuer, func(realm, client, subject, audience string, extra map[string]any) string {
		t.Helper()
		fields := map[string]any{"iss": issuer.URL + "/realms/" + realm, "aud": audience,
			"azp": client, "sub": subject, "typ": "Bearer", "exp": time.Now().Add(time.Minute).Unix()}
		for name, value := range extra {
			fields[name] = value
		}
		claims, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		unsigned := encode([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + encode(claims)
		digest := sha256.Sum256([]byte(unsigned))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return unsigned + "." + encode(signature)
	}
}
