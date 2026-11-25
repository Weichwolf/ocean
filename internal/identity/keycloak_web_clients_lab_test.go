//go:build e2e

package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func keycloakTenantLab(t *testing.T, cloud CloudEndpoints) (context.Context, keycloakAdmin, TenantReservation, CloudEndpoints, onboardingRequest) {
	t.Helper()
	return keycloakTenantExchangeLab(t, cloud, newClientSecret())
}

func keycloakTenantExchangeLab(t *testing.T, cloud CloudEndpoints, exchange string) (context.Context, keycloakAdmin, TenantReservation, CloudEndpoints, onboardingRequest) {
	t.Helper()
	origin := os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_ORIGIN")
	if origin == "" {
		t.Skip("set OCEAN_E2E_KEYCLOAK_ADMIN_ORIGIN for the disposable Keycloak instance")
	}
	if !httpsOrigin(origin) {
		t.Fatal("the disposable Keycloak origin must use HTTPS")
	}
	secret, err := readPrivateFile(os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if endpoint := os.Getenv("OCEAN_E2E_KEYCLOAK_LOOPBACK"); endpoint != "" {
		address, err := netip.ParseAddrPort(endpoint)
		if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 {
			t.Fatal("the Keycloak lab route must be a loopback address and port")
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target == strings.TrimPrefix(origin, "https://") {
				target = endpoint
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
		}}
		client.Transport = transport
		t.Cleanup(transport.CloseIdleConnections)
	}
	admin := keycloakAdmin{client: client, endpoints: []string{origin},
		clientID: os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_CLIENT"), secret: secret}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	t.Cleanup(cancel)
	tenant := newUUID()
	registration := TenantReservation{TenantID: tenant, Administrator: newUUID(), SubscriptionID: newUUID(), Fingerprint: newUUID()}
	input := onboardingRequest{DisplayName: "Ocean browser fixture", AdministratorUPN: "fixture-admin@ocean.test",
		AdministratorPassword: strings.Repeat("Oc9-"+newUUID(), 2)}
	if cloud.ResourceManager == "" {
		cloud.ResourceManager = "https://arm.ocean.test"
	}
	if cloud.MicrosoftGraph == "" {
		cloud.MicrosoftGraph = "https://graph.ocean.test"
	}
	fixture := tenantRealm(registration, input, cloud, exchange)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		var realm struct {
			Attributes map[string]string `json:"attributes"`
		}
		status, err := admin.directoryRequest(cleanup, tenant, http.MethodGet, "", nil, &realm)
		if err != nil || (status != http.StatusOK && status != http.StatusNotFound) {
			t.Errorf("check disposable realm ownership: status %d, %v", status, err)
			return
		}
		if status == http.StatusNotFound || realm.Attributes["oceanRegistration"] != registration.SubscriptionID {
			return
		}
		if status, err := admin.directoryRequest(cleanup, tenant, http.MethodDelete, "", nil, nil); err != nil || status != http.StatusNoContent {
			t.Errorf("delete disposable realm: status %d, %v", status, err)
		}
	})
	if err := admin.ensureRealm(ctx, registration, fixture); err != nil {
		t.Fatal(err)
	}
	return ctx, admin, registration, cloud, input
}

func TestKeycloakWebClientsLab(t *testing.T) {
	ctx, admin, registration, cloud, _ := keycloakTenantLab(t, CloudEndpoints{})
	tenant, origin := registration.TenantID, admin.endpoints[0]
	profile, err := admin.ensureWebBrowserProfile(ctx, registration)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := admin.ensureWebBrowserProfile(ctx, registration); err != nil || replay != profile {
		t.Fatalf("replay the dedicated browser profile: %v", err)
	}
	var realm struct {
		BrowserFlow string `json:"browserFlow"`
	}
	if status, err := admin.directoryRequest(ctx, tenant, http.MethodGet, "", nil, &realm); err != nil ||
		status != http.StatusOK || realm.BrowserFlow != "browser" {
		t.Fatalf("the default realm browser binding changed: status %d, %v", status, err)
	}
	prepare := func(app Application) (string, error) {
		return admin.reconcileWebClient(ctx, app, profile.BrowserID, keycloakWebScope{})
	}
	first := Application{TenantID: tenant, ID: newUUID(), ClientID: newUUID(), DisplayName: "Web fixture A",
		WebRedirectURIs: []string{"https://first.apps.ocean.test/oidc/callback"}}
	second := Application{TenantID: tenant, ID: newUUID(), ClientID: newUUID(), DisplayName: "Web fixture B",
		WebRedirectURIs: []string{"https://second.apps.ocean.test/oidc/callback"}}
	firstID, err := prepare(first)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := prepare(second)
	if err != nil || secondID == firstID {
		t.Fatalf("prepare a separate client: got %q, %v", secondID, err)
	}
	if replay, err := prepare(first); err != nil || replay != firstID {
		t.Fatalf("prepare the same client again: got %q, %v", replay, err)
	}

	changed := first
	changed.WebRedirectURIs = second.WebRedirectURIs
	if _, err := prepare(changed); err == nil {
		t.Fatal("preparation accepted a change to the exact callback")
	}
	changed = first
	changed.ID = newUUID()
	if _, err := prepare(changed); err == nil {
		t.Fatal("preparation adopted a different Graph object")
	}
	if _, err := admin.ensureServicePrincipal(ctx, first, CloudEndpoints{}, "unused"); err == nil {
		t.Fatal("a web client was adopted as a service principal")
	}
	if replay, err := prepare(first); err != nil || replay != firstID {
		t.Fatalf("a rejected request changed the prepared client: got %q, %v", replay, err)
	}
	automation := Application{TenantID: tenant, ID: newUUID(), ClientID: newUUID(), DisplayName: "Automation fixture"}
	secret := newClientSecret()
	subject, err := admin.ensureServicePrincipal(ctx, automation, cloud, secret)
	if err != nil {
		t.Fatal(err)
	}
	changed = automation
	changed.WebRedirectURIs = first.WebRedirectURIs
	if _, err := prepare(changed); err == nil {
		t.Fatal("preparation adopted an existing service principal client")
	}
	if replay, err := admin.ensureServicePrincipal(ctx, automation, cloud, secret); err != nil || replay != subject {
		t.Fatalf("a rejected request changed the service principal: got %q, %v", replay, err)
	}
	for _, app := range []Application{first, second} {
		challenge := sha256.Sum256([]byte(newUUID() + newUUID()))
		query := url.Values{"client_id": {app.ClientID}, "redirect_uri": {app.WebRedirectURIs[0]},
			"response_type": {"code"}, "scope": {"openid"}, "code_challenge_method": {"S256"},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
		endpoint := origin + "/realms/" + tenant + "/protocol/openid-connect/auth?" + query.Encode()
		if status, err := admin.request(ctx, http.MethodGet, endpoint, "", "", nil, nil); err != nil || status != http.StatusBadRequest {
			t.Fatalf("authorize without a published policy: status %d, %v", status, err)
		}
	}
}
