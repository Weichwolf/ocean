//go:build e2e

package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestHostedKeycloakOffboarding(t *testing.T) {
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	provider, ca := os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK"), os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK_CA")
	client, secret := os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_CLIENT"), os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_SECRET")
	if archive == "" || cli == "" || provider == "" || ca == "" || client == "" || secret == "" {
		t.Skip("requires disposable Keycloak 26.8.2, pinned etcd and stock Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	kc := newHostedKeycloakFixture(t, ctx, provider, ca, client, secret)
	tenant, neighbor := kc.realm(), kc.realm()
	web, otherWeb := kc.browser(tenant), kc.browser(neighbor)
	if refresh := web.login(); refresh == "" || web.refresh(refresh) != http.StatusOK || kc.onlineSessions(tenant) == 0 {
		t.Fatal("the target realm did not have a live web session and refresh grant")
	}
	refresh := web.login()
	neighborRefresh := otherWeb.login()
	if refresh == "" || neighborRefresh == "" {
		t.Fatal("both browser clients require native refresh grants")
	}
	var providerUnavailable atomic.Bool
	providerUnavailable.Store(true)
	admin := kc.adminProxy(&providerUnavailable, client, secret)
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.id.TenantID, neighbor.id.TenantID)
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-keycloak")
	controller := true
	cfg.OperationController = &controller
	r := openHostedLabRegion(t, ctx, cfg)
	seedHostedLabTenant(t, ctx, r, tenant.id)
	seedHostedLabTenant(t, ctx, r, neighbor.id)
	restoreCfg := restoreHostedSMBLabSnapshot(t, ctx, cfg, archive, takeHostedSMBLabSnapshot(t, ctx, r))
	sourceCtx, stopSource := context.WithCancel(ctx)
	defer stopSource()
	source, sourceHTTP, sourceAz, _ := startHostedLabAPI(t, sourceCtx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate(), &admin)
	path := "/ocean/tenants/" + tenant.id.TenantID + "/offboarding?api-version=2026-11-01"
	operatorToken := sign(operatorRealm, operatorClient, operator, source)
	body := fmt.Sprintf(`{"subscriptionId":%q}`, tenant.id.SubscriptionID)
	sourceAz("put", path, body, sign(tenant.id.TenantID, operatorClient, tenant.id.Administrator, source), "AuthorizationFailed")
	started := time.Now()
	first := hostedIdentityView(t, sourceAz("put", path, body, operatorToken, ""))
	if first.IdentityState != "Pending" || !first.IdentityConfirmedAt.IsZero() || first.Actor != operator || kc.onlineSessions(tenant) == 0 {
		t.Fatal("a stored suspension during a provider outage must report pending identity effects")
	}
	providerUnavailable.Store(false)
	pollVMWorker(t, ctx, 25*time.Second, "Keycloak to confirm the durable suspension", func() bool {
		return hostedIdentityView(t, sourceAz("get", path, "", operatorToken, "")).IdentityState == "Confirmed"
	})
	initialDelay := time.Since(started)
	assertNativeHostedRealmOffboarding(t, kc, web, refresh, tenant)
	if otherWeb.refresh(neighborRefresh) != http.StatusOK || kc.onlineSessions(neighbor) == 0 {
		t.Fatal("suspension disturbed the neighboring realm")
	}
	confirmed := hostedIdentityView(t, sourceAz("put", path, body, operatorToken, ""))
	if !confirmed.DecidedAt.Equal(first.DecidedAt) || !confirmed.IdentityConfirmedAt.After(first.DecidedAt) {
		t.Fatal("a retry did not preserve the original decision and provider evidence")
	}
	assertHostedIdentityAudit(t, ctx, r, tenant.id)
	providerUnavailable.Store(true)
	pollVMWorker(t, ctx, hostedIdentityRecheck+15*time.Second, "a failed provider recheck to invalidate the confirmation", func() bool {
		return hostedIdentityView(t, sourceAz("get", path, "", operatorToken, "")).IdentityState == "Pending"
	})
	providerUnavailable.Store(false)
	pollVMWorker(t, ctx, 15*time.Second, "Keycloak to confirm suspension again after admin recovery", func() bool {
		confirmed = hostedIdentityView(t, sourceAz("get", path, "", operatorToken, ""))
		return confirmed.IdentityState == "Confirmed"
	})
	assertHostedIdentityAudit(t, ctx, r, tenant.id)
	stopSource()
	pollVMWorker(t, ctx, 10*time.Second, "the source controller to stop before the restore", func() bool {
		response, err := sourceHTTP.Get(source + "/readyz")
		if err != nil {
			return true
		}
		_ = response.Body.Close()
		return false
	})
	// Simulate an identity-provider rollback independently of restoring the
	// real pre-suspension regional snapshot.
	kc.adminCall(http.MethodPut, "/admin/realms/"+tenant.id.TenantID, `{"enabled":true}`, http.StatusNoContent)
	reopened := kc.browser(tenant)
	rolledBackRefresh := reopened.login()
	if rolledBackRefresh == "" || kc.onlineSessions(tenant) == 0 {
		t.Fatal("the simulated rollback did not recreate live identity state")
	}
	replayStarted := time.Now()
	origin, _, az, _ := startHostedLabAPI(t, ctx, restoreCfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate(), &admin)
	read := func() hostedIdentityStatus {
		return hostedIdentityView(t, az("get", path, "", sign(operatorRealm, operatorClient, operator, origin), ""))
	}
	pollVMWorker(t, ctx, 25*time.Second, "the restored controller to reconcile the same Keycloak suspension", func() bool {
		view := read()
		return view.IdentityState == "Confirmed" && view.DecidedAt.Equal(first.DecidedAt) && view.IdentityConfirmedAt.After(confirmed.IdentityConfirmedAt)
	})
	replayDelay := time.Since(replayStarted)
	assertNativeHostedRealmOffboarding(t, kc, reopened, rolledBackRefresh, tenant)
	recovered := openHostedLabRegion(t, ctx, restoreCfg)
	assertHostedIdentityAudit(t, ctx, recovered, tenant.id)
	t.Logf("Keycloak 26.8.2 stopped the native browser session and refresh after %d ms, kept the adjacent realm available, and reconciled the snapshot replay against a re-enabled realm after %d ms.", initialDelay.Milliseconds(), replayDelay.Milliseconds())
}

type hostedIdentityStatus struct {
	identity.HostedOffboarding
	IdentityState       string    `json:"identityState"`
	IdentityConfirmedAt time.Time `json:"identityConfirmedAt"`
}

func hostedIdentityView(t *testing.T, raw []byte) hostedIdentityStatus {
	t.Helper()
	var view hostedIdentityStatus
	if err := json.Unmarshal(raw, &view); err != nil || !view.Valid(view.TenantID) {
		t.Fatalf("invalid hosted identity view: %v", err)
	}
	return view
}

type hostedKeycloakFixture struct {
	t           *testing.T
	ctx         context.Context
	client      *http.Client
	origin      string
	adminClient string
	adminSecret string
}

type hostedKeycloakRealm struct {
	id       identity.TenantReservation
	password string
}

const hostedBrowserClient = "ocean-disposable-web"
const hostedBrowserRedirect = "https://app.ocean.test/callback"
const hostedBrowserUser = "hosted-fixture-user"

func newHostedKeycloakFixture(t *testing.T, ctx context.Context, origin, ca, client, secret string) hostedKeycloakFixture {
	t.Helper()
	address, err := url.Parse(origin)
	if err != nil || address.Scheme != "https" || address.Path != "" || address.Host == "" {
		t.Fatal("provide an explicit disposable HTTPS Keycloak origin")
	}
	cert, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(cert) {
		t.Fatal("invalid Keycloak lab CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: trust}}
	t.Cleanup(transport.CloseIdleConnections)
	clientHTTP := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return hostedKeycloakFixture{t: t, ctx: ctx, client: clientHTTP, origin: origin, adminClient: client, adminSecret: secret}
}

func (k hostedKeycloakFixture) adminProxy(unavailable *atomic.Bool, client, secret string) hostedLabIdentityAdmin {
	k.t.Helper()
	upstream, err := url.Parse(k.origin)
	if err != nil {
		k.t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) { request.SetURL(upstream) }, Transport: k.client.Transport}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	k.t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return hostedLabIdentityAdmin{Origin: server.URL, Client: client, SecretFile: secret, CA: ca}
}

func (k hostedKeycloakFixture) call(client *http.Client, method, path, media, body, bearer string) (int, http.Header, []byte) {
	k.t.Helper()
	request, err := http.NewRequestWithContext(k.ctx, method, k.origin+path, strings.NewReader(body))
	if err != nil {
		k.t.Fatal(err)
	}
	request.Header.Set("Content-Type", media)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		k.t.Fatal("the disposable Keycloak request failed")
	}
	defer func() { _ = response.Body.Close() }()
	// The administrative server-info document includes all provider metadata.
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		k.t.Fatal("could not read the disposable Keycloak response")
	}
	return response.StatusCode, response.Header, data
}

func (k hostedKeycloakFixture) adminCall(method, path, body string, expected int) []byte {
	k.t.Helper()
	password, err := os.ReadFile(k.adminSecret)
	if err != nil {
		k.t.Fatal(err)
	}
	defer clear(password)
	form := url.Values{"client_id": {k.adminClient}, "client_secret": {strings.TrimSpace(string(password))}, "grant_type": {"client_credentials"}}
	status, _, data := k.call(k.client, http.MethodPost, "/realms/master/protocol/openid-connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
	var login struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &login); err != nil || status != http.StatusOK || login.AccessToken == "" {
		k.t.Fatalf("Keycloak admin login returned status %d", status)
	}
	status, _, reply := k.call(k.client, method, path, "application/json", body, login.AccessToken)
	if status != expected {
		k.t.Fatalf("disposable Keycloak admin %s returned status %d, expected %d", method, status, expected)
	}
	return reply
}

func (k hostedKeycloakFixture) realm() hostedKeycloakRealm {
	k.t.Helper()
	realm := hostedKeycloakRealm{id: identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()},
		password: "Oc9-" + operationID() + operationID()}
	body, err := json.Marshal(map[string]any{"realm": realm.id.TenantID, "enabled": true, "sslRequired": "all",
		"attributes": map[string]string{"oceanRegistration": realm.id.SubscriptionID},
		"users": []any{map[string]any{"id": realm.id.Administrator, "username": hostedBrowserUser, "enabled": true,
			"firstName": "Hosted", "lastName": "Fixture", "email": hostedBrowserUser + "@ocean.test", "emailVerified": true,
			"credentials": []any{map[string]any{"type": "password", "value": realm.password, "temporary": false}}}},
		"clients": []any{map[string]any{"clientId": hostedBrowserClient, "enabled": true, "publicClient": true, "protocol": "openid-connect",
			"standardFlowEnabled": true, "redirectUris": []string{hostedBrowserRedirect}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"}}}})
	if err != nil {
		k.t.Fatal(err)
	}
	k.adminCall(http.MethodPost, "/admin/realms", string(body), http.StatusCreated)
	k.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		k.ctx = ctx
		path := "/admin/realms/" + realm.id.TenantID
		raw := k.adminCall(http.MethodGet, path, "", http.StatusOK)
		var state struct{ Attributes map[string]string }
		if json.Unmarshal(raw, &state) == nil && state.Attributes["oceanRegistration"] == realm.id.SubscriptionID {
			k.adminCall(http.MethodDelete, path, "", http.StatusNoContent)
		}
	})
	return realm
}

func (k hostedKeycloakFixture) onlineSessions(realm hostedKeycloakRealm) int {
	k.t.Helper()
	path := "/admin/realms/" + realm.id.TenantID + "/users/" + realm.id.Administrator + "/sessions"
	var sessions []json.RawMessage
	if err := json.Unmarshal(k.adminCall(http.MethodGet, path, "", http.StatusOK), &sessions); err != nil {
		k.t.Fatal("invalid Keycloak user session listing")
	}
	return len(sessions)
}

type hostedKeycloakBrowser struct {
	fixture  hostedKeycloakFixture
	client   *http.Client
	realm    hostedKeycloakRealm
	clientID string
}

func (k hostedKeycloakFixture) browser(realm hostedKeycloakRealm) hostedKeycloakBrowser {
	k.t.Helper()
	client := *k.client
	jar, err := cookiejar.New(nil)
	if err != nil {
		k.t.Fatal(err)
	}
	client.Jar = jar
	return hostedKeycloakBrowser{fixture: k, client: &client, realm: realm, clientID: hostedBrowserClient}
}

var hostedKeycloakLoginForm = regexp.MustCompile(`(?i)<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

func (b hostedKeycloakBrowser) login() string {
	b.fixture.t.Helper()
	reply := b.browserTokens()
	if reply.RefreshToken == "" {
		b.fixture.t.Fatal("Keycloak did not issue a native refresh grant")
	}
	return reply.RefreshToken
}

func (b hostedKeycloakBrowser) browserTokens() hostedBrowserTokens {
	b.fixture.t.Helper()
	path, params, verifier := b.authorization()
	status, response, page := b.fixture.call(b.client, http.MethodGet, path+"?"+params.Encode(), "", "", "")
	if status == http.StatusOK {
		status, response, _ = b.submit(page, hostedKeycloakLoginForm,
			url.Values{"username": {hostedBrowserUser}, "password": {b.realm.password}})
	}
	return b.exchange(status, response, params.Get("state"), verifier)
}

func (b hostedKeycloakBrowser) submit(page []byte, pattern *regexp.Regexp, values url.Values) (int, http.Header, []byte) {
	b.fixture.t.Helper()
	form := pattern.FindSubmatch(page)
	if len(form) != 2 {
		b.fixture.t.Fatal("Keycloak did not return the expected browser form")
	}
	endpoint, ok := strings.CutPrefix(html.UnescapeString(string(form[1])), b.fixture.origin)
	if !ok || !strings.HasPrefix(endpoint, "/realms/"+b.realm.id.TenantID+"/login-actions/") {
		b.fixture.t.Fatal("Keycloak returned a form outside the disposable tenant")
	}
	return b.fixture.call(b.client, http.MethodPost, endpoint, "application/x-www-form-urlencoded", values.Encode(), "")
}

type hostedBrowserTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (b hostedKeycloakBrowser) exchange(status int, response http.Header, state, verifier string) hostedBrowserTokens {
	b.fixture.t.Helper()
	callback, ok := strings.CutPrefix(response.Get("Location"), hostedBrowserRedirect+"?")
	query, err := url.ParseQuery(callback)
	if status != http.StatusFound || !ok || err != nil || query.Get("state") != state || query.Get("code") == "" {
		b.fixture.t.Fatalf("Keycloak did not issue a browser authorization code, status %d, callback %t, matching state %t, required action %t",
			status, ok, query.Get("state") == state, strings.Contains(response.Get("Location"), "/required-action"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {b.clientID}, "redirect_uri": {hostedBrowserRedirect},
		"code": {query.Get("code")}, "code_verifier": {verifier}}
	status, _, data := b.token(form)
	var reply hostedBrowserTokens
	if err := json.Unmarshal(data, &reply); err != nil || status != http.StatusOK || reply.AccessToken == "" {
		b.fixture.t.Fatalf("Keycloak did not issue a native access grant, status %d", status)
	}
	return reply
}

func (b hostedKeycloakBrowser) authorization() (string, url.Values, string) {
	verifier := operationID() + operationID()
	challenge := sha256.Sum256([]byte(verifier))
	return "/realms/" + b.realm.id.TenantID + "/protocol/openid-connect/auth", url.Values{
		"client_id": {b.clientID}, "redirect_uri": {hostedBrowserRedirect}, "response_type": {"code"}, "scope": {"openid"},
		"state": {operationID()}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
	}, verifier
}

func (b hostedKeycloakBrowser) token(form url.Values) (int, http.Header, []byte) {
	return b.fixture.call(b.client, http.MethodPost, "/realms/"+b.realm.id.TenantID+"/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", form.Encode(), "")
}

func (b hostedKeycloakBrowser) refresh(value string) int {
	status, _, _ := b.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {b.clientID}, "refresh_token": {value}})
	return status
}

func assertNativeHostedRealmOffboarding(t *testing.T, kc hostedKeycloakFixture, web hostedKeycloakBrowser, refresh string, realm hostedKeycloakRealm) {
	t.Helper()
	if status := web.refresh(refresh); status != http.StatusBadRequest && status != http.StatusForbidden {
		t.Fatalf("the disabled realm did not reject a previous refresh grant, status %d", status)
	}
	if kc.onlineSessions(realm) != 0 {
		t.Fatal("the disabled target realm still has online user sessions")
	}
	for _, browser := range []hostedKeycloakBrowser{web, kc.browser(realm)} {
		path, params, _ := browser.authorization()
		params.Set("prompt", "none")
		status, _, _ := kc.call(browser.client, http.MethodGet, path+"?"+params.Encode(), "", "", "")
		if status != http.StatusBadRequest && status != http.StatusForbidden {
			t.Fatalf("Keycloak did not deny the native authorization request, status %d", status)
		}
	}
}

func assertHostedIdentityAudit(t *testing.T, ctx context.Context, r *Region, tenant identity.TenantReservation) {
	t.Helper()
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	rows, err := r.client.Get(ctx, r.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, row := range rows.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(row.Value, &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == "Ocean.Hosted/offboarding/suspendIdentity" && event.Outcome == arm.OperationSucceeded &&
			event.Target == "/ocean/tenants/"+tenant.TenantID+"/offboarding" && event.Actor == "identity-reconciler" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("want one hosted identity confirmation audit event, got %d", found)
	}
}
