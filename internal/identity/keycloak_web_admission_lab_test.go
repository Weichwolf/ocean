//go:build e2e

package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestKeycloakWebAdmissionLab(t *testing.T) {
	api, graph, authority := httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	for _, server := range []*httptest.Server{api, graph, authority} {
		t.Cleanup(server.Close)
	}
	exchange := newClientSecret()
	lab := keycloakSambaExchangeLab(t, CloudEndpoints{
		ResourceManager: "https://" + api.Listener.Addr().String(), MicrosoftGraph: "https://" + graph.Listener.Addr().String(),
	}, exchange)
	ctx, admin, tenant := lab.ctx, lab.admin, lab.tenant
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, lab.directory, lab.connectors, lab.value("reader"), directoryKerberos{}); err != nil {
		t.Fatal(err)
	}
	principal := "employee@" + federationLabDomain
	var users []ldapFixtureUser
	query := url.Values{"username": {principal}, "exact": {"true"}}
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users?"+query.Encode(), nil, &users); err != nil ||
		status != http.StatusOK || len(users) != 1 || users[0].FederationLink != lab.directory.ID {
		t.Fatalf("locate the federated browser user: status %d, %v", status, err)
	}
	user := users[0].ID
	seed := make([]byte, 20)
	rand.Read(seed)
	secretData, err := json.Marshal(map[string]string{"value": base32.StdEncoding.EncodeToString(seed)})
	if err != nil {
		t.Fatal(err)
	}
	representation := map[string]any{"credentials": []map[string]string{{"type": "otp", "userLabel": "Disposable browser test",
		"secretData": string(secretData), "credentialData": `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1","counter":0,"secretEncoding":"BASE32"}`}}}
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodPut, "/users/"+user, representation, nil); err != nil || status != http.StatusNoContent {
		t.Fatalf("enrol disposable OTP credential: status %d, %v", status, err)
	}
	group := lab.value("group-guid")
	member := lab.value("employee-guid")
	secondName := "WebLab" + newUUID()[:12]
	createGroup := func() string {
		t.Helper()
		created, err := runSambaFederationGraph(ctx, lab.primary, "groupCreate", map[string]any{
			"displayName": secondName, "mailNickname": secondName, "mailEnabled": false, "securityEnabled": true,
		}, "", "")
		if err != nil || created.Status != http.StatusCreated || created.Group == nil {
			t.Fatalf("create the second managed application group: %v", err)
		}
		return created.Group.ID
	}
	deleteGroup := func(ctx context.Context) error {
		_, err := sambaFederationPodman(ctx, "exec", lab.primary, "/bin/sh", "-ec", `
            config=$(find /var/lib/ocean-ad -path '*/etc/smb.conf')
            if /usr/bin/samba-tool group show "$1" -s "$config" >/dev/null 2>&1; then
                exec /usr/bin/samba-tool group delete "$1" -s "$config"
            fi`, "--", secondName)
		return err
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := deleteGroup(cleanup); err != nil {
			t.Error(err)
		}
	})
	secondGroup := createGroup()
	if err := sambaFederationGraph(ctx, lab.primary, "groupMemberAdd", nil, secondGroup, member); err != nil {
		t.Fatal(err)
	}
	command := startAuthenticatedWebPolicyLab(t, lab, api, graph, authority, exchange)
	callback, callbackCA := kerberosBrowserCallback(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/a" && r.URL.Path != "/b") || !r.URL.Query().Has("code") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, "Ocean test callback received")
	}))
	var apps []Application
	for _, suffix := range []string{"a", "b"} {
		name, redirect := "Samba browser "+suffix, callback.URL+"/"+suffix
		var app struct {
			ID          string                          `json:"id"`
			AppID       string                          `json:"appId"`
			DisplayName string                          `json:"displayName"`
			Web         struct{ RedirectURIs []string } `json:"web"`
		}
		created := command("", "ad", "app", "create", "--display-name", name, "--sign-in-audience", "AzureADMyOrg", "--web-redirect-uris", redirect, "-o", "json")
		if err := json.Unmarshal(created, &app); err != nil || !tenantID.MatchString(app.ID) || !tenantID.MatchString(app.AppID) ||
			app.ID == app.AppID || app.DisplayName != name || !slices.Equal(app.Web.RedirectURIs, []string{redirect}) {
			t.Fatalf("validate the registered web application: %v", err)
		}
		apps = append(apps, Application{TenantID: tenant.TenantID, ID: app.ID, ClientID: app.AppID,
			DisplayName: app.DisplayName, WebRedirectURIs: app.Web.RedirectURIs})
	}
	if apps[0].ID == apps[1].ID || apps[0].ClientID == apps[1].ClientID {
		t.Fatal("the CLI registrations shared an application or client identity")
	}
	t.Log("the authenticated Azure CLI created both browser client registrations through Graph")
	az := func(method, path string, groups []string, wantError string) []byte {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", api.URL + path + "?api-version=" + directoryAPIVersion, "-o", "json"}
		if groups != nil {
			body, err := json.Marshal(map[string][]string{"groupIds": groups})
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--body", string(body))
		}
		return command(wantError, args...)
	}
	policyPath := func(tenantID, applicationID string) string {
		return directoryPath(tenantID) + "/webApplications/" + applicationID
	}
	firstPath := policyPath(tenant.TenantID, apps[0].ID)
	az("put", firstPath, []string{group, group}, "InvalidGroupIds")
	az("put", firstPath, []string{newUUID()}, "InvalidDirectoryGroup")
	az("put", policyPath(newUUID(), apps[0].ID), []string{group}, "AuthorizationFailed")
	for index, app := range apps {
		grant := []string{group, secondGroup}[index]
		output := az("put", policyPath(tenant.TenantID, app.ID), []string{grant}, "")
		var policy struct {
			AppID      string `json:"appId"`
			Properties struct {
				Issuer string `json:"issuer"`
				State  string `json:"provisioningState"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(output, &policy); err != nil || policy.AppID != app.ClientID || policy.Properties.State != "Succeeded" ||
			policy.Properties.Issuer != admin.endpoints[0]+"/realms/"+tenant.TenantID {
			t.Fatalf("the published web application policy did not match the registration: %v", err)
		}
	}
	az("put", firstPath, []string{secondGroup}, "WebApplicationPolicyConflict")
	az("put", firstPath, []string{group}, "")
	az("get", firstPath, nil, "")

	browser := *admin.client
	browser.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer := admin.endpoints[0] + "/realms/" + tenant.TenantID
	protocol := issuer + "/protocol/openid-connect"
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, &browser), protocol+"/certs")
	unscoped := browser
	unscoped.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	outsider := newBrowserAuthorization(apps[0])
	page := browserCall(t, ctx, &unscoped, protocol+"/auth?"+outsider.params.Encode(), nil)
	page = submitBrowserForm(t, ctx, &unscoped, issuer, page, nil, url.Values{})
	page = submitBrowserForm(t, ctx, &unscoped, issuer, page, browserPasswordForm,
		url.Values{"username": {"outsider@" + federationLabDomain}, "password": {lab.value("outsider")}})
	if page.header.Get("Location") != "" || !browserPasswordForm.Match(page.body) {
		t.Fatalf("the out-of-scope account bypassed the password form: status %d", page.status)
	}
	foreignCallback := newBrowserAuthorization(apps[0])
	foreignCallback.params.Set("redirect_uri", apps[1].WebRedirectURIs[0])
	if page := browserCall(t, ctx, &browser, protocol+"/auth?"+foreignCallback.params.Encode(), nil); page.status != http.StatusBadRequest || page.header.Get("Location") != "" {
		t.Fatalf("the client accepted a different application's callback: status %d", page.status)
	}
	weakPKCE := newBrowserAuthorization(apps[0])
	weakPKCE.params.Set("code_challenge_method", "plain")
	if page := browserCall(t, ctx, &browser, protocol+"/auth?"+weakPKCE.params.Encode(), nil); page.status != http.StatusBadRequest && !strings.Contains(page.header.Get("Location"), "error=") {
		t.Fatalf("the client accepted a plain PKCE challenge: status %d", page.status)
	}
	var firstBrowserSession string
	authorizations := []browserAuthorization{newBrowserAuthorization(apps[0]), newBrowserAuthorization(apps[1])}
	callbacks := externalMFABrowser(t, ctx, issuer, admin.endpoints[0], callbackCA, principal, lab.value("employee"), seed, authorizations, browser.Jar)
	for index, authorization := range authorizations {
		page := browserPage{status: http.StatusFound, header: http.Header{"Location": {callbacks[index]}}}
		token := exchangeBrowserCode(t, ctx, &browser, issuer, keys, authorization, page)
		if token.Subject != user || (index != 0 && token.SessionID != firstBrowserSession) {
			t.Fatal("the web apps did not reuse an assured session for the same AD user")
		}
		firstBrowserSession = token.SessionID
	}
	t.Log("the two CLI-registered clients issued separate audiences for one LDAP subject and one MFA session")
	started := time.Now()
	if err := sambaFederationGraph(ctx, lab.primary, "groupMemberRemove", nil, secondGroup, member); err != nil {
		t.Fatal(err)
	}
	authorization := newBrowserAuthorization(apps[1])
	denied := browserCall(t, ctx, &browser, protocol+"/auth?"+authorization.params.Encode(), nil)
	if denied.status != http.StatusUnauthorized || denied.header.Get("WWW-Authenticate") != "" || denied.header.Get("Location") != "" {
		t.Fatalf("the revoked browser session was not denied at admission: status %d", denied.status)
	}
	t.Logf("the affected app denied a new code through the existing cookie after AD group removal in %s", time.Since(started).Round(time.Millisecond))
	authorization = newBrowserAuthorization(apps[0])
	allowed := browserCall(t, ctx, &browser, protocol+"/auth?"+authorization.params.Encode(), nil)
	if token := exchangeBrowserCode(t, ctx, &browser, issuer, keys, authorization, allowed); token.SessionID != firstBrowserSession {
		t.Fatal("revoking the second application's group disturbed the first app's session")
	}
	if err := deleteGroup(ctx); err != nil {
		t.Fatal(err)
	}
	recreated := createGroup()
	if recreated == secondGroup {
		t.Fatal("the recreated group unexpectedly retained the original native GUID")
	}
	if err := sambaFederationGraph(ctx, lab.primary, "groupMemberAdd", nil, recreated, member); err != nil {
		t.Fatal(err)
	}
	authorization = newBrowserAuthorization(apps[1])
	denied = browserCall(t, ctx, &browser, protocol+"/auth?"+authorization.params.Encode(), nil)
	if denied.status != http.StatusUnauthorized || denied.header.Get("WWW-Authenticate") != "" || denied.header.Get("Location") != "" {
		t.Fatalf("the recreated group inherited the earlier grant: status %d", denied.status)
	}
}

func externalMFABrowser(t *testing.T, ctx context.Context, issuer, origin string, callbackCA []byte, user, password string, seed []byte,
	authorizations []browserAuthorization, cookies http.CookieJar) []string {
	t.Helper()
	home := t.TempDir()
	callbackCert := filepath.Join(home, "callback-ca.pem")
	if err := os.WriteFile(callbackCert, callbackCA, 0600); err != nil {
		t.Fatal(err)
	}
	var addresses, redirects []string
	for _, auth := range authorizations {
		addresses = append(addresses, issuer+"/protocol/openid-connect/auth?"+auth.params.Encode())
		redirects = append(redirects, auth.params.Get("redirect_uri"))
	}
	config, err := json.Marshal(map[string]any{
		"home": home, "issuer": issuer, "issuerOrigin": origin, "user": user, "password": password, "otpSeed": seed,
		"addresses": addresses, "redirects": redirects,
		"certificates": map[string]string{"Ocean issuer": os.Getenv("SSL_CERT_FILE"), "Ocean callback": callbackCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	probe, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, "node", filepath.Join("..", "..", "tests", "e2e", "web_mfa_browser.mjs"))
	command.Stdin = bytes.NewReader(config)
	output, err := command.Output()
	if failure, ok := err.(*exec.ExitError); ok {
		t.Fatalf("external browser MFA: %v\n%s", failure, failure.Stderr)
	}
	if err != nil {
		t.Fatal(err)
	}
	var evidence struct {
		Redirects []string `json:"redirects"`
		Cookies   []struct {
			Name, Value, Path string
			Secure, HTTPOnly  bool
		} `json:"cookies"`
		Product string `json:"product"`
	}
	if err := json.Unmarshal(output, &evidence); err != nil || len(evidence.Redirects) != len(authorizations) || len(evidence.Cookies) == 0 || evidence.Product == "" {
		t.Fatalf("read the native MFA browser evidence: %v", err)
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range evidence.Cookies {
		parsed, err := http.ParseCookie(cookie.Name + "=" + cookie.Value)
		if err != nil || len(parsed) != 1 || parsed[0].Name != cookie.Name {
			t.Fatal("Chromium returned an invalid browser session cookie")
		}
		parsed[0].Path, parsed[0].Secure, parsed[0].HttpOnly = cookie.Path, cookie.Secure, cookie.HTTPOnly
		cookies.SetCookies(issuerURL, parsed)
	}
	t.Logf("external MFA and both redirects completed in %s with no domain ticket", evidence.Product)
	return evidence.Redirects
}

type browserAuthorization struct {
	app      Application
	verifier string
	params   url.Values
}

func newBrowserAuthorization(app Application) browserAuthorization {
	verifier := newClientSecret() + newClientSecret()
	challenge := sha256.Sum256([]byte(verifier))
	return browserAuthorization{app: app, verifier: verifier, params: url.Values{
		"client_id": {app.ClientID}, "redirect_uri": {app.WebRedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid"},
		"nonce": {newUUID()}, "state": {newUUID()}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
	}}
}

type browserPage struct {
	status int
	header http.Header
	body   []byte
}

func browserCall(t *testing.T, ctx context.Context, browser *http.Client, endpoint string, form url.Values) browserPage {
	t.Helper()
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil {
		t.Fatal(err)
	}
	return browserPage{response.StatusCode, response.Header, data}
}

var browserPasswordForm = regexp.MustCompile(`(?i)<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)
var fallbackBrowserForm = regexp.MustCompile(`(?i)<form[^>]*action="([^"]+)"`)

func submitBrowserForm(t *testing.T, ctx context.Context, browser *http.Client, issuer string, page browserPage, field *regexp.Regexp, form url.Values) browserPage {
	t.Helper()
	if field == nil {
		field = fallbackBrowserForm
	}
	matches := field.FindSubmatch(page.body)
	if len(matches) != 2 {
		t.Fatalf("browser response %d lacked form %s", page.status, field)
	}
	endpoint := html.UnescapeString(string(matches[1]))
	if !strings.HasPrefix(endpoint, issuer+"/login-actions/") {
		t.Fatal("the provider returned a form outside the tenant issuer")
	}
	return browserCall(t, ctx, browser, endpoint, form)
}

type browserIdentity struct {
	Subject     string `json:"-"`
	AccessToken string `json:"-"`
	SessionID   string `json:"sid"`
	ACR         string `json:"acr"`
}

func exchangeBrowserCode(t *testing.T, ctx context.Context, browser *http.Client, issuer string, keys oidc.KeySet,
	auth browserAuthorization, page browserPage) browserIdentity {
	t.Helper()
	location := page.header.Get("Location")
	callback := auth.params.Get("redirect_uri")
	if page.status != http.StatusFound || !strings.HasPrefix(location, callback+"?") {
		t.Fatalf("authorization status %d did not return the registered callback", page.status)
	}
	result, err := url.Parse(location)
	if err != nil || result.Query().Get("state") != auth.params.Get("state") || result.Query().Get("code") == "" {
		t.Fatalf("the browser authorization lacked its verified state and code: status %d", page.status)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {auth.app.ClientID}, "redirect_uri": {callback},
		"code": {result.Query().Get("code")}, "code_verifier": {auth.verifier}}
	issued := browserCall(t, ctx, browser, issuer+"/protocol/openid-connect/token", form)
	var reply struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(issued.body, &reply); err != nil || issued.status != http.StatusOK || reply.AccessToken == "" || reply.IDToken == "" || reply.RefreshToken != "" {
		t.Fatalf("exchange browser authorization code: status %d, %v", issued.status, err)
	}
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: auth.app.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})
	token, err := verifier.Verify(ctx, reply.IDToken)
	if err != nil || token.Nonce != auth.params.Get("nonce") || len(token.Audience) != 1 {
		t.Fatalf("the browser ID token failed verification: %v", err)
	}
	var identity browserIdentity
	if err := token.Claims(&identity); err != nil || identity.SessionID == "" || identity.ACR != "ocean-web" {
		t.Fatalf("the browser session did not satisfy its required assurance: %v", err)
	}
	identity.Subject = token.Subject
	identity.AccessToken = reply.AccessToken
	return identity
}
