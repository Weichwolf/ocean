//go:build e2e

package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestKeycloakWebAdmissionLab(t *testing.T) {
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	lab := keycloakSambaLab(t, CloudEndpoints{ResourceManager: "https://" + api.Listener.Addr().String()})
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
	apps := []Application{
		{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Samba browser A", WebRedirectURIs: []string{"https://a.apps.ocean.test/oidc"}},
		{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Samba browser B", WebRedirectURIs: []string{"https://b.apps.ocean.test/oidc"}},
	}
	az := startWebPolicyLab(t, lab, api, apps, "")
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
	for index, app := range apps {
		authorization := newBrowserAuthorization(app)
		page := browserCall(t, ctx, &browser, protocol+"/auth?"+authorization.params.Encode(), nil)
		if index == 0 {
			if page.status != http.StatusUnauthorized || page.header.Get("WWW-Authenticate") != "Negotiate" {
				t.Fatalf("the fresh browser did not receive a Kerberos challenge: status %d", page.status)
			}
			page = submitBrowserForm(t, ctx, &browser, issuer, page, nil, url.Values{})
			page = submitBrowserForm(t, ctx, &browser, issuer, page, browserPasswordForm,
				url.Values{"username": {principal}, "password": {lab.value("employee")}})
			page = submitBrowserForm(t, ctx, &browser, issuer, page, browserOTPForm,
				url.Values{"otp": {fixtureOTP(seed)}})
		}
		token := exchangeBrowserCode(t, ctx, &browser, issuer, keys, authorization, page)
		if token.Subject != user || (index != 0 && token.SessionID != firstBrowserSession) {
			t.Fatal("the web apps did not reuse an assured session for the same AD user")
		}
		firstBrowserSession = token.SessionID
	}
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
var browserOTPForm = regexp.MustCompile(`(?i)<form[^>]*id="kc-otp-login-form"[^>]*action="([^"]+)"`)
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

func fixtureOTP(seed []byte) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, seed)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 15)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
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
