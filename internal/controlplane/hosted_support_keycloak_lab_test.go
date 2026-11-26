//go:build e2e

package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
)

func TestHostedSupportKeycloakMFA(t *testing.T) {
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	provider, ca := os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK"), os.Getenv("OCEAN_E2E_HOSTED_KEYCLOAK_CA")
	client, secret := os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_CLIENT"), os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_SECRET")
	if archive == "" || cli == "" || provider == "" || ca == "" || client == "" || secret == "" {
		t.Skip("requires disposable Keycloak 26.8.2, pinned etcd and stock Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	kc := newHostedKeycloakFixture(t, ctx, provider, ca, client, secret)
	var providerInfo struct {
		SystemInfo struct{ Version string }
	}
	if err := json.Unmarshal(kc.adminCall(http.MethodGet, "/admin/serverinfo", "", http.StatusOK), &providerInfo); err != nil ||
		providerInfo.SystemInfo.Version != "26.8.2" {
		t.Fatalf("the support acceptance requires Keycloak 26.8.2: %v", err)
	}
	owner, operator := kc.realm(), kc.realm()
	rawCA, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rawCA)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid disposable Keycloak CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	const assurance = "ocean-support"
	supportClient, ownerClient, managementClient := operationID(), operationID(), operationID()
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-support-native")
	cfg.HostedWorkplace.Support = &hostedSupportPolicy{ClientID: supportClient, AuthContext: assurance,
		Pools: map[string][]netip.Prefix{"primary": {netip.MustParsePrefix("127.0.0.1/32")}}}
	r := openHostedLabRegion(t, ctx, cfg)
	seedHostedLabTenant(t, ctx, r, owner.id)
	origin, _, az, _ := startHostedRestoreAPI(t, ctx, cfg, cli, operator.id.TenantID, managementClient, provider, cert)

	kc.hostedSupportOIDCClient(owner, ownerClient, origin, "", "")
	ownerBrowser := kc.browser(owner)
	ownerBrowser.clientID = ownerClient
	ownerToken := ownerBrowser.browserTokens().AccessToken
	scope := arm.SubscriptionScope{TenantID: owner.id.TenantID, SubscriptionID: owner.id.SubscriptionID}
	resource := arm.ResourceAddress{Group: "retained-fixture", Path: "Microsoft.Network/virtualNetworks/native-support"}
	resourceID := resource.ID(scope)
	az("put", resourceID+"?api-version=2025-07-01",
		`{"location":"hosted-support-native","properties":{"addressSpace":{"addressPrefixes":["10.80.0.0/24"]}}}`, ownerToken, "")
	grant := operationID()
	path := "/ocean/tenants/" + scope.TenantID + "/supportGrants/" + grant
	const version = "?api-version=2026-11-01"
	started := time.Now().UTC()
	request, err := json.Marshal(identity.HostedSupportRequest{PrincipalID: operator.id.Administrator,
		OperatorPool: "primary", ResourceID: resourceID, ExpiresAt: started.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	approved := readHostedSupportGrant(t, az("put", path+version, string(request), ownerToken, ""))
	if approved.ApprovedBy != owner.id.Administrator {
		t.Fatal("the native tenant login was not attributed to the registered approver")
	}
	nativeAccess := path + "/diagnostic" + version
	az("get", nativeAccess, "", ownerToken, "AuthorizationFailed")

	flow := kc.hostedSupportMFAFlow(operator)
	kc.hostedSupportOIDCClient(operator, supportClient, origin, flow, assurance)
	seed := make([]byte, 20)
	rand.Read(seed)
	defer clear(seed)
	kc.enrollHostedSupportOTP(operator, seed)
	browser := kc.browser(operator)
	browser.clientID = supportClient
	status, _, _ := browser.token(url.Values{"grant_type": {"password"}, "client_id": {supportClient},
		"username": {hostedBrowserUser}, "password": {operator.password}})
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		t.Fatalf("Keycloak accepted a direct password grant for the support client: status %d", status)
	}
	beginMFA := time.Now()
	operatorToken := browser.hostedSupportMFATokens(seed).AccessToken
	az("get", resourceID+"?api-version=2025-07-01", "", operatorToken, "InvalidAuthenticationToken")
	var diagnostic identity.HostedSupportDiagnostic
	if err := json.Unmarshal(az("get", nativeAccess, "", operatorToken, ""), &diagnostic); err != nil ||
		diagnostic.ResourceID != resourceID || diagnostic.GrantID != grant || diagnostic.ProvisioningState != arm.OperationSucceeded {
		t.Fatalf("the native MFA token did not receive the approved live resource diagnostic: %v", err)
	}
	mfaDuration := time.Since(beginMFA)
	az("delete", path+version, "", ownerToken, "")
	az("get", nativeAccess, "", operatorToken, "AuthorizationFailed")
	verifyHostedSupportAudit(t, az, scope, grant, owner.id.Administrator, operator.id.Administrator, resourceID, ownerToken, started,
		"grant/Succeeded", "read/Failed", "read/Succeeded", "revoke/Succeeded")
	t.Logf("Keycloak 26.8.2 enforced OTP despite a lower requested ACR, rejected an incorrect code, and issued a native PKCE token that stock Azure CLI used for the audited diagnostic in %d ms. The same token was denied after revocation.", mfaDuration.Milliseconds())
}

func (k hostedKeycloakFixture) hostedSupportOIDCClient(realm hostedKeycloakRealm, id, audience, flow, assurance string) {
	k.t.Helper()
	attributes := map[string]string{"pkce.code.challenge.method": "S256", "access.token.lifespan": "120"}
	client := map[string]any{"clientId": id, "enabled": true, "publicClient": true, "protocol": "openid-connect",
		"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
		"redirectUris": []string{hostedBrowserRedirect}, "attributes": attributes,
		"defaultClientScopes": []string{"basic", "acr"}, "optionalClientScopes": []string{},
		"protocolMappers": []any{map[string]any{"name": "ocean-arm-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{"included.custom.audience": audience, "access.token.claim": "true", "id.token.claim": "false"}}}}
	if flow != "" {
		attributes["acr.loa.map"] = fmt.Sprintf("{%q:2}", assurance)
		attributes["minimum.acr.value"] = assurance
		client["authenticationFlowBindingOverrides"] = map[string]string{"browser": flow}
	}
	k.writeHostedSupportFixture(http.MethodPost, "/admin/realms/"+realm.id.TenantID+"/clients", client, http.StatusCreated)
}

func (k hostedKeycloakFixture) hostedSupportMFAFlow(realm hostedKeycloakRealm) string {
	k.t.Helper()
	path := "/admin/realms/" + realm.id.TenantID + "/authentication"
	create := func(endpoint string, data map[string]any) {
		k.t.Helper()
		k.writeHostedSupportFixture(http.MethodPost, path+endpoint, data, http.StatusCreated)
	}
	browser, stepUp := operationID(), operationID()
	create("/flows", map[string]any{"id": browser, "alias": "ocean-support-browser", "providerId": "basic-flow", "topLevel": true})
	create("/flows", map[string]any{"id": stepUp, "alias": "ocean-support-step-up", "providerId": "basic-flow", "topLevel": false})
	const level = "ocean-support-level-2"
	create("/config", map[string]any{"id": operationID(), "alias": level,
		"config": map[string]string{"loa-condition-level": "2", "loa-max-age": "900"}})
	create("/executions", map[string]any{"id": operationID(), "parentFlow": stepUp, "authenticator": "conditional-level-of-authentication",
		"requirement": "REQUIRED", "priority": 10, "authenticatorConfig": level})
	create("/executions", map[string]any{"id": operationID(), "parentFlow": stepUp, "authenticator": "auth-username-password-form",
		"requirement": "REQUIRED", "priority": 20})
	create("/executions", map[string]any{"id": operationID(), "parentFlow": stepUp, "authenticator": "auth-otp-form",
		"requirement": "REQUIRED", "priority": 30})
	create("/executions", map[string]any{"id": operationID(), "parentFlow": browser, "flowId": stepUp, "authenticatorFlow": true,
		"requirement": "CONDITIONAL", "priority": 10})
	return browser
}

func (k hostedKeycloakFixture) enrollHostedSupportOTP(realm hostedKeycloakRealm, seed []byte) {
	k.t.Helper()
	secret, err := json.Marshal(map[string]string{"value": base32.StdEncoding.EncodeToString(seed)})
	if err != nil {
		k.t.Fatal(err)
	}
	defer clear(secret)
	body := map[string]any{"credentials": []map[string]string{{"type": "otp", "userLabel": "Disposable support probe",
		"secretData": string(secret), "credentialData": `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1","counter":0,"secretEncoding":"BASE32"}`}}}
	k.writeHostedSupportFixture(http.MethodPut, "/admin/realms/"+realm.id.TenantID+"/users/"+realm.id.Administrator, body, http.StatusNoContent)
}

func (k hostedKeycloakFixture) writeHostedSupportFixture(method, path string, body any, expected int) {
	k.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		k.t.Fatal(err)
	}
	defer clear(raw)
	k.adminCall(method, path, string(raw), expected)
}

var hostedSupportOTPForm = regexp.MustCompile(`(?i)<form[^>]*id="kc-otp-login-form"[^>]*action="([^"]+)"`)

func (b hostedKeycloakBrowser) hostedSupportMFATokens(seed []byte) hostedBrowserTokens {
	b.fixture.t.Helper()
	path, params, verifier := b.authorization()
	params.Set("acr_values", "1")
	status, _, page := b.fixture.call(b.client, http.MethodGet, path+"?"+params.Encode(), "", "", "")
	if status != http.StatusOK {
		b.fixture.t.Fatalf("Keycloak did not start the dedicated MFA browser flow: status %d", status)
	}
	status, _, page = b.submit(page, hostedKeycloakLoginForm, url.Values{"username": {hostedBrowserUser}, "password": {b.realm.password}})
	if status != http.StatusOK || !hostedSupportOTPForm.Match(page) {
		b.fixture.t.Fatalf("Keycloak did not require OTP after the password with a lower requested ACR: status %d", status)
	}
	now := time.Now()
	var wrong string
	for value := 0; ; value++ {
		wrong = fmt.Sprintf("%06d", value)
		if wrong != hostedSupportOTP(seed, now.Add(-30*time.Second)) && wrong != hostedSupportOTP(seed, now) &&
			wrong != hostedSupportOTP(seed, now.Add(30*time.Second)) && wrong != hostedSupportOTP(seed, now.Add(time.Minute)) {
			break
		}
	}
	status, _, page = b.submit(page, hostedSupportOTPForm, url.Values{"otp": {wrong}})
	if status != http.StatusOK || !hostedSupportOTPForm.Match(page) {
		b.fixture.t.Fatalf("the incorrect OTP did not leave the browser at its MFA challenge: status %d", status)
	}
	status, response, _ := b.submit(page, hostedSupportOTPForm, url.Values{"otp": {hostedSupportOTP(seed, time.Now())}})
	return b.exchange(status, response, params.Get("state"), verifier)
}

func hostedSupportOTP(seed []byte, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, seed)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
