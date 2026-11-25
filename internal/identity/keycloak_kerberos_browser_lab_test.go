//go:build e2e

package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestKeycloakKerberosBrowserLab(t *testing.T) {
	fixture := os.Getenv("OCEAN_E2E_KERBEROS_BROWSER_STATE")
	if fixture == "" {
		t.Skip("set OCEAN_E2E_KERBEROS_BROWSER_STATE for the disposable domain-browser test")
	}
	paths := make(map[string]string)
	for _, name := range []string{"service.keytab", "employee.ccache", "krb5.conf", "tls.pem"} {
		file := filepath.Join(fixture, name)
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("use a private fixture file for %s: %v", name, err)
		}
		paths[name] = file
	}
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	lab := keycloakSambaLab(t, CloudEndpoints{ResourceManager: "https://" + api.Listener.Addr().String()})
	ctx, admin, tenant := lab.ctx, lab.admin, lab.tenant
	provider := admin.endpoints[0]
	if kerberosServiceHost(provider) == "" {
		t.Fatal("use the DNS origin matching the fixture service principal")
	}
	// Prepare the existing password profile first, then exercise the opt-in
	// upgrade through the same ARM operation used for web publication.
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, lab.directory, lab.connectors, lab.value("reader"), directoryKerberos{}); err != nil {
		t.Fatal(err)
	}
	principal := "employee@" + federationLabDomain
	var users []ldapFixtureUser
	query := url.Values{"username": {principal}, "exact": {"true"}}
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users?"+query.Encode(), nil, &users); err != nil ||
		status != http.StatusOK || len(users) != 1 || users[0].FederationLink != lab.directory.ID {
		t.Fatalf("locate the existing federated identity: status %d, %v", status, err)
	}
	callbackQueries := make(chan string, 1)
	callback, callbackCA := kerberosBrowserCallback(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/oidc" && req.URL.RawQuery != "" {
			select {
			case callbackQueries <- req.URL.RawQuery:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, req)
	}))
	app := Application{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Kerberos browser fixture",
		WebRedirectURIs: []string{callback.URL + "/oidc"}}
	az := startWebPolicyLab(t, lab, api, []Application{app}, paths["service.keytab"])
	path := directoryPath(tenant.TenantID) + "/webApplications/" + app.ID
	groups := []string{lab.value("group-guid")}
	for range 2 {
		payload := az("put", path, groups, "")
		var published struct {
			Properties struct{ ProvisioningState string } `json:"properties"`
		}
		if err := json.Unmarshal(payload, &published); err != nil || published.Properties.ProvisioningState != "Succeeded" {
			t.Fatalf("activate the Kerberos web application: %v", err)
		}
	}
	var existing []struct {
		Provider    string `json:"providerId"`
		Requirement string `json:"requirement"`
	}
	status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/authentication/flows/browser/executions", nil, &existing)
	if err != nil || status != http.StatusOK {
		t.Fatalf("inspect the default browser binding: status %d, %v", status, err)
	}
	spnego := 0
	for _, execution := range existing {
		if execution.Provider == "auth-spnego" {
			spnego++
			if execution.Requirement != "DISABLED" {
				t.Fatal("Kerberos was enabled in the default browser flow")
			}
		}
	}
	if spnego != 1 {
		t.Fatalf("unexpected SPNEGO executions in the default flow: %d", spnego)
	}
	issuer := provider + "/realms/" + tenant.TenantID
	probe := newBrowserAuthorization(app)
	cert := paths["tls.pem"]
	configuration, cache := paths["krb5.conf"], paths["employee.ccache"]
	statusCode, hasCode, _ := kerberosHTTPProbe(t, ctx, issuer, probe, cert, configuration, cache)
	if statusCode != "302" || !hasCode {
		t.Fatalf("the service ticket did not complete the explicit SPNEGO probe: status %s", statusCode)
	}
	authorization := newBrowserAuthorization(app)
	profile := firefoxKerberosProfile(t, ctx, provider, paths["tls.pem"], callbackCA)
	checkpoint := issuer + "/protocol/openid-connect/auth?" + authorization.params.Encode()
	started := time.Now()
	queryResult := runFirefoxKerberos(t, ctx, profile, checkpoint, paths["krb5.conf"], paths["employee.ccache"], callbackQueries)
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, admin.client), issuer+"/protocol/openid-connect/certs")
	page := browserPage{status: http.StatusFound, header: http.Header{"Location": {app.WebRedirectURIs[0] + "?" + queryResult}}}
	identity := exchangeBrowserCode(t, ctx, admin.client, issuer, keys, authorization, page)
	if identity.Subject != users[0].ID {
		t.Fatal("Kerberos created a different user identity from the existing directory account")
	}
	t.Logf("Debian Firefox completed Kerberos/SPNEGO and the signed token check in %s", time.Since(started).Round(time.Millisecond))
	userinfo := issuer + "/protocol/openid-connect/userinfo"
	if status, err := admin.request(ctx, http.MethodGet, userinfo, identity.AccessToken, "", nil, nil); err != nil || status != http.StatusOK {
		t.Fatalf("check the issued browser access token: status %d, %v", status, err)
	}
	member := lab.value("employee-guid")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := sambaFederationGraph(cleanup, lab.primary, "userUpdate", map[string]any{"accountEnabled": true}, member, ""); err != nil {
			t.Error(err)
		}
	})
	started = time.Now()
	if err := sambaFederationGraph(ctx, lab.primary, "userUpdate", map[string]any{"accountEnabled": false}, member, ""); err != nil {
		t.Fatal(err)
	}
	if status, err := admin.request(ctx, http.MethodGet, userinfo, identity.AccessToken, "", nil, nil); err != nil || status != http.StatusUnauthorized {
		t.Fatalf("the issued browser token remained usable at UserInfo after account disable: status %d, %v", status, err)
	}
	t.Logf("UserInfo rejected the previously issued browser token after AD account disable in %s", time.Since(started).Round(time.Millisecond))
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: app.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})
	accessToken, err := verifier.Verify(ctx, identity.AccessToken)
	if err != nil || accessToken.Subject != identity.Subject {
		t.Fatalf("verify the unexpired signed access token offline: %v", err)
	}
	t.Logf("offline token validation still accepted the signature with %s until expiry", time.Until(accessToken.Expiry).Round(time.Millisecond))
	statusCode, hasCode, fallback := kerberosHTTPProbe(t, ctx, issuer, newBrowserAuthorization(app), cert, configuration, cache)
	if hasCode || (statusCode != "401" && (statusCode != "200" || !fallback)) {
		t.Fatalf("a fresh Kerberos request was not denied for the disabled account: status %s", statusCode)
	}
	t.Logf("new Kerberos authorization was denied after AD account disable in %s", time.Since(started).Round(time.Millisecond))
}

func kerberosHTTPProbe(t *testing.T, ctx context.Context, issuer string, auth browserAuthorization, cert, configuration, cache string) (string, bool, bool) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "authentication-response.html")
	command := exec.CommandContext(ctx, "curl", "--negotiate", "--user", ":", "--silent", "--show-error",
		"--max-time", "12", "--cacert", cert, "--output", output, "--write-out", "%{http_code}\n%header{location}",
		issuer+"/protocol/openid-connect/auth?"+auth.params.Encode())
	command.Env = append(os.Environ(), "KRB5_CONFIG="+configuration, "KRB5CCNAME=FILE:"+cache)
	result, err := command.Output()
	status, location, _ := strings.Cut(string(result), "\n")
	if err != nil {
		t.Fatalf("execute the Kerberos probe: status %s, %v", status, err)
	}
	var fallback bool
	if status == "200" {
		body, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		fallback = browserPasswordForm.Match(body)
	}
	return status, strings.HasPrefix(location, auth.app.WebRedirectURIs[0]+"?") && strings.Contains(location, "code="), fallback
}

func kerberosBrowserCallback(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	makeKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	rootKey, serverKey := makeKey(), makeKey()
	validFrom, validUntil := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ocean callback fixture CA"},
		NotBefore: validFrom, NotAfter: validUntil, BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: validFrom, NotAfter: validUntil,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, serverKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	t.Cleanup(server.Close)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: serverKey}}}
	server.StartTLS()
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func firefoxKerberosProfile(t *testing.T, ctx context.Context, origin, providerCert string, callbackCA []byte) string {
	t.Helper()
	profile := t.TempDir()
	callbackCert := filepath.Join(profile, "callback.pem")
	if err := os.WriteFile(callbackCert, callbackCA, 0600); err != nil {
		t.Fatal(err)
	}
	database := "sql:" + profile
	for _, args := range [][]string{
		{"-N", "--empty-password", "-d", database},
		{"-A", "-n", "Ocean fixture issuer", "-i", providerCert, "-t", "C,,", "-d", database},
		{"-A", "-n", "Ocean fixture callback", "-i", callbackCert, "-t", "C,,", "-d", database},
	} {
		if output, err := exec.CommandContext(ctx, "certutil", args...).CombinedOutput(); err != nil {
			t.Fatalf("configure the Firefox certificate database: %v\n%s", err, output)
		}
	}
	prefs := "user_pref(\"network.negotiate-auth.trusted-uris\", " + strconv.Quote(origin) + ");\n" +
		`user_pref("network.negotiate-auth.allow-non-fqdn", true);
user_pref("network.negotiate-auth.delegation-uris", "");
user_pref("network.proxy.type", 0);
`
	if err := os.WriteFile(filepath.Join(profile, "user.js"), []byte(prefs), 0600); err != nil {
		t.Fatal(err)
	}
	return profile
}

func runFirefoxKerberos(t *testing.T, ctx context.Context, profile, address, configuration, cache string, calls <-chan string) string {
	t.Helper()
	browser, err := exec.LookPath("firefox-esr")
	if err != nil {
		t.Fatal(err)
	}
	run, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	process := exec.CommandContext(run, "nice", "-n", "15", browser, "--headless", "--no-remote", "--profile", profile, address)
	var output bytes.Buffer
	process.Stdout, process.Stderr = &output, &output
	process.Env = append(os.Environ(), "KRB5_CONFIG="+configuration, "KRB5CCNAME=FILE:"+cache)
	process.WaitDelay = 3 * time.Second
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var waitError error
	go func() {
		waitError = process.Wait()
		close(exited)
	}()
	select {
	case query := <-calls:
		cancel()
		<-exited
		if !strings.Contains(query, "code=") {
			t.Fatal("Firefox returned without an authorization code")
		}
		return query
	case <-exited:
		t.Fatalf("Firefox exited before the callback: %v\n%s", waitError, &output)
	case <-run.Done():
		<-exited
		t.Fatalf("Firefox did not complete the Kerberos browser flow\n%s", &output)
	}
	return ""
}
