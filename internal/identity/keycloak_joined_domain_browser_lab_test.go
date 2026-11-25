//go:build e2e

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/coreos/go-oidc/v3/oidc"
)

func TestKeycloakDebianDomainBrowserLab(t *testing.T) {
	testKeycloakJoinedDomainBrowserLab(t, "Debian Firefox")
}

func TestKeycloakWindowsDomainBrowserLab(t *testing.T) {
	if os.Getenv("OCEAN_E2E_JOINED_WEB_WINDOWS") != "1" {
		t.Skip("provide the disposable Windows domain employee desktop")
	}
	testKeycloakJoinedDomainBrowserLab(t, "Windows Edge")
}

func testKeycloakJoinedDomainBrowserLab(t *testing.T, browser string) {
	t.Helper()
	fixture, state := os.Getenv("OCEAN_E2E_JOINED_WEB_STATE"), os.Getenv("OCEAN_E2E_DOMAIN_STATE")
	if fixture == "" || state == "" {
		t.Skip("provide the enabled two-controller and joined browser fixture")
	}
	keytab := filepath.Join(fixture, "service.keytab")
	if info, err := os.Stat(keytab); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("use a private regular service keytab: %v", err)
	}
	value := func(name string) string {
		t.Helper()
		text, err := readPrivateFile(filepath.Join(fixture, name))
		if err != nil || text == "" {
			t.Fatalf("read joined browser fixture %s: %v", name, err)
		}
		return text
	}
	const domain = "ad.ocean.test"
	const employee = "webemployee@" + domain
	const group = "OceanWebJoined"
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	ctx, admin, tenant, cloud, firstAdmin := keycloakTenantLab(t, CloudEndpoints{ResourceManager: "https://" + api.Listener.Addr().String()})
	origin := admin.endpoints[0]
	host := kerberosServiceHost(origin)
	if host != "oauth."+domain {
		t.Fatal("use the configured DNS origin of the joined browser fixture")
	}
	root := filepath.Join("..", "..")
	labTool := filepath.Join(root, "bin", "ocean-lab")
	groupLookup := func(ctx context.Context, id string) (enrollment.DirectoryGraphResult, error) {
		command := exec.CommandContext(ctx, labTool, "ssh", "-state", state, "farm-1-node-01", "--", "sudo samba-tool group show "+group)
		output, err := command.Output()
		if err != nil {
			return enrollment.DirectoryGraphResult{}, errors.New("read the Samba security group over the management connection")
		}
		fields := strings.Split(string(output), "\n")
		var matchingID, security bool
		for _, field := range fields {
			matchingID = matchingID || strings.EqualFold(field, "objectGUID: "+id)
			security = security || strings.HasPrefix(field, "groupType: -")
		}
		if !matchingID || !security {
			return enrollment.DirectoryGraphResult{Status: http.StatusNotFound}, nil
		}
		return enrollment.DirectoryGraphResult{Status: http.StatusOK, Group: &enrollment.DirectoryGroupView{ID: id, Security: true}}, nil
	}
	directory := ManagedDirectory{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID, ID: value("directory-id"),
		Spec:        DirectorySpec{DNSName: domain, NetBIOSName: "OCEANLAB", SubnetID: "/fixture/subnet"},
		RequestedAt: time.Now().Add(-time.Minute), ProvisionedAt: time.Now(), DomainSID: value("sid")}
	connectors := [2]string{"ldaps://127.0.0.1:" + value("port1"), "ldaps://127.0.0.1:" + value("port2")}
	lab := sambaDirectoryLab{ctx: ctx, admin: admin, tenant: tenant, directory: directory, connectors: connectors, cloud: cloud,
		firstAdmin: firstAdmin, readerFile: filepath.Join(fixture, "reader"), group: groupLookup}
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, directory, connectors, value("reader"), directoryKerberos{}); err != nil {
		t.Fatal(err)
	}
	var users []ldapFixtureUser
	query := url.Values{"username": {employee}, "exact": {"true"}}
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users?"+query.Encode(), nil, &users); err != nil ||
		status != http.StatusOK || len(users) != 1 || users[0].FederationLink != directory.ID {
		t.Fatalf("read the federated employee: status %d, %v", status, err)
	}
	queries := make(chan string, 1)
	var complete atomic.Bool
	receiveCode := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/oidc" && req.URL.Query().Get("code") != "":
			select {
			case queries <- req.URL.RawQuery:
				complete.Store(true)
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		case req.URL.Path == "/complete" && complete.Load():
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, req)
		}
	})
	var callback *httptest.Server
	var callbackCA []byte
	var callbackOrigin string
	if browser == "Windows Edge" {
		callback = windowsBrowserCallback(t, fixture, receiveCode)
		callbackOrigin = "https://" + host + ":18444"
	} else {
		callback, callbackCA = kerberosBrowserCallback(t, receiveCode)
		callbackOrigin = callback.URL
	}
	app := Application{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Joined " + browser + " browser",
		WebRedirectURIs: []string{callbackOrigin + "/oidc"}}
	az := startWebPolicyLab(t, lab, api, []Application{app}, keytab)
	output := az("put", directoryPath(tenant.TenantID)+"/webApplications/"+app.ID, []string{value("group-guid")}, "")
	var published struct {
		Properties struct{ ProvisioningState string } `json:"properties"`
	}
	if err := json.Unmarshal(output, &published); err != nil || published.Properties.ProvisioningState != "Succeeded" {
		t.Fatalf("activate the joined-browser Kerberos policy: %v", err)
	}
	ca, err := os.ReadFile(filepath.Join(fixture, "tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	issuer := origin + "/realms/" + tenant.TenantID
	authorization := newBrowserAuthorization(app)
	realm := strings.ToUpper(domain)
	principal, ticket := "webemployee@"+realm, "HTTP/"+host+"@"+realm
	config := map[string]any{"user": employee, "principal": principal, "servicePrincipal": ticket,
		"authorize": issuer + "/protocol/openid-connect/auth?" + authorization.params.Encode(), "completed": callbackOrigin + "/complete"}
	var result joinedBrowserResult
	if browser == "Windows Edge" {
		config["run"], config["domain"], config["realm"], config["account"], config["serviceHost"] = newUUID(), domain, realm, "webemployee", host
		result = joinedEdge(t, ctx, root, state, value("primary-ssh-port"), callback.Listener.Addr().String(), config)
	} else {
		config["password"], config["origin"], config["providerCA"], config["callbackCA"] = value("employee"), origin, ca, callbackCA
		config["ticketGrantingPrincipal"] = "krbtgt/" + realm + "@" + realm
		result = joinedFirefox(t, ctx, root, state, value("guest-ssh-port"), callback.Listener.Addr().String(), config)
	}
	if result.User != employee || result.Principal != principal || result.ServicePrincipal != ticket || result.DurationMS <= 0 ||
		(result.Encryption != "aes128-cts-hmac-sha1-96" && result.Encryption != "aes256-cts-hmac-sha1-96") {
		t.Fatal("the guest did not acquire the expected HTTP service ticket in the employee's domain session")
	}
	select {
	case response := <-queries:
		keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, admin.client), issuer+"/protocol/openid-connect/certs")
		page := browserPage{status: http.StatusFound, header: http.Header{"Location": {app.WebRedirectURIs[0] + "?" + response}}}
		identity := exchangeBrowserCode(t, ctx, admin.client, issuer, keys, authorization, page)
		if identity.Subject != users[0].ID {
			t.Fatal("the signed browser session did not preserve the existing AD subject")
		}
	default:
		t.Fatal("the browser did not return an authorization code")
	}
	t.Logf("joined %s acquired the %s HTTP ticket and reached the OIDC callback in %d ms from browser launch", browser, result.Encryption, result.DurationMS)
}

type joinedBrowserResult struct {
	User             string `json:"user"`
	Principal        string `json:"principal"`
	ServicePrincipal string `json:"servicePrincipal"`
	Encryption       string `json:"encryption"`
	DurationMS       int    `json:"durationMs"`
	EdgeVersion      string `json:"edgeVersion"`
	WindowsEdition   string `json:"windowsEdition"`
	ErrorStage       string `json:"errorStage"`
	Message          string `json:"message"`
}

func joinedFirefox(t *testing.T, ctx context.Context, root, state, port, callback string, config map[string]any) joinedBrowserResult {
	t.Helper()
	if parsed, err := strconv.ParseUint(port, 10, 16); err != nil || parsed == 0 {
		t.Fatal("the joined Debian SSH port must be numeric")
	}
	source, err := os.ReadFile(filepath.Join(root, "lab", "debian_web_browser.py"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	run := `set -eu
sudo adcli testjoin --domain ad.ocean.test
umask 077
workspace=$(mktemp -d)
trap 'unlink "$workspace/probe.py"; rmdir "$workspace"' EXIT
printf '%s' '` + base64.StdEncoding.EncodeToString(source) + `' | base64 -d > "$workspace/probe.py"
python3 "$workspace/probe.py" "$workspace/probe.py"`
	short, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	command := exec.CommandContext(short, "ssh", "-T", "-p", port, "-i", filepath.Join(state, "ssh-key"),
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5",
		"-o", "ExitOnForwardFailure=yes", "-o", "UserKnownHostsFile="+filepath.Join(state, "known-hosts"),
		"-o", "HostKeyAlias=farm-1-node-02", "-R", callback+":"+callback, "ocean@127.0.0.1", run)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run the joined guest's PAM browser probe: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if record, found := strings.CutPrefix(line, "OCEAN_BROWSER "); found {
			var result joinedBrowserResult
			if err := json.Unmarshal([]byte(record), &result); err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	t.Fatal("the joined guest did not return browser evidence")
	return joinedBrowserResult{}
}

func windowsBrowserCallback(t *testing.T, fixture string, handler http.Handler) *httptest.Server {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(fixture, "oauth.pem"), filepath.Join(fixture, "oauth.key"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	t.Cleanup(server.Close)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	return server
}

func joinedEdge(t *testing.T, ctx context.Context, root, state, port, callback string, config map[string]any) joinedBrowserResult {
	t.Helper()
	input, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "python3", filepath.Join(root, "lab", "windows_web_browser.py"),
		"--state", state, "--primary-port", port, "--callback", callback)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run the joined Windows desktop browser probe: %v\n%s", err, output)
	}
	var result joinedBrowserResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("read Windows browser evidence: %v: %s", err, output)
	}
	if result.ErrorStage != "" || result.EdgeVersion == "" || result.WindowsEdition == "" {
		t.Fatalf("Windows browser probe failed in %q: %s", result.ErrorStage, result.Message)
	}
	t.Logf("Microsoft Edge %s on Windows 11 %s", result.EdgeVersion, result.WindowsEdition)
	return result
}
