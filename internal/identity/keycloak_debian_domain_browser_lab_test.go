//go:build e2e

package identity

import (
	"bytes"
	"context"
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
	fixture, state := os.Getenv("OCEAN_E2E_JOINED_WEB_STATE"), os.Getenv("OCEAN_E2E_DOMAIN_STATE")
	if fixture == "" || state == "" {
		t.Skip("provide the enabled two-controller and joined Debian browser fixture")
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
	callback, callbackCA := kerberosBrowserCallback(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
	}))
	app := Application{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Joined Debian browser",
		WebRedirectURIs: []string{callback.URL + "/oidc"}}
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
	result := joinedFirefox(t, ctx, root, state, value("guest-ssh-port"), callback.Listener.Addr().String(), map[string]any{
		"user": employee, "password": value("employee"), "principal": principal, "servicePrincipal": ticket,
		"ticketGrantingPrincipal": "krbtgt/" + realm + "@" + realm, "providerCA": ca, "callbackCA": callbackCA,
		"origin": origin, "authorize": issuer + "/protocol/openid-connect/auth?" + authorization.params.Encode(), "completed": callback.URL + "/complete",
	})
	if result.User != employee || result.Principal != principal || result.ServicePrincipal != ticket || result.DurationMS <= 0 ||
		(result.Encryption != "aes128-cts-hmac-sha1-96" && result.Encryption != "aes256-cts-hmac-sha1-96") {
		t.Fatal("the guest did not acquire the expected HTTP service ticket in the employee's PAM session")
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
	t.Logf("joined Debian Firefox acquired the %s HTTP ticket and reached the OIDC callback in %d ms from browser launch", result.Encryption, result.DurationMS)
}

type joinedFirefoxResult struct {
	User             string `json:"user"`
	Principal        string `json:"principal"`
	ServicePrincipal string `json:"servicePrincipal"`
	Encryption       string `json:"encryption"`
	DurationMS       int    `json:"durationMs"`
}

func joinedFirefox(t *testing.T, ctx context.Context, root, state, port, callback string, config map[string]any) joinedFirefoxResult {
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
			var result joinedFirefoxResult
			if err := json.Unmarshal([]byte(record), &result); err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	t.Fatal("the joined guest did not return browser evidence")
	return joinedFirefoxResult{}
}
