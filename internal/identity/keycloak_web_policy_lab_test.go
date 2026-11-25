//go:build e2e

package identity

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

type webPolicyLabStore struct {
	directoryTenantFixture
	directoryRequestFixture
	existing   TenantReservation
	controller string
	group      func(context.Context, string) (enrollment.DirectoryGraphResult, error)
	apps       map[string]webPolicyLabRecord
	mu         sync.Mutex
}

type webPolicyLabRecord struct {
	app      Application
	revision int64
}

func (s *webPolicyLabStore) LookupTenant(ctx context.Context, tenant string) (*TenantReservation, error) {
	if s.existing.TenantID != "" && tenant == s.existing.TenantID {
		return &s.existing, nil
	}
	return s.directoryTenantFixture.LookupTenant(ctx, tenant)
}

func (s *webPolicyLabStore) FindApplication(_ context.Context, tenant, field, value string) (*Application, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.apps {
		app := record.app
		if app.TenantID != tenant || !(field == "id" && app.ID == value || field == "appId" && app.ClientID == value) {
			continue
		}
		if app.WebPolicy != nil {
			policy := *app.WebPolicy
			policy.GroupIDs = slices.Clone(policy.GroupIDs)
			app.WebPolicy = &policy
		}
		return &app, record.revision, nil
	}
	return nil, 0, nil
}

func (s *webPolicyLabStore) ListApplications(_ context.Context, tenant, after string, limit int) ([]Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var apps []Application
	for _, record := range s.apps {
		if record.app.TenantID == tenant && record.app.ID > after {
			apps = append(apps, record.app)
		}
	}
	slices.SortFunc(apps, func(left, right Application) int { return cmp.Compare(left.ID, right.ID) })
	return apps[:min(len(apps), limit)], nil
}

func (s *webPolicyLabStore) SaveApplication(_ context.Context, app Application, rev int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !app.Valid(app.TenantID) || (app.TenantID != s.tenant.TenantID && app.TenantID != s.existing.TenantID) || s.apps[app.ID].revision != rev {
		return false, nil
	}
	s.apps[app.ID] = webPolicyLabRecord{app, rev + 1}
	return true, nil
}

func (s *webPolicyLabStore) RunDirectoryGraph(ctx context.Context, tenant TenantReservation, input enrollment.DirectoryGraphInput) (enrollment.DirectoryGraphResult, error) {
	if tenant != s.tenant || input.Operation != enrollment.DirectoryGroupGet {
		return enrollment.DirectoryGraphResult{Status: http.StatusNotFound}, nil
	}
	if s.group != nil {
		return s.group(ctx, input.Selector)
	}
	return runSambaFederationGraph(ctx, s.controller, input.Operation, nil, input.Selector, "")
}

func webPolicyLabCompatibility(t *testing.T, lab sambaDirectoryLab, authority string, apps []Application, kerberosKeytab string) *Compatibility {
	t.Helper()
	issuer := lab.admin.endpoints[0]
	compat, err := NewCompatibility(authority, issuer, lab.admin.client.Transport)
	if err != nil {
		t.Fatal(err)
	}
	compat.cloud = lab.cloud
	store := &webPolicyLabStore{directoryTenantFixture: directoryTenantFixture{tenant: lab.tenant},
		directoryRequestFixture: directoryRequestFixture{received: &lab.directory}, controller: lab.primary, group: lab.group,
		apps: make(map[string]webPolicyLabRecord)}
	for _, app := range apps {
		store.apps[app.ID] = webPolicyLabRecord{app, 1}
	}
	compat.EnableSubscriptions("farm-1", func(_ context.Context, tenantID string) (*Subscription, error) {
		if tenantID != lab.tenant.TenantID {
			return nil, nil
		}
		return &Subscription{TenantID: tenantID, SubscriptionID: lab.tenant.SubscriptionID, DisplayName: "Web policy fixture",
			Members: []string{lab.tenant.Administrator}}, nil
	})
	compat.onboarding = &onboarding{admin: lab.admin, store: store, config: OnboardingConfig{WebDirectories: map[string]WebDirectoryConfig{
		lab.tenant.TenantID: {DirectoryID: lab.directory.ID, DomainSID: lab.directory.DomainSID, Connectors: lab.connectors,
			ReaderSecretFile: lab.readerFile, KerberosKeytab: kerberosKeytab},
	}}}
	if err := compat.EnableManagedDirectories(store); err != nil {
		t.Fatal(err)
	}
	return compat
}

func startWebPolicyLab(t *testing.T, lab sambaDirectoryLab, api *httptest.Server, apps []Application, kerberosKeytab string) func(string, string, []string, string) []byte {
	t.Helper()
	compat := webPolicyLabCompatibility(t, lab, "https://authority.apps.ocean.test", apps, kerberosKeytab)
	api.Config.Handler = compat.Handler()
	api.StartTLS()
	az, err := exec.LookPath("az")
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.CommandContext(lab.ctx, az, "version", "--query", `"azure-cli"`, "-o", "tsv").Output()
	if err != nil || strings.TrimSpace(string(version)) != "2.93.0" {
		t.Fatalf("require stock Azure CLI 2.93.0: %v", err)
	}
	private := t.TempDir()
	authorization, err := json.Marshal(map[string]string{"Authorization": "Bearer " + webPolicyARMToken(t, lab)})
	if err != nil {
		t.Fatal(err)
	}
	headers, ca := filepath.Join(private, "auth.json"), filepath.Join(private, "api.pem")
	if err := os.WriteFile(headers, authorization, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return func(method, path string, groups []string, wantError string) []byte {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", api.URL + path + "?api-version=" + directoryAPIVersion,
			"--skip-authorization-header", "--headers", "@" + headers, "--only-show-errors", "-o", "json"}
		if groups != nil {
			body, err := json.Marshal(map[string][]string{"groupIds": groups})
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--body", string(body))
		}
		command := exec.CommandContext(lab.ctx, az, args...)
		command.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+private, "REQUESTS_CA_BUNDLE="+ca,
			"AZURE_CORE_COLLECT_TELEMETRY=false", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
		output, err := command.CombinedOutput()
		if wantError == "" && err != nil || wantError != "" && (err == nil || !strings.Contains(string(output), wantError)) {
			t.Fatalf("az rest %s web policy: %v\n%s", method, err, output)
		}
		return output
	}
}

func startAuthenticatedWebPolicyLab(t *testing.T, lab sambaDirectoryLab, arm, graph, authority *httptest.Server, exchange string) func(string, ...string) []byte {
	t.Helper()
	compat := webPolicyLabCompatibility(t, lab, "https://"+authority.Listener.Addr().String(), nil, "")
	compat.exchangeSecret = func(tenant string) (string, error) {
		if tenant != lab.tenant.TenantID {
			return "", os.ErrNotExist
		}
		return exchange, nil
	}
	handler := compat.Handler()
	for _, server := range []*httptest.Server{arm, graph, authority} {
		server.Config.Handler = handler
		server.StartTLS()
	}
	private := t.TempDir()
	ca := filepath.Join(private, "trust.pem")
	providerCA, err := os.ReadFile(os.Getenv("SSL_CERT_FILE"))
	if err != nil {
		t.Fatalf("read the Keycloak lab CA from SSL_CERT_FILE: %v", err)
	}
	certs := append(append(providerCA, '\n'), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: arm.Certificate().Raw})...)
	if err := os.WriteFile(ca, certs, 0600); err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(map[string]string{
		"arm": arm.URL, "graph": graph.URL, "authority": authority.URL, "provider": lab.admin.endpoints[0], "ca": ca,
		"tenant": lab.tenant.TenantID, "subscription": lab.tenant.SubscriptionID, "expectedSubject": lab.tenant.Administrator,
		"user": lab.firstAdmin.AdministratorUPN, "password": lab.firstAdmin.AdministratorPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(private, "settings.secret")
	if err := os.WriteFile(settingsPath, settings, 0600); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	env := append(os.Environ(), "AZURE_CONFIG_DIR="+cache, "REQUESTS_CA_BUNDLE="+ca,
		"AZURE_CORE_INSTANCE_DISCOVERY=false", "AZURE_CORE_COLLECT_TELEMETRY=false", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
	prepare := exec.CommandContext(lab.ctx, "python3", filepath.Join("..", "..", "tests", "e2e", "identity_cli.py"),
		"--settings", settingsPath, "--device-cache", cache)
	prepare.Env = env
	if output, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("authenticate the fresh Azure CLI cache: %v\n%s", err, output)
	}
	return func(wantError string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(lab.ctx, "az", args...)
		command.Env = env
		output, err := command.CombinedOutput()
		if wantError == "" && err != nil || wantError != "" && (err == nil || !strings.Contains(string(output), wantError)) {
			t.Fatalf("az %s: %v\n%s", strings.Join(args[:2], " "), err, output)
		}
		return output
	}
}

func webPolicyARMToken(t *testing.T, lab sambaDirectoryLab) string {
	t.Helper()
	clientID := "ocean-arm-lab-" + newUUID()
	status, err := lab.admin.directoryRequest(lab.ctx, lab.tenant.TenantID, http.MethodPost, "/clients", map[string]any{
		"clientId": clientID, "enabled": true, "protocol": "openid-connect", "publicClient": true, "fullScopeAllowed": false,
		"directAccessGrantsEnabled": true, "standardFlowEnabled": false,
		"defaultClientScopes": []string{"basic", lab.cloud.ResourceManager + "/.default"}, "optionalClientScopes": []string{},
	}, nil)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("create the disposable ARM token client: status %d, %v", status, err)
	}
	form := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {lab.firstAdmin.AdministratorUPN},
		"password": {lab.firstAdmin.AdministratorPassword}}
	endpoint := lab.admin.endpoints[0] + "/realms/" + lab.tenant.TenantID + "/protocol/openid-connect/token"
	var issued struct {
		Token string `json:"access_token"`
	}
	status, err = lab.admin.request(lab.ctx, http.MethodPost, endpoint, "", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), &issued)
	if err != nil || status != http.StatusOK || issued.Token == "" {
		t.Fatalf("obtain the signed test ARM credential: status %d, %v", status, err)
	}
	return issued.Token
}
