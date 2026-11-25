//go:build e2e

package identity

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestKeycloakWebCLIRegressionLab(t *testing.T) {
	kerberosState := os.Getenv("OCEAN_E2E_KERBEROS_BROWSER_STATE")
	if kerberosState == "" {
		t.Skip("set OCEAN_E2E_KERBEROS_BROWSER_STATE for the Kerberos provider configuration")
	}
	keytab := filepath.Join(kerberosState, "service.keytab")
	if stat, err := os.Stat(keytab); err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 {
		t.Fatalf("use a private Samba service keytab: %v", err)
	}
	arm, graph, authority := httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	for _, server := range []*httptest.Server{arm, graph, authority} {
		t.Cleanup(server.Close)
	}
	cloud := CloudEndpoints{ResourceManager: "https://" + arm.Listener.Addr().String(), MicrosoftGraph: "https://" + graph.Listener.Addr().String()}
	managedExchange, existingExchange := newClientSecret(), newClientSecret()
	lab := keycloakSambaExchangeLab(t, cloud, managedExchange)
	_, _, existing, _, existingAdmin := keycloakTenantExchangeLab(t, cloud, existingExchange)
	issuer := lab.admin.endpoints[0]
	compat, err := NewCompatibility("https://"+authority.Listener.Addr().String(), issuer, lab.admin.client.Transport)
	if err != nil {
		t.Fatal(err)
	}
	compat.cloud = cloud
	compat.exchangeSecret = func(tenant string) (string, error) {
		switch tenant {
		case lab.tenant.TenantID:
			return managedExchange, nil
		case existing.TenantID:
			return existingExchange, nil
		default:
			return "", os.ErrNotExist
		}
	}
	web := Application{TenantID: lab.tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Kerberos CLI regression",
		WebRedirectURIs: []string{"https://regression.apps.ocean.test/oidc"}}
	store := &webPolicyLabStore{directoryTenantFixture: directoryTenantFixture{tenant: lab.tenant}, existing: existing,
		directoryRequestFixture: directoryRequestFixture{received: &lab.directory}, controller: lab.primary,
		apps: map[string]webPolicyLabRecord{web.ID: {app: web, revision: 1}}}
	compat.onboarding = &onboarding{admin: lab.admin, store: store, key: []byte(newClientSecret()), config: OnboardingConfig{
		WebDirectories: map[string]WebDirectoryConfig{lab.tenant.TenantID: {
			DirectoryID: lab.directory.ID, DomainSID: lab.directory.DomainSID, Connectors: lab.connectors,
			ReaderSecretFile: filepath.Join(os.Getenv("OCEAN_E2E_SAMBA_FEDERATION_STATE"), "reader"), KerberosKeytab: keytab,
		}},
	}}
	subscriptions := make(map[string]Subscription)
	managedApp, managedSecret := seedWebRegressionPrincipal(t, lab.ctx, compat, lab.tenant, subscriptions)
	existingApp, existingSecret := seedWebRegressionPrincipal(t, lab.ctx, compat, existing, subscriptions)
	compat.EnableSubscriptions("farm-1", func(_ context.Context, tenant string) (*Subscription, error) {
		subscription, found := subscriptions[tenant]
		if !found {
			return nil, nil
		}
		return &subscription, nil
	})
	if err := compat.EnableManagedDirectories(store); err != nil {
		t.Fatal(err)
	}
	handler := compat.Handler()
	for _, server := range []*httptest.Server{arm, graph, authority} {
		server.Config.Handler = handler
		server.StartTLS()
	}
	certs, err := os.ReadFile(os.Getenv("SSL_CERT_FILE"))
	if err != nil {
		t.Fatalf("read the private Keycloak lab CA from SSL_CERT_FILE: %v", err)
	}
	ca := filepath.Join(t.TempDir(), "trust.pem")
	if err := os.WriteFile(ca, append(append(certs, '\n'), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: arm.Certificate().Raw})...), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(tenant TenantReservation, admin onboardingRequest, app, foreign Application, secret string, policy bool) {
		t.Helper()
		config := map[string]any{
			"arm": cloud.ResourceManager, "graph": cloud.MicrosoftGraph, "authority": authority.URL, "provider": issuer, "ca": ca,
			"tenant": tenant.TenantID, "subscription": tenant.SubscriptionID, "location": "farm-1",
			"user": admin.AdministratorUPN, "password": admin.AdministratorPassword,
			"app": app.ClientID, "appObject": app.ID, "foreignAppObject": foreign.ID, "secret": secret,
		}
		if policy {
			config["webPolicy"] = map[string]any{"appObject": web.ID, "groupIds": []string{lab.value("group-guid")}}
		}
		checkWebCLICaches(t, lab.ctx, config, tenant.Administrator, app.PrincipalID)
	}
	check(existing, existingAdmin, existingApp, managedApp, existingSecret, false)
	t.Log("existing tenant passed the baseline CLI sign-ins")
	check(lab.tenant, lab.firstAdmin, managedApp, existingApp, managedSecret, true)
	t.Log("managed tenant passed the baseline CLI sign-ins and activated Kerberos with its administrator's CLI session")
	check(lab.tenant, lab.firstAdmin, managedApp, existingApp, managedSecret, false)
	t.Log("managed tenant preserved CLI identities and tenant isolation after enabling web Kerberos")
	check(existing, existingAdmin, existingApp, managedApp, existingSecret, false)
	t.Log("existing tenant preserved CLI identities and tenant isolation after the other tenant enabled web Kerberos")
}

func seedWebRegressionPrincipal(t *testing.T, ctx context.Context, compat *Compatibility, tenant TenantReservation,
	subscriptions map[string]Subscription) (Application, string) {
	t.Helper()
	app := Application{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: "Existing CLI automation"}
	owner := compat.onboarding
	subject, err := owner.admin.ensureServicePrincipal(ctx, app, compat.cloud, owner.providerClientSecret(tenant.TenantID, app.ClientID))
	if err != nil {
		t.Fatal(err)
	}
	app.PrincipalID = subject
	secret := newClientSecret()
	now := time.Now()
	app.Credentials = []ClientCredential{{ID: newUUID(), DisplayName: "Existing automation secret", Start: now.Add(-time.Minute), End: now.Add(time.Hour),
		Verifier: owner.credentialVerifier(tenant.TenantID, app.ClientID, secret)}}
	if saved, err := owner.store.SaveApplication(ctx, app, 0); err != nil || !saved {
		t.Fatalf("seed the existing automation application: %v", err)
	}
	subscriptions[tenant.TenantID] = Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		DisplayName: "CLI regression fixture", Members: []string{tenant.Administrator, app.PrincipalID}}
	return app, secret
}

func checkWebCLICaches(t *testing.T, ctx context.Context, config map[string]any, administrator, automation string) {
	t.Helper()
	start := time.Now()
	settings := filepath.Join(t.TempDir(), "settings.secret")
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join("..", "..", "tests", "e2e", "identity_cli.py")
	command := exec.CommandContext(ctx, "python3", script, "--settings", settings, "--web-regression")
	output, err := command.Output()
	if err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			t.Fatalf("CLI regression: %v\n%s", failure, failure.Stderr)
		}
		t.Fatal(err)
	}
	var subjects struct {
		User        string `json:"user"`
		Application string `json:"application"`
	}
	if err := json.Unmarshal(output, &subjects); err != nil || subjects.User != administrator || subjects.Application != automation {
		t.Fatalf("fresh CLI sessions changed the administrator or service principal subject: %v", err)
	}
	t.Logf("fresh device and service-principal sign-ins with ARM and Graph checks completed in %s", time.Since(start).Round(time.Millisecond))
}
