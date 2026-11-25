//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalWebApplicationRegistration(t *testing.T) {
	endpoint := os.Getenv("OCEAN_E2E_DIRECTORY_ETCD")
	if endpoint == "" {
		t.Skip("requires an isolated loopback etcd and Azure CLI 2.93.0")
	}
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("use an isolated loopback etcd for the web application fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	region := &Region{root: "/test/web-applications/" + operationID(), name: "farm-1", client: client}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := client.Delete(cleanup, region.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
		_ = client.Close()
	})
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	if _, err := region.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := region.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DisplayName: "Web application fixture", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	issuer, _, enableLogin := directoryJoinIssuer(t, tenant.TenantID)
	private := t.TempDir()
	write := func(name string, content []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	regionalKey := write("regional.key", bytes.Repeat([]byte{7}, 32))
	api, graph := httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	defer api.Close()
	defer graph.Close()
	armOrigin, graphOrigin := "https://"+api.Listener.Addr().String(), "https://"+graph.Listener.Addr().String()
	compat, err := (identity.Config{Authority: issuer.URL, Provider: issuer.URL,
		ProviderCAFile: write("issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})),
		Cloud:          &identity.CloudEndpoints{ResourceManager: armOrigin, MicrosoftGraph: graphOrigin},
	}).OpenCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	compat.EnableSubscriptions(region.name, region.lookupSubscription)
	if err := compat.EnableOnboarding(identity.OnboardingConfig{OperatorTenant: operationID(), OperatorClient: operationID(),
		AdminEndpoints: []string{"https://private.ocean.test"}, AdminClient: "lab", AdminSecretFile: regionalKey, RegionalKeyFile: regionalKey}, region); err != nil {
		t.Fatal(err)
	}
	api.Config.Handler, graph.Config.Handler = compat.Handler(), compat.Handler()
	api.StartTLS()
	graph.StartTLS()
	app, secret := operationID(), rand.Text()
	enableLogin(api.URL, graph.URL, app, secret, tenant.Administrator)
	az := (regionalGraphFixture{ctx: ctx, private: private, api: api, graph: graph, issuer: issuer, tenant: tenant, app: app, secret: secret}).loginCLI(t)

	type graphApplication struct {
		ID, AppID string
		Web       *struct{ RedirectURIs []string }
	}
	decode := func(data []byte) graphApplication {
		t.Helper()
		var app graphApplication
		if err := json.Unmarshal(data, &app); err != nil || app.ID == "" || app.AppID == "" {
			t.Fatalf("invalid Azure CLI application projection: %v", err)
		}
		return app
	}
	first := decode(az(false, "ad", "app", "create", "--display-name", "Web A", "--sign-in-audience", "AzureADMyOrg",
		"--web-redirect-uris", "https://web-a.ocean.test/callback", "https://web-a.ocean.test/return", "-o", "json"))
	second := decode(az(false, "ad", "app", "create", "--display-name", "Web B", "--web-redirect-uris", "https://web-b.ocean.test/callback", "-o", "json"))
	if first.ID == second.ID || first.AppID == second.AppID || first.Web == nil || second.Web == nil ||
		!slices.Equal(first.Web.RedirectURIs, []string{"https://web-a.ocean.test/callback", "https://web-a.ocean.test/return"}) ||
		!slices.Equal(second.Web.RedirectURIs, []string{"https://web-b.ocean.test/callback"}) {
		t.Fatal("the two web registrations did not preserve distinct identities and exact redirects")
	}
	replay := decode(az(false, "ad", "app", "create", "--display-name", "Web A", "--web-redirect-uris",
		"https://web-a.ocean.test/callback", "https://web-a.ocean.test/return", "-o", "json"))
	if replay.ID != first.ID || replay.AppID != first.AppID {
		t.Fatal("stock Azure CLI replay changed the registered application identity")
	}
	conflict := az(true, "ad", "app", "create", "--display-name", "Web A", "--web-redirect-uris", "https://web-b.ocean.test/callback")
	if !bytes.Contains(conflict, []byte("Use the registered web redirect URIs")) {
		t.Fatalf("changed redirects did not conflict: %s", conflict)
	}
	wildcard := az(true, "ad", "app", "create", "--display-name", "Wildcard", "--web-redirect-uris", "https://web-a.ocean.test/*")
	if !bytes.Contains(wildcard, []byte("Specify unique, exact HTTPS web redirect URIs")) {
		t.Fatalf("wildcard redirects were not rejected: %s", wildcard)
	}
	for _, args := range [][]string{
		{"ad", "sp", "create", "--id", first.AppID},
		{"ad", "app", "credential", "reset", "--id", first.AppID, "--append"},
	} {
		if denial := az(true, args...); !bytes.Contains(denial, []byte("Use a separate automation application")) {
			t.Fatalf("web application accepted an automation credential request: %s", denial)
		}
	}
	stored := decode(az(false, "ad", "app", "show", "--id", first.AppID, "-o", "json"))
	if stored.Web == nil || !slices.Equal(stored.Web.RedirectURIs, first.Web.RedirectURIs) {
		t.Fatal("a rejected callback request changed the persisted registration")
	}
	legacy := decode(az(false, "ad", "app", "create", "--display-name", "Automation", "-o", "json"))
	if legacy.Web != nil {
		t.Fatal("an automation application acquired an interactive callback")
	}
	t.Log("Azure CLI 2.93.0 registered and replayed two independent web applications through Graph and etcd, rejected unsafe changes, and preserved existing automation registration")
}
