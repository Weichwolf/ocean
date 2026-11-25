package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type directoryTenantFixture struct {
	TenantStore
	tenant TenantReservation
}

func (f directoryTenantFixture) LookupTenant(_ context.Context, tenant string) (*TenantReservation, error) {
	if tenant != f.tenant.TenantID {
		return nil, nil
	}
	return &f.tenant, nil
}

type directoryRequestFixture struct {
	received *ManagedDirectory
}

func (f *directoryRequestFixture) LookupManagedDirectory(context.Context, TenantReservation) (*ManagedDirectory, error) {
	return f.received, nil
}

func (f *directoryRequestFixture) RequestManagedDirectory(_ context.Context, tenant TenantReservation, spec DirectorySpec) (ManagedDirectory, error) {
	if f.received != nil {
		if f.received.Spec != spec {
			return ManagedDirectory{}, ErrDirectoryConflict
		}
		return *f.received, nil
	}
	f.received = &ManagedDirectory{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID, ID: newUUID(), Spec: spec, RequestedAt: time.Now()}
	return *f.received, nil
}

func TestManagedDirectoryHTTP(t *testing.T) {
	const armOrigin = "https://arm.ocean.test"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/realms/"+testTenant+"/protocol/openid-connect/certs" {
			http.NotFound(w, req)
			return
		}
		writeJSON(w, http.StatusOK, map[string][]map[string]string{
			"keys": {{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture",
				"n": encode(key.N.Bytes()), "e": "AQAB"}},
		})
	}))
	defer upstream.Close()
	compat, err := NewCompatibility("https://id.ocean.test", upstream.URL, upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	tenant := TenantReservation{TenantID: testTenant, Administrator: newUUID(), SubscriptionID: newUUID(), Fingerprint: "fixture"}
	member := newUUID()
	compat.cloud = CloudEndpoints{ResourceManager: armOrigin}
	compat.EnableSubscriptions("farm-1", func(_ context.Context, id string) (*Subscription, error) {
		if id != tenant.TenantID {
			return nil, nil
		}
		return &Subscription{TenantID: id, SubscriptionID: tenant.SubscriptionID,
			DisplayName: "Directory Lab", Members: []string{tenant.Administrator, member}}, nil
	})
	compat.onboarding = &onboarding{store: directoryTenantFixture{tenant: tenant}}
	store := &directoryRequestFixture{}
	if err := compat.EnableManagedDirectories(store); err != nil {
		t.Fatal(err)
	}
	handler := compat.Handler()
	signedToken := func(audience, subject string) string {
		t.Helper()
		claims, _ := json.Marshal(map[string]any{"iss": upstream.URL + "/realms/" + tenant.TenantID,
			"sub": subject, "aud": audience, "typ": "Bearer", "exp": time.Now().Add(time.Minute).Unix()})
		unsigned := encode([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + encode(claims)
		digest := sha256.Sum256([]byte(unsigned))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return unsigned + "." + encode(signature)
	}
	send := func(method, path, query, subject, content string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, armOrigin+path+query, strings.NewReader(content))
		if subject != "" {
			request.Header.Set("Authorization", "Bearer "+signedToken(armOrigin, subject))
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	path := directoryPath(tenant.TenantID)
	query := "?api-version=" + directoryAPIVersion
	input := `{"dnsName":"AD.Example.Test","netbiosName":"office","subnetId":"/fixture"}`
	for _, check := range []struct {
		name, method, path, query, subject, content string
		status                                      int
	}{
		{"missing auth", http.MethodPut, path, query, "", input, http.StatusUnauthorized},
		{"subscription member", http.MethodPut, path, query, member, input, http.StatusForbidden},
		{"foreign tenant", http.MethodGet, directoryPath(newUUID()), query, tenant.Administrator, "", http.StatusForbidden},
		{"unsupported query", http.MethodPut, path, query + "&other=yes", tenant.Administrator, input, http.StatusBadRequest},
		{"unsupported field", http.MethodPut, path, query, tenant.Administrator, `{"dnsName":"ad.example.test","unknown":true}`, http.StatusBadRequest},
		{"absent directory", http.MethodGet, path, query, tenant.Administrator, "", http.StatusNotFound},
	} {
		t.Run(check.name, func(t *testing.T) {
			result := send(check.method, check.path, check.query, check.subject, check.content)
			if result.Code != check.status || store.received != nil {
				t.Fatalf("unexpected directory response (%d) %s", result.Code, result.Body)
			}
		})
	}
	accepted := send(http.MethodPut, path, query, tenant.Administrator, input)
	if accepted.Code != http.StatusAccepted || accepted.Header().Get("Location") != armOrigin+path+query ||
		store.received == nil || store.received.Spec.DNSName != "ad.example.test" || store.received.Spec.NetBIOSName != "OFFICE" {
		t.Fatalf("directory response did not accept a normalized request (%d) %s", accepted.Code, accepted.Body)
	}
	replay := send(http.MethodGet, path, query, tenant.Administrator, "")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), store.received.ID) ||
		!strings.Contains(replay.Body.String(), `"provisioningState":"Creating"`) || !strings.Contains(replay.Body.String(), `"availability":"Pending"`) {
		t.Fatalf("directory response did not expose the accepted request (%d) %s", replay.Code, replay.Body)
	}
	store.received.ProvisionedAt = time.Now()
	for i, dns := range []string{"dc01.ad.example.test", "dc02.ad.example.test"} {
		address := []string{"10.86.0.4", "10.86.0.5"}[i]
		store.received.Controllers[i] = DirectoryControllerReadiness{DNSName: dns, PrivateIPv4: netip.MustParseAddr(address)}
	}
	for i, state := range []string{"Unavailable", "Degraded", "Available"} {
		result := send(http.MethodGet, path, query, tenant.Administrator, "")
		if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"provisioningState":"Succeeded"`) ||
			!strings.Contains(result.Body.String(), `"availability":"`+state+`"`) ||
			!strings.Contains(result.Body.String(), `"dnsName":"dc01.ad.example.test"`) {
			t.Fatalf("unexpected directory availability (%d) %s", result.Code, result.Body)
		}
		if i < len(store.received.Controllers) {
			store.received.Controllers[i].Ready = true
		}
	}
	if os.Getenv("OCEAN_E2E_DIRECTORY_CLI") == "1" {
		t.Run("pinned Azure CLI", func(t *testing.T) {
			ready := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-ready
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			compat.cloud.ResourceManager = server.URL
			close(ready)
			testManagedDirectoryCLI(t, server, path+query, input, signedToken(server.URL, tenant.Administrator), store.received.ID)
		})
	}
}

func testManagedDirectoryCLI(t *testing.T, api *httptest.Server, directoryPath, input, token, expectedID string) {
	t.Helper()
	temp := t.TempDir()
	ca, body := filepath.Join(temp, "test-ca.pem"), filepath.Join(temp, "directory.json")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(body, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(t.Context(), "az", args...)
		command.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+filepath.Join(temp, "az"),
			"REQUESTS_CA_BUNDLE="+ca, "AZURE_CORE_COLLECT_TELEMETRY=0", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("pinned CLI %s failed: %v: %s", args[0], err, strings.ReplaceAll(string(output), token, "[fixture token]"))
		}
		return output
	}
	var version struct {
		CLI        string            `json:"azure-cli"`
		Extensions map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(run("version", "-o", "json"), &version); err != nil || version.CLI != "2.93.0" || len(version.Extensions) != 0 {
		t.Fatalf("expected Azure CLI 2.93.0 with no extensions, got %+v (%v)", version, err)
	}
	for _, method := range []string{"put", "get"} {
		// The test-only token is valid only against the loopback fixture issuer.
		args := []string{"rest", "--method", method, "--url", api.URL + directoryPath,
			"--headers", "Authorization=Bearer " + token, "--only-show-errors", "-o", "json"}
		if method == "put" {
			args = append(args, "--body", "@"+body)
		}
		var state struct {
			ID           string                         `json:"directoryId"`
			Provisioning string                         `json:"provisioningState"`
			Availability string                         `json:"availability"`
			Controllers  []DirectoryControllerReadiness `json:"controllers"`
		}
		if err := json.Unmarshal(run(args...), &state); err != nil || state.ID != expectedID ||
			state.Provisioning != "Succeeded" || state.Availability != "Available" ||
			len(state.Controllers) != 2 || !state.Controllers[0].Ready || !state.Controllers[1].Ready {
			t.Fatalf("az rest %s directory status %+v (%v)", method, state, err)
		}
		t.Logf("Azure CLI %s az rest %s preserved the directory ID and returned two ready controllers", version.CLI, method)
	}
}
