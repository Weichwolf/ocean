package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	send := func(method, path, query, subject, content string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, armOrigin+path+query, strings.NewReader(content))
		if subject != "" {
			claims, _ := json.Marshal(map[string]any{"iss": upstream.URL + "/realms/" + tenant.TenantID,
				"sub": subject, "aud": armOrigin, "typ": "Bearer", "exp": time.Now().Add(time.Minute).Unix()})
			unsigned := encode([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + encode(claims)
			digest := sha256.Sum256([]byte(unsigned))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+unsigned+"."+encode(signature))
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
		!strings.Contains(replay.Body.String(), `"provisioningState":"Creating"`) {
		t.Fatalf("directory response did not expose the accepted request (%d) %s", replay.Code, replay.Body)
	}
}
