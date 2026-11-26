package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testTenant = "1807cb55-8282-4d15-b70f-ca68440bbaec"

func TestCompatibilityDiscoveryAndDeviceFlow(t *testing.T) {
	const authority = "https://id.ocean.test"
	var issuer string
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol := issuer + "/protocol/openid-connect"
		realm := "/realms/" + testTenant
		switch {
		case r.Method == http.MethodGet && r.URL.Path == realm+"/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]string{
				"issuer": issuer, "authorization_endpoint": protocol + "/auth", "token_endpoint": protocol + "/token",
				"jwks_uri": protocol + "/certs", "device_authorization_endpoint": protocol + "/auth/device",
			})
		case r.Method == http.MethodPost && r.URL.Path == realm+"/protocol/openid-connect/auth/device":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != cliClientID || r.PostForm.Get("scope") != "openid" {
				t.Errorf("unexpected device form: %v", r.PostForm)
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"user_code": "ABCD-1234", "device_code": "device-token", "expires_in": 180, "interval": 5,
				"verification_uri": issuer + "/device",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	upstream.StartTLS()
	defer upstream.Close()
	issuer = upstream.URL + "/realms/" + testTenant
	compat, err := NewCompatibility(authority, upstream.URL, upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	handler := compat.Handler()
	device := "/" + testTenant + "/oauth2/v2.0/devicecode"
	for _, tc := range []struct {
		method string
		path   string
		form   url.Values
		want   map[string]string
	}{
		{http.MethodGet, "/" + testTenant + "/v2.0/.well-known/openid-configuration", nil,
			map[string]string{"issuer": issuer, "token_endpoint": issuer + "/protocol/openid-connect/token", "device_authorization_endpoint": authority + device}},
		{http.MethodPost, device, url.Values{"client_id": {cliClientID}, "scope": {"openid"}},
			map[string]string{"device_code": "device-token", "message": "Open " + issuer + "/device in a browser and enter the code ABCD-1234 to sign in."}},
	} {
		request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("compatibility response for %s: %d %s", tc.path, response.Code, response.Body.String())
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		for field, want := range tc.want {
			if got := jsonString(result[field]); got != want {
				t.Errorf("%s = %q, want %q", field, got, want)
			}
		}
	}
}

func TestCompatibilityRejectsUntrustedDiscovery(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/", http.StatusFound)
	}))
	defer upstream.Close()
	compat, err := NewCompatibility("https://id.ocean.test", upstream.URL, upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	handler := compat.Handler()
	const suffix = "/v2.0/.well-known/openid-configuration"
	for _, tc := range []struct {
		tenant string
		status int
	}{
		{"master", http.StatusNotFound},
		{testTenant, http.StatusBadGateway},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+tc.tenant+suffix, nil))
		if response.Code != tc.status || response.Header().Get("Location") != "" {
			t.Errorf("discovery returned %d and Location %q, want %d without a redirect", response.Code, response.Header().Get("Location"), tc.status)
		}
	}
}

func TestCloudMetadataForAzureCLI(t *testing.T) {
	const authority = "https://id.ocean.test"
	const arm = "https://arm.ocean.test"
	const graph = "https://graph.ocean.test"
	compat, err := (Config{
		Authority: authority,
		Provider:  "https://oauth.ocean.test",
		Cloud:     &CloudEndpoints{ResourceManager: arm, MicrosoftGraph: graph, FunctionsSCM: true},
	}).OpenCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	handler := compat.Handler()
	for _, query := range []string{"", "?api-version=2019-05-01", "?api-version=2022-09-01&other=true"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metadata/endpoints"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("metadata with query %q returned %d, want %d", query, response.Code, http.StatusBadRequest)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metadata/endpoints?api-version=2022-09-01", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metadata returned %d", response.Code)
	}
	var body struct {
		ResourceManager    string `json:"resourceManager"`
		MicrosoftGraph     string `json:"microsoftGraphResourceId"`
		AppServiceResource string `json:"appServiceResourceId"`
		Authentication     struct {
			Audiences     []string `json:"audiences"`
			LoginEndpoint string   `json:"loginEndpoint"`
		} `json:"authentication"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ResourceManager != arm || body.MicrosoftGraph != graph || body.AppServiceResource != arm || body.Authentication.LoginEndpoint != authority ||
		len(body.Authentication.Audiences) != 1 || body.Authentication.Audiences[0] != arm {
		t.Errorf("unexpected metadata: %+v", body)
	}
}
