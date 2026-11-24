package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTokenExchangePreservesSessionAndRestrictsAudience(t *testing.T) {
	const authority = "https://id.ocean.test"
	const arm = "https://arm.ocean.test"
	const graph = "https://graph.ocean.test"
	const testSecret = "test-only-credential-for-keycloak-exchange"
	const subject = "a5eb8694-e9c6-42ba-a1d0-060b044bcea1"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "lab-key"
	encode := base64.RawURLEncoding.EncodeToString
	header := encode([]byte(`{"alg":"RS256","kid":"` + keyID + `"}`))
	for _, tc := range []struct {
		name     string
		audience any
		tamper   bool
		status   int
		response string
	}{
		{"requested audience", []string{graph}, false, http.StatusOK, "new-session"},
		{"multiple audiences", []string{graph, arm}, false, http.StatusBadGateway, "temporarily_unavailable"},
		{"invalid signature", []string{graph}, true, http.StatusBadGateway, "temporarily_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var issuer string
			expiration := time.Now().Add(time.Minute).Unix()
			mint := func(client string, audience any) string {
				payload, err := json.Marshal(map[string]any{
					"iss": issuer, "sub": subject, "aud": audience, "azp": client, "typ": "Bearer", "exp": expiration,
				})
				if err != nil {
					panic(err)
				}
				input := header + "." + encode(payload)
				digest := sha256.Sum256([]byte(input))
				signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
				if err != nil {
					panic(err)
				}
				if tc.tamper && client == exchangeClient {
					signature[0] ^= 1
				}
				return input + "." + encode(signature)
			}
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/realms/"+testTenant+"/protocol/openid-connect/certs" {
					writeJSON(w, http.StatusOK, map[string][]map[string]string{
						"keys": {{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": keyID,
							"n": encode(key.N.Bytes()), "e": encode(big.NewInt(int64(key.E)).Bytes())}},
					})
					return
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse provider form: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.PostForm.Get("grant_type") {
				case "refresh_token":
					if r.PostForm.Has("scope") || r.PostForm.Get("refresh_token") != "old-session" ||
						r.PostForm.Get("client_id") != cliClientID || r.Header.Get("Authorization") != "" {
						t.Error("refresh did not preserve the native grant")
					}
					writeJSON(w, http.StatusOK, map[string]any{
						"access_token": mint(cliClientID, exchangeClient), "token_type": "Bearer", "expires_in": 60,
						"refresh_token": "new-session", "id_token": "id-token", "scope": "profile",
					})
				case exchangeGrant:
					client, secret, ok := r.BasicAuth()
					if !ok || client != exchangeClient || secret != testSecret ||
						r.PostForm.Get("subject_token") != mint(cliClientID, exchangeClient) ||
						r.PostForm.Get("subject_token_type") != accessType || r.PostForm.Get("scope") != graph+"/.default" {
						t.Error("exchange did not use the configured client and requested Graph scope")
					}
					writeJSON(w, http.StatusOK, map[string]any{
						"access_token": mint(exchangeClient, tc.audience), "token_type": "Bearer", "expires_in": 30,
						"scope": graph + "/.default",
					})
				default:
					t.Error("unexpected grant at provider")
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			upstream.StartTLS()
			defer upstream.Close()
			issuer = upstream.URL + "/realms/" + testTenant
			compat, err := NewCompatibility(authority, upstream.URL, upstream.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			compat.cloud = CloudEndpoints{ResourceManager: arm, MicrosoftGraph: graph}
			compat.exchangeSecret = func(tenant string) (string, error) {
				if tenant != testTenant {
					return "", os.ErrNotExist
				}
				return testSecret, nil
			}
			handler := compat.Handler()
			endpoint := "/" + testTenant + "/oauth2/v2.0/token"
			for _, request := range []struct {
				form     url.Values
				status   int
				response string
			}{
				{url.Values{"client_id": {cliClientID}, "grant_type": {"refresh_token"}, "refresh_token": {"old-session"}, "scope": {graph + "/.default"}},
					tc.status, tc.response},
				{url.Values{"client_id": {cliClientID}, "grant_type": {"refresh_token"}, "refresh_token": {"old-session"}, "scope": {arm + "/.default " + graph + "/.default"}},
					http.StatusBadRequest, "invalid_scope"},
				{url.Values{"client_id": {cliClientID}, "grant_type": {exchangeGrant}, "subject_token": {"provided-by-caller"}},
					http.StatusBadRequest, "unsupported_grant_type"},
			} {
				req := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(request.form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != request.status || !strings.Contains(response.Body.String(), request.response) {
					t.Errorf("grant returned status %d, expected %d with %s", response.Code, request.status, request.response)
				}
				if response.Code != http.StatusOK && strings.Contains(response.Body.String(), "access_token") {
					t.Error("an unsuccessful request returned an access token")
				}
			}
		})
	}
}
