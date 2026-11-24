package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthenticateARM(t *testing.T) {
	const arm = "https://arm.ocean.test"
	const graph = "https://graph.ocean.test"
	const subject = "a5eb8694-e9c6-42ba-a1d0-060b044bcea1"
	const subscriptionID = "02dc534c-e5d8-451d-a364-a5b03b170462"
	const foreignTenant = "3a3da23a-edc2-4b93-b9ca-79360d22c479"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/"+testTenant+"/protocol/openid-connect/certs" {
			t.Errorf("unexpected signing key request for %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string][]map[string]string{
			"keys": {{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test-key",
				"n": encode(key.N.Bytes()), "e": encode(big.NewInt(int64(key.E)).Bytes())}},
		})
	}))
	defer upstream.Close()
	compat, err := NewCompatibility("https://id.ocean.test", upstream.URL, upstream.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	compat.cloud = CloudEndpoints{ResourceManager: arm, MicrosoftGraph: graph}
	entry := Subscription{TenantID: testTenant, SubscriptionID: subscriptionID, DisplayName: "Test Subscription"}
	compat.EnableSubscriptions("farm-1", func(_ context.Context, tenant string) (*Subscription, error) {
		if tenant != testTenant {
			return nil, nil
		}
		return &entry, nil
	})
	issuer := upstream.URL + "/realms/" + testTenant
	now := time.Now()
	for _, tc := range []struct {
		name     string
		issuer   string
		audience any
		token    string
		expires  time.Time
		modified bool
		valid    bool
	}{
		{"valid subject with no subscription role", issuer, []string{arm}, "Bearer", now.Add(time.Minute), false, true},
		{"expired", issuer, arm, "Bearer", now.Add(-time.Minute), false, false},
		{"modified", issuer, arm, "Bearer", now.Add(time.Minute), true, false},
		{"wrong audience", issuer, graph, "Bearer", now.Add(time.Minute), false, false},
		{"multiple audiences", issuer, []string{arm, graph}, "Bearer", now.Add(time.Minute), false, false},
		{"foreign issuer", "https://foreign.ocean.test/realms/" + testTenant, arm, "Bearer", now.Add(time.Minute), false, false},
		{"unregistered tenant", upstream.URL + "/realms/" + foreignTenant, arm, "Bearer", now.Add(time.Minute), false, false},
		{"ID token", issuer, arm, "ID", now.Add(time.Minute), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"iss": tc.issuer, "sub": subject, "aud": tc.audience, "typ": tc.token, "exp": tc.expires.Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			token := encode([]byte(`{"alg":"RS256","kid":"test-key"}`)) + "." + encode(payload)
			digest := sha256.Sum256([]byte(token))
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if tc.modified {
				signature[0] ^= 1
			}
			request := httptest.NewRequest(http.MethodGet, arm+"/subscriptions?api-version="+subscriptionAPIVersion, nil)
			request.Header.Set("Authorization", "Bearer "+token+"."+encode(signature))
			principal, err := compat.AuthenticateARM(request.Context(), request)
			if !tc.valid {
				if !errors.Is(err, ErrInvalidARMToken) || principal.Subject != "" {
					t.Fatal("invalid token resolved a principal")
				}
				return
			}
			if err != nil || principal.Subject != subject || principal.Subscription.SubscriptionID != subscriptionID {
				t.Fatalf("expected the verified tenant principal: %v", err)
			}
			response := httptest.NewRecorder()
			compat.Handler().ServeHTTP(response, request)
			var list struct {
				Value []json.RawMessage `json:"value"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &list) != nil || list.Value == nil || len(list.Value) != 0 {
				t.Fatal("subscription discovery exposed a subscription to a principal without permission")
			}
		})
	}
}
