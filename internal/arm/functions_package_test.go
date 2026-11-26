package arm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/identity"
)

type fixtureSCM struct {
	deploy func(context.Context, SubscriptionScope, string, string, []byte) (functions.DeploymentStatus, error)
}

func (s fixtureSCM) DeployFunctionZIP(ctx context.Context, scope SubscriptionScope, actor, host string, archive []byte) (functions.DeploymentStatus, error) {
	return s.deploy(ctx, scope, actor, host, archive)
}

func (fixtureSCM) FunctionZIPStatus(_ context.Context, _ SubscriptionScope, _ string) (functions.DeploymentStatus, error) {
	return functions.DeploymentStatus{ID: "deployment", Status: functions.DeploymentSucceeded, Complete: true}, nil
}

func TestFunctionsSCMCLIRequestShape(t *testing.T) {
	data, err := os.ReadFile("../../tests/e2e/testdata/functions-zip-cli-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var trace []struct {
		Command     string
		Method      string
		Path        string
		Query       url.Values
		ContentType string
		AuthScheme  string
	}
	if err := json.Unmarshal(data, &trace); err != nil {
		t.Fatal(err)
	}
	scope := SubscriptionScope{TenantID: "tenant", SubscriptionID: "subscription"}
	requests := 0
	called := 0
	var expectedHost string
	s := Server{Origin: "https://arm.ocean.test", FunctionDomain: "functions.ocean.test", FunctionSCMDomain: "scm.ocean.test",
		FunctionPackages: fixtureSCM{deploy: func(_ context.Context, got SubscriptionScope, actor, host string, code []byte) (functions.DeploymentStatus, error) {
			called++
			if got != scope || actor != "owner" || host != expectedHost || string(code) != "disposable upload" {
				t.Fatal("the SCM handler did not preserve the authenticated deployment target")
			}
			return functions.DeploymentStatus{ID: "deployment"}, nil
		}},
		AuthenticateSCM: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			token := request.Header.Get("Authorization")
			if token != "Bearer owner" && token != "Bearer reader" {
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: strings.TrimPrefix(token, "Bearer "), Subscription: identity.Subscription{
				TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Members: []string{"owner"}}}, nil
		}}
	handle := s.Handler(http.NotFoundHandler())
	for _, item := range trace {
		path := item.Path
		if item.Command != "zip-production" && item.Command != "zip-slot" || path != "/api/zipdeploy" && path != "/api/deployments/latest" {
			continue
		}
		if item.AuthScheme != "Bearer" {
			t.Fatal("the captured CLI used an unexpected deployment credential")
		}
		requests++
		label := "native"
		if item.Command == "zip-slot" {
			label += "-staging"
		}
		expectedHost = label + ".functions.ocean.test"
		target := "https://" + label + ".scm.ocean.test" + path
		if len(item.Query) != 0 {
			target += "?" + item.Query.Encode()
		}
		for token, denied := range map[string]int{"Bearer owner": 0, "Bearer reader": http.StatusForbidden, "Basic owner": http.StatusUnauthorized} {
			request := httptest.NewRequest(item.Method, target, strings.NewReader("disposable upload"))
			request.Header.Set("Authorization", token)
			request.Header.Set("Content-Type", item.ContentType)
			response := httptest.NewRecorder()
			handle.ServeHTTP(response, request)
			if denied != 0 {
				if response.Code != denied {
					t.Fatalf("the SCM credential was not rejected: HTTP %d", response.Code)
				}
				continue
			}
			code := http.StatusOK
			if item.Method == http.MethodPost {
				code = http.StatusAccepted
			}
			if response.Code != code || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "disposable upload") {
				t.Fatalf("SCM %s did not match the observed Azure CLI request: HTTP %d", path, response.Code)
			}
		}
	}
	if requests != 4 || called != 2 {
		t.Fatal("the captured upload and deployment poll did not exercise distinct authorized routes")
	}
}
