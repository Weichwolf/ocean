package arm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/identity"
)

type desktopAdmissionStore struct {
	DesktopStore
	subject identity.DesktopPrincipal
	address ResourceAddress
}

func (s *desktopAdmissionStore) AuthorizePersonalDesktop(_ context.Context, subject identity.DesktopPrincipal, address ResourceAddress) (DesktopAdmission, error) {
	s.subject, s.address = subject, address
	return DesktopAdmission{AssignmentID: "assignment", MachineID: "machine", ExpiresAt: subject.ExpiresAt}, nil
}

func TestDesktopAuthorizationUsesBrowserIdentity(t *testing.T) {
	const origin = "https://arm.ocean.test"
	const subscription = "84b678b0-0a39-47d3-a355-ff4d84de4a83"
	const foreign = "310dee94-5876-489a-a5a9-4e25515f30e6"
	browser := identity.DesktopPrincipal{Tenant: identity.TenantReservation{SubscriptionID: subscription}, UserID: "browser-user",
		ExpiresAt: time.Now().Add(time.Minute)}
	for _, tc := range []struct {
		name, method, subscription, credential, body string
		status                                       int
	}{
		{"browser action", http.MethodPost, subscription, "browser", "", http.StatusOK},
		{"ARM credential", http.MethodPost, subscription, "arm", "", http.StatusUnauthorized},
		{"foreign subscription", http.MethodPost, foreign, "browser", "", http.StatusNotFound},
		{"unexpected identity override", http.MethodPost, subscription, "browser", `{"userId":"other-user"}`, http.StatusBadRequest},
		{"unsupported method", http.MethodGet, subscription, "browser", "", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &desktopAdmissionStore{}
			api := Server{Origin: origin, Desktops: store,
				Authenticate: func(context.Context, *http.Request) (identity.ARMPrincipal, error) {
					t.Fatal("desktop authorization used the ARM authenticator")
					return identity.ARMPrincipal{}, nil
				},
				AuthenticateDesktop: func(_ context.Context, request *http.Request) (identity.DesktopPrincipal, error) {
					if request.Header.Get("Authorization") != "Bearer browser" {
						return identity.DesktopPrincipal{}, identity.ErrInvalidDesktopToken
					}
					return browser, nil
				},
			}
			request := httptest.NewRequestWithContext(t.Context(), tc.method, origin+"/subscriptions/"+tc.subscription+
				"/resourceGroups/workplace/providers/"+DesktopType+"/personal/authorize?api-version="+DesktopAPIVersion, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer "+tc.credential)
			recorder := httptest.NewRecorder()
			api.Handler(http.NotFoundHandler()).ServeHTTP(recorder, request)
			if recorder.Code != tc.status || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("desktop authorization returned %d: %s", recorder.Code, recorder.Body)
			}
			if tc.status == http.StatusOK {
				want := ResourceAddress{Group: "workplace", Path: DesktopType + "/personal"}
				if store.subject != browser || store.address != want {
					t.Fatalf("unexpected desktop authorization input: %+v, %+v", store.subject, store.address)
				}
			} else if store.address != (ResourceAddress{}) {
				t.Fatal("a denied request was forwarded to the authorization store")
			}
		})
	}
}
