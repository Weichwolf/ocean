// Package arm implements the supported Azure Resource Manager contract.
package arm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/identity"
)

const resourceAPIVersion = "2024-11-01"

type Server struct {
	Origin       string
	Location     string
	Authenticate func(context.Context, *http.Request) (identity.ARMPrincipal, error)
	Groups       GroupStore
}

// Handler serves ARM routes over the same ingress as identity and discovery.
func (s Server) Handler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if !strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) ||
			(len(segments) != 3 && len(segments) != 4) || !strings.EqualFold(segments[0], "subscriptions") {
			fallback.ServeHTTP(w, r)
			return
		}
		resourceGroup := strings.EqualFold(segments[2], "resourcegroups")
		provider := len(segments) == 4 && strings.EqualFold(segments[2], "providers")
		if !resourceGroup && !provider {
			fallback.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		principal, ok := s.subscriptionPrincipal(ctx, w, r, segments[1])
		if !ok {
			return
		}
		entry := principal.Subscription
		if !slices.Contains(entry.Members, principal.Subject) {
			writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
			return
		}
		scope := SubscriptionScope{TenantID: entry.TenantID, SubscriptionID: entry.SubscriptionID}
		if provider {
			s.provider(w, r, scope, segments[3])
			return
		}
		name := ""
		if len(segments) == 4 {
			name = segments[3]
			if !validGroupName(name) {
				writeError(w, http.StatusBadRequest, "InvalidResourceGroup", "The resource group name is invalid.")
				return
			}
		}
		s.group(ctx, w, r, scope, name)
	})
}

func (s Server) subscriptionPrincipal(ctx context.Context, w http.ResponseWriter, r *http.Request, subscription string) (identity.ARMPrincipal, bool) {
	principal, err := s.Authenticate(ctx, r)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidARMToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid ARM access token is required.")
		} else {
			unavailable(w)
		}
		return identity.ARMPrincipal{}, false
	}
	if !strings.EqualFold(principal.Subscription.SubscriptionID, subscription) {
		writeError(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription could not be found.")
		return identity.ARMPrincipal{}, false
	}
	return principal, true
}

func readQuery(w http.ResponseWriter, r *http.Request, version string, parameterAllowed func(string, string) bool) (url.Values, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query string is invalid.")
		return nil, false
	}
	for key, items := range query {
		if len(items) != 1 || (key != "api-version" && (parameterAllowed == nil || !parameterAllowed(key, items[0]))) {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query contains an unsupported parameter or value.")
			return nil, false
		}
	}
	if query.Get("api-version") != version {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "This operation requires api-version="+version+".")
		return nil, false
	}
	return query, true
}

func methodNotAllowed(w http.ResponseWriter, methods string) {
	w.Header().Set("Allow", methods)
	writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "This method is unsupported at the requested scope.")
}

func unavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The regional resource store is unavailable.")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
