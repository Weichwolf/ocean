// Package arm implements the supported Azure Resource Manager contract.
package arm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Weichwolf/ocean/internal/identity"
)

const resourceAPIVersion = "2024-11-01"
const groupPageSize = 16

type SubscriptionScope struct {
	TenantID       string
	SubscriptionID string
}

type Group struct {
	Name     string            `json:"name"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
}

type GroupStore interface {
	GetGroup(context.Context, SubscriptionScope, string) (*Group, error)
	ListGroups(context.Context, SubscriptionScope, string, int) ([]Group, error)
	PutGroup(context.Context, SubscriptionScope, Group) (Group, bool, error)
	DeleteGroup(context.Context, SubscriptionScope, string) error
}

var ErrGroupLocation = errors.New("resource group location cannot change")

type Server struct {
	Origin       string
	Location     string
	Authenticate func(context.Context, *http.Request) (identity.ARMPrincipal, error)
	Groups       GroupStore
}

// Handler serves ARM resource routes over the same ingress as discovery.
func (s Server) Handler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if !strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) ||
			(len(segments) != 3 && len(segments) != 4) || !strings.EqualFold(segments[0], "subscriptions") ||
			!strings.EqualFold(segments[2], "resourcegroups") {
			fallback.ServeHTTP(w, r)
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
		s.group(w, r, segments[1], name)
	})
}

func (s Server) group(w http.ResponseWriter, r *http.Request, subscription, name string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	principal, err := s.Authenticate(ctx, r)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidARMToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid ARM access token is required.")
			return
		}
		unavailable(w)
		return
	}
	entry := principal.Subscription
	if !strings.EqualFold(entry.SubscriptionID, subscription) {
		writeError(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription could not be found.")
		return
	}
	if !slices.Contains(entry.Members, principal.Subject) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query string is invalid.")
		return
	}
	for key, items := range query {
		if len(items) != 1 || (key != "api-version" &&
			!(key == "$skiptoken" && name == "" && r.Method == http.MethodGet && validGroupName(items[0]) && items[0] == strings.ToLower(items[0]))) {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query contains an unsupported parameter or value.")
			return
		}
	}
	if query.Get("api-version") != resourceAPIVersion {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Resource groups require api-version="+resourceAPIVersion+".")
		return
	}
	scope := SubscriptionScope{TenantID: entry.TenantID, SubscriptionID: entry.SubscriptionID}
	if name == "" {
		if r.Method == http.MethodGet {
			s.listGroups(ctx, w, scope, query.Get("$skiptoken"))
			return
		}
		methodNotAllowed(w, "GET")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		group, err := s.Groups.GetGroup(ctx, scope, name)
		if err != nil {
			unavailable(w)
			return
		}
		if group == nil {
			writeError(w, http.StatusNotFound, "ResourceGroupNotFound", "The resource group could not be found.")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, group.view(scope))
	case http.MethodPut:
		s.putGroup(ctx, w, r, scope, name)
	case http.MethodDelete:
		if err := s.Groups.DeleteGroup(ctx, scope, name); err != nil {
			unavailable(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		methodNotAllowed(w, "GET, HEAD, PUT, DELETE")
	}
}

func (s Server) listGroups(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, after string) {
	groups, err := s.Groups.ListGroups(ctx, scope, after, groupPageSize+1)
	if err != nil {
		unavailable(w)
		return
	}
	count := min(len(groups), groupPageSize)
	result := make([]groupView, 0, count)
	for _, group := range groups[:count] {
		result = append(result, group.view(scope))
	}
	response := struct {
		Value    []groupView `json:"value"`
		NextLink string      `json:"nextLink,omitempty"`
	}{Value: result}
	if len(groups) > groupPageSize {
		query := url.Values{"api-version": {resourceAPIVersion}, "$skiptoken": {strings.ToLower(groups[groupPageSize-1].Name)}}
		response.NextLink = s.Origin + "/subscriptions/" + scope.SubscriptionID + "/resourcegroups?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s Server) putGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, name string) {
	var input struct {
		Location string            `json:"location"`
		Tags     map[string]string `json:"tags"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !validTags(input.Tags) {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "Specify a location and optional string tags.")
		return
	}
	if !strings.EqualFold(input.Location, s.Location) {
		writeError(w, http.StatusBadRequest, "InvalidLocation", "The resource group location is unsupported.")
		return
	}
	if input.Tags == nil {
		input.Tags = map[string]string{}
	}
	group, created, err := s.Groups.PutGroup(ctx, scope, Group{Name: name, Location: s.Location, Tags: input.Tags})
	if errors.Is(err, ErrGroupLocation) {
		writeError(w, http.StatusConflict, "InvalidResourceGroupLocation", "The resource group location cannot change.")
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, group.view(scope))
}

func validGroupName(name string) bool {
	if name == "" || strings.HasSuffix(name, ".") || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 90 {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_.()", r)
	})
}

func validTags(tags map[string]string) bool {
	if len(tags) > 50 {
		return false
	}
	keys := make(map[string]struct{}, len(tags))
	for name, value := range tags {
		key := strings.ToLower(name)
		if _, exists := keys[key]; exists || name == "" || utf8.RuneCountInString(name) > 512 || utf8.RuneCountInString(value) > 256 {
			return false
		}
		keys[key] = struct{}{}
	}
	return true
}

type groupView struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Group
	Properties map[string]string `json:"properties"`
}

func (g Group) view(scope SubscriptionScope) groupView {
	return groupView{ID: "/subscriptions/" + scope.SubscriptionID + "/resourceGroups/" + g.Name, Type: "Microsoft.Resources/resourceGroups",
		Group: g, Properties: map[string]string{"provisioningState": "Succeeded"}}
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
