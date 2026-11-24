package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const subscriptionAPIVersion = "2022-12-01"

// Subscription is the initial subscription allocated to an ocean tenant.
// Its membership lists Keycloak subject identifiers authorized to discover it.
type Subscription struct {
	TenantID       string   `json:"tenantId"`
	SubscriptionID string   `json:"subscriptionId"`
	DisplayName    string   `json:"displayName"`
	Members        []string `json:"members"`
}

func readARMQuery(raw string, locations bool) (string, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", errors.New("The query string is invalid.")
	}
	for key, items := range values {
		if len(items) != 1 || (key != "api-version" && !(locations && key == "includeExtendedLocations" && items[0] == "false")) {
			return "", errors.New("The query contains an unsupported parameter or value.")
		}
	}
	return values.Get("api-version"), nil
}

// Valid checks identifiers and tenant ownership on records read from the store.
func (s Subscription) Valid(tenant string) bool {
	if s.TenantID != tenant || !tenantID.MatchString(s.TenantID) ||
		!tenantID.MatchString(s.SubscriptionID) || strings.TrimSpace(s.DisplayName) == "" {
		return false
	}
	for _, member := range s.Members {
		if !tenantID.MatchString(member) {
			return false
		}
	}
	return true
}

type subscriptionReader struct {
	location string
	lookup   func(context.Context, string) (*Subscription, error)
	granted  func(context.Context, Subscription, string) (bool, error)
}

// ARMPrincipal identifies a verified subject and its tenant subscription.
// Resource authorization is evaluated separately for each requested scope.
type ARMPrincipal struct {
	Subject      string
	Subscription Subscription
}

var (
	ErrInvalidARMToken        = errors.New("a valid ARM access token is required")
	ErrARMIdentityUnavailable = errors.New("the subscription store is unavailable")
)

// EnableSubscriptions registers ARM discovery against the regional tenant store.
func (c *Compatibility) EnableSubscriptions(location string, lookup func(context.Context, string) (*Subscription, error)) {
	if c.cloud.ResourceManager != "" {
		c.subscriptions = &subscriptionReader{location: location, lookup: lookup}
	}
}

// EnableSubscriptionGrants lets scoped roles expose their parent subscription
// to clients without granting subscription-wide resource permissions.
func (c *Compatibility) EnableSubscriptionGrants(check func(context.Context, Subscription, string) (bool, error)) {
	if c.subscriptions != nil {
		c.subscriptions.granted = check
	}
}

func (c *Compatibility) readSubscription(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, r)
		return
	}
	subscriptionID := r.PathValue("subscription")
	locations := subscriptionID != "" && strings.HasSuffix(r.URL.Path, "/locations")
	query, err := readARMQuery(r.URL.RawQuery, locations)
	if err != nil {
		armError(w, http.StatusBadRequest, "InvalidQueryParameter", err.Error())
		return
	}
	if query != subscriptionAPIVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Subscription discovery requires api-version="+subscriptionAPIVersion+".")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	principal, err := c.AuthenticateARM(ctx, r)
	if errors.Is(err, ErrARMIdentityUnavailable) {
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The subscription store is unavailable.")
		return
	}
	if err != nil {
		invalidARMToken(w)
		return
	}
	entry := principal.Subscription
	canRead := slices.Contains(entry.Members, principal.Subject)
	if !canRead && c.subscriptions.granted != nil && (subscriptionID == "" || strings.EqualFold(entry.SubscriptionID, subscriptionID)) {
		canRead, err = c.subscriptions.granted(ctx, entry, principal.Subject)
		if err != nil {
			armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The subscription grants are unavailable.")
			return
		}
	}
	if subscriptionID == "" {
		items := []map[string]any{}
		if canRead {
			items = append(items, entry.armView())
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": items})
		return
	}
	if !canRead || !strings.EqualFold(entry.SubscriptionID, subscriptionID) {
		armError(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription could not be found.")
		return
	}
	if locations {
		location := c.subscriptions.location
		writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]any{{
			"id": "/subscriptions/" + entry.SubscriptionID + "/locations/" + location, "name": location,
			"displayName": location, "regionalDisplayName": location,
			"metadata": map[string]string{"regionType": "Physical", "regionCategory": "Recommended"},
		}}})
		return
	}
	writeJSON(w, http.StatusOK, entry.armView())
}

// AuthenticateARM resolves the registered tenant and verifies its signed access
// token. An authenticated subject may still have no rights on the subscription.
func (c *Compatibility) AuthenticateARM(ctx context.Context, r *http.Request) (ARMPrincipal, error) {
	if c.subscriptions == nil || !strings.EqualFold(r.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		return ARMPrincipal{}, ErrInvalidARMToken
	}
	raw, issuer, tenant := c.bearerRealm(r)
	if tenant == "" {
		return ARMPrincipal{}, ErrInvalidARMToken
	}
	entry, err := c.subscriptions.lookup(ctx, tenant)
	if err != nil || (entry != nil && !entry.Valid(tenant)) {
		return ARMPrincipal{}, ErrARMIdentityUnavailable
	}
	if entry == nil {
		return ARMPrincipal{}, ErrInvalidARMToken
	}
	token, err := c.verifyAccessToken(ctx, raw, issuer, c.cloud.ResourceManager)
	var claims struct {
		Type string `json:"typ"`
	}
	if err != nil || token.Claims(&claims) != nil || claims.Type != "Bearer" || !tenantID.MatchString(token.Subject) {
		return ARMPrincipal{}, ErrInvalidARMToken
	}
	return ARMPrincipal{Subject: token.Subject, Subscription: *entry}, nil
}

// bearerRealm uses the unverified issuer only to locate a tenant record. Every
// caller must verify the signature and claims before using a token as identity.
func (c *Compatibility) bearerRealm(r *http.Request) (raw, issuer, tenant string) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || len(headers[0]) > 16<<10 {
		return "", "", ""
	}
	fields := strings.Fields(headers[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", "", ""
	}
	token := strings.Split(fields[1], ".")
	if len(token) != 3 {
		return "", "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(token[1])
	if err != nil {
		return "", "", ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", "", ""
	}
	tenant, ok := strings.CutPrefix(claims.Issuer, c.provider+"/realms/")
	if !ok || !tenantID.MatchString(tenant) {
		return "", "", ""
	}
	return fields[1], claims.Issuer, tenant
}

func (s Subscription) armView() map[string]any {
	return map[string]any{
		"id": "/subscriptions/" + s.SubscriptionID, "subscriptionId": s.SubscriptionID, "tenantId": s.TenantID,
		"displayName": s.DisplayName, "state": "Enabled", "authorizationSource": "RoleBased",
		"managedByTenants": []any{},
	}
}

func invalidARMToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	armError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid ARM access token is required.")
}

func armError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
