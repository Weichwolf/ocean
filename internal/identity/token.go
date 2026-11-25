package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

const (
	deviceGrant    = "urn:ietf:params:oauth:grant-type:device_code"
	exchangeGrant  = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessType     = "urn:ietf:params:oauth:token-type:access_token"
	exchangeClient = "ocean-token-exchange"
)

func readExchangeSecret(directory, tenant string) (string, error) {
	if !tenantID.MatchString(tenant) {
		return "", errors.New("invalid tenant ID")
	}
	file, err := os.OpenInRoot(directory, tenant+".secret")
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("exchange credential must be a private regular file")
	}
	bytes, err := io.ReadAll(io.LimitReader(file, 513))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(bytes))
	if len(bytes) > 512 || len(secret) < 32 || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("invalid exchange credential")
	}
	return secret, nil
}

func (c *Compatibility) token(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	if !tenantID.MatchString(tenant) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOIDCBody)
	if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	form := r.PostForm
	for _, values := range form {
		if len(values) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	clientID := form.Get("client_id")
	issuer := c.provider + "/realms/" + tenant
	endpoint := issuer + "/protocol/openid-connect/token"
	if form.Get("grant_type") == "client_credentials" && tenantID.MatchString(clientID) && clientID != cliClientID {
		c.servicePrincipalToken(w, r, endpoint, issuer)
		return
	}
	if clientID != cliClientID || len(r.Header.Values("Authorization")) != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	c.userToken(w, r, tenant, endpoint, issuer)
}

func (c *Compatibility) servicePrincipalToken(w http.ResponseWriter, r *http.Request, endpoint, issuer string) {
	form := r.PostForm
	authorization := r.Header.Get("Authorization")
	if !tokenFields(form, "client_secret") || len(r.Header.Values("Authorization")) > 1 {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	client := form.Get("client_id")
	secret := form.Get("client_secret")
	if authorization != "" {
		var basicClient string
		var ok bool
		basicClient, secret, ok = r.BasicAuth()
		if !ok || basicClient != client || secret == "" || form.Has("client_secret") {
			oauthError(w, http.StatusBadRequest, "invalid_client")
			return
		}
	} else if secret == "" {
		oauthError(w, http.StatusBadRequest, "invalid_client")
		return
	}
	audience, _, err := c.splitScopes(form.Get("scope"))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	// Azure CLI may send client_info for its token cache. Keycloak has no use for it.
	form.Del("client_info")
	var principal string
	if c.onboarding != nil {
		private, subject, err := c.onboarding.authenticateClient(r.Context(), r.PathValue("tenant"), client, secret)
		switch {
		case errors.Is(err, errClientCredential):
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		case err != nil:
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		case private != "":
			authorization = ""
			form.Set("client_secret", private)
			principal = subject
		}
	}
	data, status, err := c.providerJSON(r.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()), authorization)
	if !acceptGrant(w, status, data, err) {
		return
	}
	if identity, ok := c.providerAccessToken(r.Context(), data, issuer, audience, client); !ok ||
		(principal != "" && identity.Subject != principal) {
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func (c *Compatibility) userToken(w http.ResponseWriter, r *http.Request, tenant, endpoint, issuer string) {
	form := r.PostForm
	audience := c.cloud.ResourceManager
	switch form.Get("grant_type") {
	case deviceGrant:
		// MSAL polls without a resource scope. The device endpoint admits ARM
		// only and the native device grant is restricted to the exchange client.
		code := form.Get("device_code")
		if !tokenFields(form, "device_code", "code") || code == "" ||
			(form.Has("code") && form.Get("code") != code) || form.Has("scope") {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		form.Del("code")
	case "refresh_token":
		if !tokenFields(form, "refresh_token") || form.Get("refresh_token") == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var err error
		audience, _, err = c.splitScopes(form.Get("scope"))
		if err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_scope")
			return
		}
		// Keycloak refreshes the original, neutral grant. The requested
		// resource participates only in the subsequent token exchange.
		form.Del("scope")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	form.Del("client_info")
	secret, err := c.exchangeSecret(tenant)
	if errors.Is(err, os.ErrNotExist) {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if err != nil {
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	grant, status, err := c.upstream(r.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if !acceptGrant(w, status, grant, err) {
		return
	}
	source, ok := c.providerAccessToken(r.Context(), grant, issuer, exchangeClient, cliClientID)
	if !ok {
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	request := url.Values{
		"grant_type":         {exchangeGrant},
		"subject_token":      {jsonString(grant["access_token"])},
		"subject_token_type": {accessType},
		"scope":              {audience + "/.default"},
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(exchangeClient+":"+url.QueryEscape(secret)))
	exchanged, status, err := c.providerJSON(r.Context(), http.MethodPost, endpoint, strings.NewReader(request.Encode()), auth)
	destination, ok := c.providerAccessToken(r.Context(), exchanged, issuer, audience, exchangeClient)
	if err != nil || status != http.StatusOK || !ok || destination.Subject != source.Subject ||
		destination.Expires > source.Expires || exchanged["refresh_token"] != nil ||
		!slices.Contains(strings.Fields(jsonString(exchanged["scope"])), audience+"/.default") {
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	for _, field := range []string{"access_token", "expires_in", "scope", "token_type"} {
		grant[field] = exchanged[field]
	}
	delete(grant, "session_state")
	writeJSON(w, http.StatusOK, grant)
}

func (c *Compatibility) splitScopes(scope string) (audience, provider string, err error) {
	var oidc []string
	for _, item := range strings.Fields(scope) {
		switch item {
		case "openid", "profile", "offline_access":
			oidc = append(oidc, item)
		case c.cloud.ResourceManager + "/.default", c.cloud.MicrosoftGraph + "/.default":
			if audience != "" {
				return "", "", errors.New("exactly one resource scope is required")
			}
			audience = strings.TrimSuffix(item, "/.default")
		default:
			return "", "", errors.New("unsupported token scope")
		}
	}
	if audience == "" {
		return "", "", errors.New("a resource scope is required")
	}
	return audience, strings.Join(oidc, " "), nil
}

func tokenFields(form url.Values, extra ...string) bool {
	for field := range form {
		switch field {
		case "client_id", "client_info", "grant_type", "scope", "claims":
		default:
			if !slices.Contains(extra, field) {
				return false
			}
		}
	}
	return true
}

func acceptGrant(w http.ResponseWriter, status int, data map[string]json.RawMessage, err error) bool {
	if err == nil && status == http.StatusOK {
		return true
	}
	if err == nil && (status == http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden) {
		code := jsonString(data["error"])
		switch code {
		case "authorization_pending", "slow_down", "expired_token", "access_denied", "invalid_grant",
			"invalid_request", "invalid_scope", "invalid_client", "unauthorized_client", "unsupported_grant_type":
			oauthError(w, status, code)
			return false
		}
	}
	oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
	return false
}

func (c *Compatibility) providerAccessToken(ctx context.Context, data map[string]json.RawMessage, issuer, audience, client string) (accessIdentity, bool) {
	var lifetime int64
	if !strings.EqualFold(jsonString(data["token_type"]), "Bearer") ||
		json.Unmarshal(data["expires_in"], &lifetime) != nil || lifetime <= 0 {
		return accessIdentity{}, false
	}
	token, err := c.verifyAccessToken(ctx, jsonString(data["access_token"]), issuer, audience)
	if err != nil {
		return accessIdentity{}, false
	}
	var claims struct {
		Client string `json:"azp"`
		Type   string `json:"typ"`
	}
	if token.Claims(&claims) != nil || claims.Client != client || claims.Type != "Bearer" {
		return accessIdentity{}, false
	}
	return accessIdentity{Subject: token.Subject, Expires: token.Expiry.Unix()}, true
}

type accessIdentity struct {
	Subject string
	Expires int64
}
