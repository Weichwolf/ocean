package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	cliClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
	maxOIDCBody = 64 << 10
)

var (
	tenantID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	userCode = regexp.MustCompile(`^[A-Za-z0-9-]{4,32}$`)
)

// Compatibility serves the tenant-specific discovery and device response formats
// consumed by Azure CLI. Keycloak owns the OAuth grants and signs the tokens.
type Compatibility struct {
	authority string
	provider  string
	client    *http.Client
	cloud     CloudEndpoints
}

// NewCompatibility pins the public origins used by the client and the provider.
// The transport can supply a private CA for the provider.
func NewCompatibility(authority, provider string, transport http.RoundTripper) (*Compatibility, error) {
	if !httpsOrigin(authority) || !httpsOrigin(provider) {
		return nil, errors.New("identity authority and provider must be HTTPS origins without trailing slashes")
	}
	return &Compatibility{
		authority: authority,
		provider:  provider,
		client: &http.Client{
			Transport:     transport,
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func httpsOrigin(raw string) bool {
	value, err := url.Parse(raw)
	return err == nil && value.Scheme == "https" && value.Hostname() != "" && value.User == nil &&
		value.Path == "" && value.RawQuery == "" && !value.ForceQuery && value.Fragment == "" &&
		raw == "https://"+value.Host
}

// Handler exposes only the compatibility routes. Native authorization, token,
// and key endpoints remain on the provider origin.
func (c *Compatibility) Handler() http.Handler {
	mux := http.NewServeMux()
	if c.cloud.ResourceManager != "" {
		mux.HandleFunc("GET /metadata/endpoints", c.cloudMetadata)
	}
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", c.discover)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode", c.device)
	return mux
}

func (c *Compatibility) discover(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	if !tenantID.MatchString(tenant) {
		http.NotFound(w, r)
		return
	}
	issuer := c.provider + "/realms/" + tenant
	protocol := issuer + "/protocol/openid-connect"
	data, status, err := c.upstream(r.Context(), http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if status == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	if err != nil || status != http.StatusOK ||
		!matches(data, "issuer", issuer) ||
		!matches(data, "authorization_endpoint", protocol+"/auth") ||
		!matches(data, "token_endpoint", protocol+"/token") ||
		!matches(data, "jwks_uri", protocol+"/certs") ||
		!matches(data, "device_authorization_endpoint", protocol+"/auth/device") {
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	data["device_authorization_endpoint"], _ = json.Marshal(c.authority + "/" + tenant + "/oauth2/v2.0/devicecode")
	writeJSON(w, http.StatusOK, data)
}

func (c *Compatibility) device(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	if !tenantID.MatchString(tenant) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOIDCBody)
	if err := r.ParseForm(); err != nil || len(r.PostForm["client_id"]) != 1 || r.PostForm.Get("client_id") != cliClientID ||
		len(r.PostForm["scope"]) != 1 || r.PostForm.Get("scope") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for field, values := range r.PostForm {
		if len(values) != 1 || (field != "client_id" && field != "scope" && field != "claims") {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	issuer := c.provider + "/realms/" + tenant
	data, status, err := c.upstream(r.Context(), http.MethodPost, issuer+"/protocol/openid-connect/auth/device", strings.NewReader(r.PostForm.Encode()))
	switch {
	case status == http.StatusNotFound:
		http.NotFound(w, r)
	case err != nil:
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
	case status == http.StatusBadRequest || status == http.StatusUnauthorized:
		code := jsonString(data["error"])
		switch code {
		case "invalid_client", "invalid_request", "invalid_scope", "unauthorized_client":
			oauthError(w, status, code)
		default:
			oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
		}
	case status == http.StatusOK:
		code := jsonString(data["user_code"])
		verification := issuer + "/device"
		if !matches(data, "verification_uri", verification) || !userCode.MatchString(code) || jsonString(data["device_code"]) == "" {
			oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
			return
		}
		data["message"], _ = json.Marshal("Open " + verification + " in a browser and enter the code " + code + " to sign in.")
		writeJSON(w, http.StatusOK, data)
	default:
		oauthError(w, http.StatusBadGateway, "temporarily_unavailable")
	}
}

func (c *Compatibility) upstream(ctx context.Context, method, endpoint string, body io.Reader) (map[string]json.RawMessage, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCBody+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(raw) > maxOIDCBody {
		return nil, response.StatusCode, errors.New("provider response exceeded size limit")
	}
	var data map[string]json.RawMessage
	err = json.Unmarshal(raw, &data)
	return data, response.StatusCode, err
}

func matches(data map[string]json.RawMessage, field, want string) bool {
	return jsonString(data[field]) == want
}

func jsonString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
