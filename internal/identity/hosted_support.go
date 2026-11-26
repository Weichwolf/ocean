package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	ErrSupportDenied   = errors.New("hosted support access is denied")
	ErrSupportMissing  = errors.New("the support grant or resource does not exist")
	ErrSupportInvalid  = errors.New("submit a scoped support grant with an expiry within one hour")
	ErrSupportConflict = errors.New("the support grant ID already identifies a different approval")
)

type HostedSupportRequest struct {
	PrincipalID  string    `json:"principalId"`
	OperatorPool string    `json:"operatorPool"`
	ResourceID   string    `json:"resourceId"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type HostedSupportGrant struct {
	HostedSupportRequest
	ID                string    `json:"grantId"`
	TenantID          string    `json:"tenantId"`
	SubscriptionID    string    `json:"subscriptionId"`
	ApprovedBy        string    `json:"approvedBy"`
	ApprovedAt        time.Time `json:"approvedAt"`
	ResourceCreatedAt time.Time `json:"resourceCreatedAt"`
	RevokedAt         time.Time `json:"revokedAt,omitzero"`
	RevokedBy         string    `json:"revokedBy,omitempty"`
}

type HostedSupportDiagnostic struct {
	GrantID           string    `json:"grantId"`
	ResourceID        string    `json:"resourceId"`
	Location          string    `json:"location"`
	APIVersion        string    `json:"apiVersion"`
	ProvisioningState string    `json:"provisioningState"`
	ChangedAt         time.Time `json:"changedAt"`
}

type HostedSupportStore interface {
	ManageHostedSupport(context.Context, ARMPrincipal, string, string, *HostedSupportRequest) (HostedSupportGrant, error)
	ReadHostedSupport(context.Context, string, string, string, netip.Addr) (HostedSupportDiagnostic, error)
}

type hostedSupport struct {
	client, authContext string
	store               HostedSupportStore
}

func (c *Compatibility) EnableHostedSupport(client, authContext string, store HostedSupportStore) error {
	if c.offboarding == nil || c.onboarding == nil || store == nil || !tenantID.MatchString(client) ||
		client == cliClientID || client == c.onboarding.config.OperatorClient || authContext == "" || len(authContext) > 64 {
		return errors.New("hosted support requires a distinct operator client and an authentication context")
	}
	c.hostedSupport = &hostedSupport{client: client, authContext: authContext, store: store}
	return nil
}

func (c *Compatibility) supportTarget(w http.ResponseWriter, req *http.Request) (tenant, grant string, ok bool) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, req)
		return "", "", false
	}
	w.Header().Set("Cache-Control", "no-store")
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["api-version"]) != 1 || query.Get("api-version") != hostedOperatorVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Hosted support requires api-version="+hostedOperatorVersion+".")
		return "", "", false
	}
	tenant, grant = req.PathValue("tenant"), req.PathValue("grant")
	if !tenantID.MatchString(tenant) || tenant == c.onboarding.config.OperatorTenant || !tenantID.MatchString(grant) {
		hostedSupportError(w, ErrSupportMissing)
		return "", "", false
	}
	return tenant, grant, true
}

func (c *Compatibility) manageHostedSupport(w http.ResponseWriter, req *http.Request) {
	tenant, id, ok := c.supportTarget(w, req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	principal, err := c.AuthenticateARM(ctx, req)
	if err != nil {
		hostedSupportError(w, err)
		return
	}
	if principal.Subscription.TenantID != tenant {
		hostedSupportError(w, ErrSupportDenied)
		return
	}
	var input *HostedSupportRequest
	if req.Method == http.MethodPut {
		input = new(HostedSupportRequest)
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF || !tenantID.MatchString(input.PrincipalID) {
			hostedSupportError(w, ErrSupportInvalid)
			return
		}
	}
	grant, err := c.hostedSupport.store.ManageHostedSupport(ctx, principal, id, req.Method, input)
	if err != nil {
		hostedSupportError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

func (c *Compatibility) readHostedSupport(w http.ResponseWriter, req *http.Request) {
	tenant, id, ok := c.supportTarget(w, req)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	raw, issuer, realm := c.bearerRealm(req)
	if realm == "" {
		hostedSupportError(w, ErrInvalidARMToken)
		return
	}
	if realm != c.onboarding.config.OperatorTenant {
		hostedSupportError(w, ErrSupportDenied)
		return
	}
	token, err := c.verifyAccessToken(ctx, raw, issuer, c.cloud.ResourceManager)
	var claims struct {
		Type     string `json:"typ"`
		Client   string `json:"azp"`
		ACR      string `json:"acr"`
		AuthTime int64  `json:"auth_time"`
	}
	if err != nil || token.Claims(&claims) != nil || claims.Type != "Bearer" || !tenantID.MatchString(token.Subject) {
		hostedSupportError(w, ErrInvalidARMToken)
		return
	}
	authAge := time.Since(time.Unix(claims.AuthTime, 0))
	if claims.Client != c.hostedSupport.client || claims.ACR != c.hostedSupport.authContext || authAge < -30*time.Second || authAge > 15*time.Minute {
		hostedSupportError(w, ErrSupportDenied)
		return
	}
	peer, _, err := net.SplitHostPort(req.RemoteAddr)
	address, ipErr := netip.ParseAddr(peer)
	if err != nil || ipErr != nil {
		hostedSupportError(w, ErrSupportDenied)
		return
	}
	diagnostic, err := c.hostedSupport.store.ReadHostedSupport(ctx, tenant, id, token.Subject, address.Unmap())
	if err != nil {
		hostedSupportError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, diagnostic)
}

func hostedSupportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidARMToken):
		invalidARMToken(w)
	case errors.Is(err, ErrSupportDenied), errors.Is(err, ErrTenantSuspended):
		armError(w, http.StatusForbidden, "AuthorizationFailed", ErrSupportDenied.Error())
	case errors.Is(err, ErrSupportInvalid):
		armError(w, http.StatusBadRequest, "InvalidSupportGrant", err.Error())
	case errors.Is(err, ErrSupportMissing):
		armError(w, http.StatusNotFound, "ResourceNotFound", err.Error())
	case errors.Is(err, ErrSupportConflict):
		armError(w, http.StatusConflict, "SupportGrantConflict", err.Error())
	default:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "Hosted support is temporarily unavailable.")
	}
}
