package identity

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"
)

var ErrInvalidDesktopToken = errors.New("a current managed desktop application token is required")

// DesktopPrincipal binds a verified browser subject to its native AD object.
// An ARM subject, a user-supplied principal ID, and an application identity
// cannot supply this binding.
type DesktopPrincipal struct {
	Tenant      TenantReservation
	DirectoryID string
	UserID      string
	AppGroupIDs []string
	ExpiresAt   time.Time
}

func (c *Compatibility) AuthenticateDesktop(ctx context.Context, request *http.Request) (DesktopPrincipal, error) {
	var empty DesktopPrincipal
	raw, issuer, tenant := c.bearerRealm(request)
	if c.onboarding == nil || tenant == "" {
		return empty, ErrInvalidDesktopToken
	}
	cfg := c.onboarding.config.WebDirectories[tenant]
	if cfg.DesktopApplicationID == "" {
		return empty, ErrInvalidDesktopToken
	}
	app, err := lookupGraphApplication(ctx, c.onboarding.store, tenant, "id", cfg.DesktopApplicationID)
	if errors.Is(err, errDirectoryNotFound) ||
		err == nil && (app == nil || app.WebPolicy == nil || app.WebPolicy.NativeID == "" || app.WebPolicy.DirectoryID != cfg.DirectoryID ||
			!validWebGroupIDs(app.WebPolicy.GroupIDs)) {
		return empty, ErrInvalidDesktopToken
	}
	if err != nil {
		return empty, err
	}
	token, err := c.verifyAccessToken(ctx, raw, issuer, app.ClientID)
	var claims struct {
		Type      string `json:"typ"`
		Client    string `json:"azp"`
		Assurance string `json:"acr"`
	}
	if err != nil || token.Claims(&claims) != nil || !tenantID.MatchString(token.Subject) ||
		claims.Type != "Bearer" || claims.Client != app.ClientID || claims.Assurance != "ocean-web" ||
		token.IssuedAt.IsZero() || token.IssuedAt.After(time.Now().Add(10*time.Second)) ||
		token.Expiry.Sub(token.IssuedAt) <= 0 || token.Expiry.Sub(token.IssuedAt) > 120*time.Second {
		return empty, ErrInvalidDesktopToken
	}
	reservation, err := c.onboarding.store.LookupTenant(ctx, tenant)
	if err != nil {
		return empty, err
	}
	if reservation == nil || !reservation.Valid(tenant) {
		return empty, ErrInvalidDesktopToken
	}
	user, err := c.onboarding.admin.directoryUser(ctx, tenant, token.Subject)
	if err != nil {
		return empty, err
	}
	if user == nil || !user.Enabled || user.FederationLink != cfg.DirectoryID {
		return empty, ErrInvalidDesktopToken
	}
	native := user.Attributes[managedLDAPObjectID]
	if len(native) != 1 || !tenantID.MatchString(native[0]) {
		return empty, ErrInvalidDesktopToken
	}
	return DesktopPrincipal{Tenant: *reservation, DirectoryID: cfg.DirectoryID, UserID: native[0],
		AppGroupIDs: slices.Clone(app.WebPolicy.GroupIDs), ExpiresAt: token.Expiry}, nil
}
