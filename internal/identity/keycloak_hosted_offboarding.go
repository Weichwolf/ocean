package identity

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// SuspendHostedRealm disables and drains the Keycloak realm owned by this
// decision. Detached JWT validators must still enforce their own token expiry.
func (c *Compatibility) SuspendHostedRealm(ctx context.Context, decision HostedOffboarding) error {
	if c.offboarding == nil || !decision.Valid(decision.TenantID) || decision.TenantID == c.onboarding.config.OperatorTenant {
		return errors.New("invalid hosted identity suspension")
	}
	return c.onboarding.admin.suspendHostedRealm(ctx, decision)
}

func (k keycloakAdmin) suspendHostedRealm(ctx context.Context, decision HostedOffboarding) error {
	for _, origin := range k.endpoints {
		token, err := k.login(ctx, origin)
		if err != nil {
			continue
		}
		err = k.confirmHostedRealmDisabled(ctx, origin+"/admin/realms/"+decision.TenantID, token, decision)
		if err == nil || errors.Is(err, ErrTenantConflict) {
			return err
		}
	}
	return errors.New("Keycloak has not confirmed the hosted realm suspension")
}

func (k keycloakAdmin) confirmHostedRealmDisabled(ctx context.Context, endpoint, token string, decision HostedOffboarding) error {
	read := func() (bool, error) {
		var realm struct {
			Name       string            `json:"realm"`
			Enabled    *bool             `json:"enabled"`
			Attributes map[string]string `json:"attributes"`
		}
		status, err := k.request(ctx, http.MethodGet, endpoint, token, "", nil, &realm)
		if err != nil || status != http.StatusOK || realm.Enabled == nil {
			return false, errors.New("Keycloak realm state is unavailable")
		}
		if realm.Name != decision.TenantID || realm.Attributes["oceanRegistration"] != decision.SubscriptionID {
			return false, ErrTenantConflict
		}
		return *realm.Enabled, nil
	}
	enabled, err := read()
	if err != nil {
		return err
	}
	if enabled {
		// Read back even after a failure. The disable may have committed before
		// the response was lost, and the current ownership must still match.
		_, _ = k.request(ctx, http.MethodPut, endpoint, token, "application/json", strings.NewReader(`{"enabled":false}`), nil)
		active, err := read()
		if err != nil {
			return err
		}
		if active {
			return errors.New("Keycloak realm is still enabled")
		}
	}
	active, err := k.hostedRealmHasOnlineSessions(ctx, endpoint, token)
	if err != nil {
		return err
	}
	if active || enabled {
		_, _ = k.request(ctx, http.MethodPost, endpoint+"/logout-all", token, "", nil, nil)
		active, err = k.hostedRealmHasOnlineSessions(ctx, endpoint, token)
		if err != nil {
			return err
		}
	}
	if active {
		return errors.New("Keycloak still lists online sessions for the disabled realm")
	}
	enabled, err = read()
	if err != nil {
		return err
	}
	if enabled {
		return errors.New("Keycloak realm was re-enabled during session verification")
	}
	return nil
}

func (k keycloakAdmin) hostedRealmHasOnlineSessions(ctx context.Context, endpoint, token string) (bool, error) {
	var sessions []struct {
		Active string `json:"active"`
	}
	status, err := k.request(ctx, http.MethodGet, endpoint+"/client-session-stats", token, "", nil, &sessions)
	if err != nil || status != http.StatusOK || sessions == nil {
		return false, errors.New("Keycloak session counts are unavailable")
	}
	for _, client := range sessions {
		count, err := strconv.ParseUint(client.Active, 10, 64)
		if err != nil {
			return false, errors.New("Keycloak returned an invalid online session count")
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}
