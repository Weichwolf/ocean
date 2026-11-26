package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

var ErrTenantSuspended = errors.New("the hosted tenant is suspended")

type HostedOffboarding struct {
	TenantID       string    `json:"tenantId"`
	SubscriptionID string    `json:"subscriptionId"`
	Actor          string    `json:"actor"`
	State          string    `json:"state"`
	DecidedAt      time.Time `json:"decidedAt"`
}

func (d HostedOffboarding) Valid(tenant string) bool {
	return d.TenantID == tenant && tenantID.MatchString(tenant) && tenantID.MatchString(d.SubscriptionID) &&
		tenantID.MatchString(d.Actor) && d.State == "Suspended" && !d.DecidedAt.IsZero()
}

type HostedOffboardingStore interface {
	HostedOffboarding(context.Context, string) (*HostedOffboarding, error)
	SuspendHostedTenant(context.Context, string, string, string) (*HostedOffboarding, error)
}

func (c *Compatibility) EnableHostedOffboarding(store HostedOffboardingStore) error {
	if c.onboarding == nil || c.subscriptions == nil || store == nil {
		return errors.New("hosted offboarding requires operator onboarding and the regional ARM origin")
	}
	c.offboarding = store
	return nil
}

func (c *Compatibility) hostedOffboarding(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	tenant, actor, ok := c.hostedOperator(ctx, w, req)
	if !ok {
		return
	}
	var decision *HostedOffboarding
	var err error
	if req.Method == http.MethodPut {
		var input struct {
			SubscriptionID string `json:"subscriptionId"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !tenantID.MatchString(input.SubscriptionID) {
			armError(w, http.StatusBadRequest, "InvalidRequestContent", "Submit the current subscription ID of the tenant to suspend.")
			return
		}
		decision, err = c.offboarding.SuspendHostedTenant(ctx, tenant, input.SubscriptionID, actor)
	} else {
		decision, err = c.offboarding.HostedOffboarding(ctx, tenant)
	}
	switch {
	case errors.Is(err, ErrPlacementTenantGone) || err == nil && decision == nil:
		armError(w, http.StatusNotFound, "ResourceNotFound", "The active subscription or offboarding decision does not exist.")
	case err != nil:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The hosted offboarding decision is temporarily unavailable.")
	default:
		writeJSON(w, http.StatusOK, decision)
	}
}

func (c *Compatibility) admitHostedOAuth(w http.ResponseWriter, r *http.Request, tenant string) bool {
	if c.offboarding == nil || tenant == c.onboarding.config.OperatorTenant {
		return true
	}
	decision, err := c.offboarding.HostedOffboarding(r.Context(), tenant)
	if err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return false
	}
	if decision != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant")
		return false
	}
	return true
}
