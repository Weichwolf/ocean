package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

const hostedOperatorVersion = "2026-11-01"

var (
	ErrPlacementPolicy      = errors.New("placement pools or quota are outside the hosted policy")
	ErrPlacementPolicyInUse = errors.New("active reservations or shares prevent narrowing the hosted pool policy")
	ErrPlacementPolicyQuota = errors.New("the new quota is below current usage")
	ErrPlacementTenantGone  = errors.New("the hosted tenant subscription is unavailable")
)

type PlacementPolicy struct {
	Pools []string            `json:"pools"`
	Quota enrollment.Capacity `json:"quota"`
}

type PlacementPolicyStore interface {
	ReadTenantPlacementPolicy(context.Context, Subscription, string) (PlacementPolicy, error)
	WriteTenantPlacementPolicy(context.Context, Subscription, string, PlacementPolicy) (PlacementPolicy, error)
}

// EnablePlacementPolicies adds the hosted operator API to the ARM origin.
func (c *Compatibility) EnablePlacementPolicies(store PlacementPolicyStore) error {
	if c.onboarding == nil || c.subscriptions == nil || c.cloud.ResourceManager == "" || store == nil {
		return errors.New("hosted placement requires tenant onboarding and an ARM origin")
	}
	c.placement = store
	return nil
}

func (c *Compatibility) tenantPlacementPolicy(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	tenant, actor, ok := c.hostedOperator(ctx, w, req)
	if !ok {
		return
	}
	subscription, err := c.subscriptions.lookup(ctx, tenant)
	if err != nil || subscription != nil && !subscription.Valid(tenant) {
		placementPolicyError(w, ErrARMIdentityUnavailable)
		return
	}
	if subscription == nil {
		placementPolicyError(w, ErrPlacementTenantGone)
		return
	}
	var policy PlacementPolicy
	if req.Method == http.MethodPut {
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF {
			armError(w, http.StatusBadRequest, "InvalidRequestContent", "Submit one placement policy with pools and quota.")
			return
		}
		policy, err = c.placement.WriteTenantPlacementPolicy(ctx, *subscription, actor, policy)
	} else {
		policy, err = c.placement.ReadTenantPlacementPolicy(ctx, *subscription, actor)
	}
	if err != nil {
		placementPolicyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (c *Compatibility) hostedOperator(ctx context.Context, w http.ResponseWriter, req *http.Request) (tenant, actor string, ok bool) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, req)
		return "", "", false
	}
	w.Header().Set("Cache-Control", "no-store")
	actor, err := c.authenticateOperator(ctx, req)
	if err != nil {
		if errors.Is(err, errOperatorDenied) {
			armError(w, http.StatusForbidden, "AuthorizationFailed", "This hosted operation requires an ocean operator.")
		} else {
			invalidARMToken(w)
		}
		return "", "", false
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["api-version"]) != 1 || query.Get("api-version") != hostedOperatorVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Hosted operations require api-version="+hostedOperatorVersion+".")
		return "", "", false
	}
	tenant = req.PathValue("tenant")
	if !tenantID.MatchString(tenant) || tenant == c.onboarding.config.OperatorTenant {
		armError(w, http.StatusBadRequest, "InvalidTenant", "Use a customer tenant UUID.")
		return "", "", false
	}
	return tenant, actor, true
}

func placementPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPlacementPolicy):
		armError(w, http.StatusBadRequest, "InvalidPlacementPolicy", err.Error())
	case errors.Is(err, ErrPlacementPolicyInUse):
		armError(w, http.StatusConflict, "PlacementPolicyInUse", err.Error())
	case errors.Is(err, ErrPlacementPolicyQuota):
		armError(w, http.StatusConflict, "QuotaExceeded", err.Error())
	case errors.Is(err, ErrPlacementTenantGone):
		armError(w, http.StatusNotFound, "ResourceNotFound", err.Error())
	default:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The hosted placement policy is temporarily unavailable.")
	}
}
