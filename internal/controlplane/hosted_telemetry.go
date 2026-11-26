package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type hostedTelemetryPolicy struct {
	OperatorPool     string   `json:"operatorPool"`
	Endpoints        []string `json:"endpoints"`
	RetentionSeconds int64    `json:"retentionSeconds"`
}

func (cfg regionConfig) telemetryPool() (string, error) {
	if cfg.Telemetry != nil {
		for _, endpoint := range cfg.Telemetry.Etcd.Endpoints {
			if slices.Contains(cfg.Etcd.Endpoints, endpoint) {
				return "", errors.New("telemetry requires separate etcd endpoints")
			}
		}
	}
	if cfg.HostedWorkplace == nil {
		return "", nil
	}
	policy := cfg.HostedWorkplace.Telemetry
	if policy == nil && cfg.Telemetry == nil {
		return "", nil
	}
	if policy == nil || cfg.Telemetry == nil || !cfg.HostedWorkplace.allowsPool(policy.OperatorPool) || len(policy.Endpoints) == 0 ||
		policy.RetentionSeconds != cfg.Telemetry.RetentionSeconds {
		return "", errors.New("hosted telemetry requires an approved operator pool, exact HTTPS origins and matching retention")
	}
	slices.Sort(policy.Endpoints)
	for index, endpoint := range policy.Endpoints {
		if !validEtcdOrigin(endpoint) || index > 0 && policy.Endpoints[index-1] == endpoint {
			return "", errors.New("hosted telemetry requires distinct HTTPS origins")
		}
	}
	if !slices.Equal(policy.Endpoints, slices.Sorted(slices.Values(cfg.Telemetry.Etcd.Endpoints))) {
		return "", errors.New("telemetry origins differ from the approved hosted regional policy")
	}
	return policy.OperatorPool, nil
}

func (r *Region) bootstrapHostedTelemetry(ctx context.Context) error {
	if r.hosted == nil {
		return nil
	}
	var expected []byte
	if r.hosted.Telemetry != nil {
		var err error
		expected, err = json.Marshal(r.hosted.Telemetry)
		if err != nil {
			return err
		}
	}
	return r.bootstrapHostedApproval(ctx, r.root+"/telemetry/policy", "telemetry", expected)
}

func (r *Region) hostedTelemetryAdmission(ctx context.Context, scope arm.SubscriptionScope, hostPool string, revision int64) (bool, error) {
	if err := r.requireActiveHostedTenant(ctx, scope.TenantID); err != nil {
		if errors.Is(err, identity.ErrTenantSuspended) {
			return false, nil
		}
		return false, err
	}
	policy, _, err := r.placementPolicy(ctx, r.armPrefix(scope)+"placement-policy", true, clientv3.WithRev(revision))
	return slices.Contains(policy.Pools, r.telemetry.pool) &&
		(hostPool == "" || slices.Contains(policy.Pools, hostPool)), err
}
