package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// hostedRegionPolicy records the approved physical country of the regional
// services and each operator pool. The operator establishes physical location
// when approving infrastructure and issuing its enrollment credentials.
type hostedRegionPolicy struct {
	Country       string            `json:"country"`
	OperatorPools map[string]string `json:"operatorPools"`
}

func euCountry(country string) bool {
	return slices.Contains([]string{"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU",
		"IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"}, country)
}

func (p *hostedRegionPolicy) validate() error {
	if p == nil {
		return nil
	}
	if !euCountry(p.Country) || len(p.OperatorPools) == 0 {
		return errors.New("the hosted region requires an EU country and approved operator pools")
	}
	for pool, country := range p.OperatorPools {
		if !identifier.MatchString(pool) || !euCountry(country) {
			return errors.New("hosted operator pools require valid identifiers and EU countries")
		}
	}
	return nil
}

func (p *hostedRegionPolicy) allowsPool(pool string) bool {
	return p == nil || p.OperatorPools[pool] != ""
}

func (p *hostedRegionPolicy) allowsPlacement(pools []string) bool {
	if p == nil {
		return true
	}
	if len(pools) == 0 {
		return false
	}
	for _, pool := range pools {
		if !p.allowsPool(pool) {
			return false
		}
	}
	return true
}

func (r *Region) validateHostedInventory(inventory []enrollment.Approval) error {
	if r.hosted == nil {
		return nil
	}
	compute := make(map[string]bool, len(inventory))
	for _, approved := range inventory {
		if !r.hosted.allowsPool(approved.Pool) {
			return errors.New("host enrollment references an unapproved hosted operator pool")
		}
		compute[approved.HostID] = slices.Contains(approved.Roles, "compute")
	}
	if r.storage != nil {
		for _, worker := range r.storage.workers {
			if !compute[worker] {
				return errors.New("a hosted storage worker is absent from the approved compute inventory")
			}
		}
	}
	if r.smb != nil {
		for host := range r.smb.hosts {
			if !compute[host] {
				return errors.New("a hosted SMB member is absent from the approved compute inventory")
			}
		}
	}
	return nil
}

// hostedHostGuards checks a fixed placement using the certified registration.
// It also covers an offline standby. The caller includes the revision guards
// when committing a placement or publishing a replacement writer.
func (r *Region) hostedHostGuards(ctx context.Context, scope arm.SubscriptionScope, host string, revision int64) ([]clientv3.Cmp, error) {
	if r.hosted == nil {
		return nil, nil
	}
	key := r.hostKey("registered", host)
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	var registration enrollment.Host
	if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &registration) != nil || registration.HostID != host ||
		len(registration.Certificate) == 0 || registration.RevokedAt != nil || !slices.Contains(registration.Roles, "compute") {
		return nil, enrollment.ErrHostDenied
	}
	if revision == 0 {
		revision = rows.Header.Revision
	}
	guard, err := r.hostedPoolGuard(ctx, scope, registration.Pool, revision)
	if err != nil {
		return nil, err
	}
	return []clientv3.Cmp{guard, clientv3.Compare(clientv3.ModRevision(key), "=", rows.Kvs[0].ModRevision)}, nil
}

func (r *Region) hostedPoolGuard(ctx context.Context, scope arm.SubscriptionScope, pool string, revision int64) (clientv3.Cmp, error) {
	key := r.armPrefix(scope) + "placement-policy"
	policy, version, err := r.placementPolicy(ctx, key, true, clientv3.WithRev(revision))
	if err != nil {
		return clientv3.Cmp{}, err
	}
	if !slices.Contains(policy.Pools, pool) {
		return clientv3.Cmp{}, ErrPlacementPolicy
	}
	return clientv3.Compare(clientv3.ModRevision(key), "=", version), nil
}
