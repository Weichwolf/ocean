package controlplane

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Weichwolf/ocean/internal/identity"
)

func (r *Region) lookupSubscription(ctx context.Context, tenant string) (*identity.Subscription, error) {
	key := r.root + "/tenants/" + tenant + "/subscription"
	result, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read tenant subscription: %w", err)
	}
	if len(result.Kvs) == 0 {
		return nil, nil
	}
	var subscription identity.Subscription
	if err := json.Unmarshal(result.Kvs[0].Value, &subscription); err != nil {
		return nil, fmt.Errorf("decode tenant subscription: %w", err)
	}
	return &subscription, nil
}
