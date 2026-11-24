package controlplane

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) tenantKeys(tenant string) (registration, subscription string) {
	prefix := r.root + "/tenants/" + tenant
	return prefix + "/registration", prefix + "/subscription"
}

func (r *Region) lookupSubscription(ctx context.Context, tenant string) (*identity.Subscription, error) {
	_, key := r.tenantKeys(tenant)
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

func (r *Region) ReserveTenant(ctx context.Context, reservation identity.TenantReservation) (identity.TenantReservation, error) {
	key, subscription := r.tenantKeys(reservation.TenantID)
	data, _ := json.Marshal(reservation)
	result, err := r.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(subscription), "=", 0)).
		Then(clientv3.OpPut(key, string(data))).
		Else(clientv3.OpGet(key)).Commit()
	if err != nil {
		return identity.TenantReservation{}, err
	}
	if result.Succeeded {
		return reservation, nil
	}
	values := result.Responses[0].GetResponseRange().GetKvs()
	if len(values) != 1 {
		return identity.TenantReservation{}, identity.ErrTenantConflict
	}
	var existing identity.TenantReservation
	if err := json.Unmarshal(values[0].Value, &existing); err != nil {
		return identity.TenantReservation{}, err
	}
	if !existing.Valid(reservation.TenantID) || existing.Fingerprint != reservation.Fingerprint {
		return identity.TenantReservation{}, identity.ErrTenantConflict
	}
	return existing, nil
}

func (r *Region) LookupTenant(ctx context.Context, tenant string) (*identity.TenantReservation, error) {
	key, _ := r.tenantKeys(tenant)
	result, err := r.client.Get(ctx, key)
	if err != nil || len(result.Kvs) == 0 {
		return nil, err
	}
	var record identity.TenantReservation
	if err := json.Unmarshal(result.Kvs[0].Value, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *Region) PublishSubscription(ctx context.Context, reservation identity.TenantReservation, sub identity.Subscription) (bool, error) {
	registration, key := r.tenantKeys(reservation.TenantID)
	lock, _ := json.Marshal(reservation)
	data, _ := json.Marshal(sub)
	result, err := r.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Value(registration), "=", string(lock)), clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, string(data))).Commit()
	if err != nil || result.Succeeded {
		return err == nil, err
	}
	existing, err := r.lookupSubscription(ctx, reservation.TenantID)
	if err != nil {
		return false, err
	}
	if existing == nil || !existing.Valid(reservation.TenantID) || existing.SubscriptionID != reservation.SubscriptionID {
		return false, identity.ErrTenantConflict
	}
	return false, nil
}
