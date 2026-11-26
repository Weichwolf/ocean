package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedIdentityRecheck = 30 * time.Second
const hostedIdentityConfirmationAge = 2 * time.Minute

type hostedIdentityReceipt struct {
	DecidedAt   time.Time `json:"decidedAt"`
	ConfirmedAt time.Time `json:"confirmedAt"`
}

func (r *Region) hostedIdentityReceiptKey(tenant string) string {
	return r.root + "/hosted-identity-receipts/" + tenant
}

func (r *Region) readHostedIdentityReceipt(ctx context.Context, decision identity.HostedOffboarding) (time.Time, int64, error) {
	rows, err := r.client.Get(ctx, r.hostedIdentityReceiptKey(decision.TenantID))
	if err != nil || len(rows.Kvs) == 0 {
		return time.Time{}, 0, err
	}
	var receipt hostedIdentityReceipt
	if json.Unmarshal(rows.Kvs[0].Value, &receipt) != nil || !receipt.DecidedAt.Equal(decision.DecidedAt) ||
		(!receipt.ConfirmedAt.IsZero() && receipt.ConfirmedAt.Before(receipt.DecidedAt)) {
		return time.Time{}, 0, errors.New("invalid hosted identity suspension receipt")
	}
	return receipt.ConfirmedAt, rows.Kvs[0].ModRevision, nil
}

func (r *Region) HostedRealmSuspendedAt(ctx context.Context, decision identity.HostedOffboarding) (time.Time, error) {
	confirmed, _, err := r.readHostedIdentityReceipt(ctx, decision)
	if time.Since(confirmed) >= hostedIdentityConfirmationAge {
		return time.Time{}, err
	}
	return confirmed, err
}

func (r *Region) reconcileHostedIdentity(ctx context.Context, logger *slog.Logger, suspend func(context.Context, identity.HostedOffboarding) error) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	cursor := ""
	for ctx.Err() == nil {
		next, err := r.reconcileHostedIdentityPage(ctx, cursor, suspend)
		if err != nil && ctx.Err() == nil {
			logger.Warn("hosted identity suspension will retry", "error", err)
		}
		cursor = next
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Region) reconcileHostedIdentityPage(ctx context.Context, cursor string, suspend func(context.Context, identity.HostedOffboarding) error) (string, error) {
	prefix := r.offboardingMarker("")
	if cursor == "" {
		cursor = prefix
	}
	read, cancel := context.WithTimeout(ctx, 4*time.Second)
	rows, err := r.client.Get(read, cursor, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(16))
	cancel()
	if err != nil {
		return cursor, err
	}
	var failures error
	for _, row := range rows.Kvs {
		if ctx.Err() != nil {
			return cursor, ctx.Err()
		}
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		failures = errors.Join(failures, r.reconcileHostedRealm(call, row, suspend))
		cancel()
	}
	if rows.More {
		return string(rows.Kvs[len(rows.Kvs)-1].Key) + "\x00", failures
	}
	return "", failures
}

func (r *Region) reconcileHostedRealm(ctx context.Context, row *mvccpb.KeyValue, suspend func(context.Context, identity.HostedOffboarding) error) error {
	tenant := strings.TrimPrefix(string(row.Key), r.offboardingMarker(""))
	decision, err := decodeOffboarding(tenant, row.Value)
	if err != nil {
		return err
	}
	confirmed, revision, err := r.readHostedIdentityReceipt(ctx, *decision)
	if err != nil || time.Since(confirmed) < hostedIdentityRecheck {
		return err
	}
	approved, err := r.HostedOffboarding(ctx, tenant)
	if err != nil {
		return err
	}
	if approved == nil || approved.SubscriptionID != decision.SubscriptionID || approved.Actor != decision.Actor || !approved.DecidedAt.Equal(decision.DecidedAt) {
		return errors.New("hosted identity suspension differs from the independent ledger")
	}
	key := r.hostedIdentityReceiptKey(tenant)
	checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(string(row.Key)), "=", row.ModRevision),
		clientv3.Compare(clientv3.ModRevision(key), "=", revision)}
	if err := suspend(ctx, *decision); err != nil {
		if !confirmed.IsZero() {
			// Use a fresh bounded context when the provider call exhausted its
			// deadline so a failed recheck can invalidate a stale confirmation.
			clearCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer stop()
			_, clearErr := r.client.Txn(clearCtx).If(checks...).Then(putJSON(key, hostedIdentityReceipt{DecidedAt: decision.DecidedAt})).Commit()
			return errors.Join(err, clearErr)
		}
		return err
	}
	now := time.Now().UTC()
	writes := []clientv3.Op{putJSON(key, hostedIdentityReceipt{DecidedAt: decision.DecidedAt, ConfirmedAt: now})}
	if revision == 0 {
		scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: decision.SubscriptionID}
		writes = append(writes, r.auditOp(scope, arm.AuditEvent{Time: now, Actor: "identity-reconciler",
			Action: "Ocean.Hosted/offboarding/suspendIdentity", Target: "/ocean/tenants/" + tenant + "/offboarding", Outcome: arm.OperationSucceeded}))
	}
	_, err = r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
	return err
}
