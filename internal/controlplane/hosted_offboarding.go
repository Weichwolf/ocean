package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type hostedLedgerPolicy struct {
	OperatorPool string   `json:"operatorPool"`
	ClusterID    string   `json:"clusterId"`
	Endpoints    []string `json:"endpoints"`
}

type hostedLedger struct {
	client    *clientv3.Client
	clusterID uint64
	prefix    string
}

func (p *hostedRegionPolicy) validateDeletionLedger() error {
	ledger := p.DeletionLedger
	if ledger == nil {
		return nil
	}
	id, err := strconv.ParseUint(ledger.ClusterID, 16, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 16) != ledger.ClusterID || !p.allowsPool(ledger.OperatorPool) || len(ledger.Endpoints) == 0 {
		return errors.New("the deletion ledger requires its pinned cluster ID, approved operator pool and HTTPS origins")
	}
	slices.Sort(ledger.Endpoints)
	for i, endpoint := range ledger.Endpoints {
		if !validEtcdOrigin(endpoint) || i > 0 && ledger.Endpoints[i-1] == endpoint {
			return errors.New("deletion ledger endpoints must be distinct HTTPS origins")
		}
	}
	return nil
}

func (cfg regionConfig) openDeletionLedger(root string) (*hostedLedger, error) {
	var approved *hostedLedgerPolicy
	if cfg.HostedWorkplace != nil {
		approved = cfg.HostedWorkplace.DeletionLedger
	}
	if approved == nil && cfg.DeletionLedgerEtcd == nil {
		return nil, nil
	}
	if approved == nil || cfg.DeletionLedgerEtcd == nil ||
		!slices.Equal(approved.Endpoints, slices.Sorted(slices.Values(cfg.DeletionLedgerEtcd.Endpoints))) {
		return nil, errors.New("deletion ledger credentials and origins must match the hosted regional policy")
	}
	for _, endpoint := range approved.Endpoints {
		if slices.Contains(cfg.Etcd.Endpoints, endpoint) || cfg.Telemetry != nil && slices.Contains(cfg.Telemetry.Etcd.Endpoints, endpoint) {
			return nil, errors.New("the deletion ledger must use independent etcd endpoints")
		}
	}
	connection, err := cfg.DeletionLedgerEtcd.clientConfig()
	if err != nil {
		return nil, err
	}
	client, err := clientv3.New(connection)
	if err != nil {
		return nil, err
	}
	id, _ := strconv.ParseUint(approved.ClusterID, 16, 64)
	return &hostedLedger{client: client, clusterID: id, prefix: root + "/deletion-ledger/"}, nil
}

func (l *hostedLedger) verifyCluster(actual uint64) error {
	if actual != l.clusterID {
		return errors.New("the deletion ledger does not match the pinned cluster identity")
	}
	return nil
}

func (l *hostedLedger) revision(ctx context.Context, regionalClusterID uint64) (int64, error) {
	if regionalClusterID == l.clusterID {
		return 0, errors.New("the deletion ledger must be independent of regional metadata")
	}
	row, err := l.client.Get(ctx, l.prefix, clientv3.WithCountOnly())
	if err != nil {
		return 0, err
	}
	return row.Header.Revision, l.verifyCluster(row.Header.ClusterId)
}

func (l *hostedLedger) check(ctx context.Context, regionalClusterID uint64) error {
	_, err := l.revision(ctx, regionalClusterID)
	return err
}

func decodeOffboarding(tenant string, raw []byte) (*identity.HostedOffboarding, error) {
	var decision identity.HostedOffboarding
	if json.Unmarshal(raw, &decision) != nil || !decision.Valid(tenant) {
		return nil, errors.New("invalid hosted offboarding decision")
	}
	return &decision, nil
}

func (r *Region) HostedOffboarding(ctx context.Context, tenant string) (*identity.HostedOffboarding, error) {
	if r.deletionLedger == nil {
		return nil, nil
	}
	l := r.deletionLedger
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := l.client.Get(probe, l.prefix+"tenants/"+tenant)
	if err != nil {
		return nil, err
	}
	if err := l.verifyCluster(rows.Header.ClusterId); err != nil {
		return nil, err
	}
	if len(rows.Kvs) == 0 {
		return nil, nil
	}
	return decodeOffboarding(tenant, rows.Kvs[0].Value)
}

func (r *Region) requireActiveHostedTenant(ctx context.Context, tenant string) error {
	decision, err := r.HostedOffboarding(ctx, tenant)
	if err == nil && decision != nil {
		return identity.ErrTenantSuspended
	}
	return err
}

func (r *Region) SuspendHostedTenant(ctx context.Context, tenant, subscription, actor string) (*identity.HostedOffboarding, error) {
	prior, err := r.HostedOffboarding(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if prior.SubscriptionID != subscription {
			return nil, identity.ErrPlacementTenantGone
		}
		return prior, r.applyHostedOffboarding(ctx, *prior)
	}
	decision := identity.HostedOffboarding{TenantID: tenant, SubscriptionID: subscription, Actor: actor,
		State: "Suspended", DecidedAt: time.Now().UTC()}
	if r.deletionLedger == nil || !decision.Valid(tenant) {
		return nil, identity.ErrPlacementTenantGone
	}
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: subscription}
	if _, err := r.readPlacementSubscriptionRecord(ctx, scope); err != nil {
		return nil, err
	}
	l := r.deletionLedger
	key := l.prefix + "tenants/" + tenant
	result, err := l.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(putJSON(key, decision)).Else(clientv3.OpGet(key)).Commit()
	if err != nil {
		return nil, err
	}
	if err := l.verifyCluster(result.Header.ClusterId); err != nil {
		return nil, err
	}
	if !result.Succeeded {
		rows := result.Responses[0].GetResponseRange().Kvs
		if len(rows) != 1 {
			return nil, errors.New("persisted offboarding decision is unavailable")
		}
		previous, err := decodeOffboarding(tenant, rows[0].Value)
		if err != nil {
			return nil, err
		}
		if previous.SubscriptionID != subscription {
			return nil, identity.ErrPlacementTenantGone
		}
		decision = *previous
	}
	return &decision, r.applyHostedOffboarding(ctx, decision)
}

func (r *Region) offboardingMarker(tenant string) string { return r.root + "/offboarding/" + tenant }

func (r *Region) applyHostedOffboarding(ctx context.Context, decision identity.HostedOffboarding) error {
	key := r.offboardingMarker(decision.TenantID)
	scope := arm.SubscriptionScope{TenantID: decision.TenantID, SubscriptionID: decision.SubscriptionID}
	audit := r.auditOp(scope, arm.AuditEvent{Time: decision.DecidedAt, Actor: decision.Actor, Action: "Ocean.Hosted/offboarding/suspend",
		Target: "/subscriptions/" + scope.SubscriptionID + "/providers/Ocean.Hosted/offboarding/default", Outcome: decision.State})
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(putJSON(key, decision), r.advanceBackupPolicy(), audit).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	rows := result.Responses[0].GetResponseRange().Kvs
	if len(rows) != 1 {
		return errors.New("regional offboarding marker is missing")
	}
	marker, err := decodeOffboarding(decision.TenantID, rows[0].Value)
	if err != nil || marker.SubscriptionID != decision.SubscriptionID || marker.Actor != decision.Actor || !marker.DecidedAt.Equal(decision.DecidedAt) {
		return errors.New("regional offboarding marker differs from the independent deletion ledger")
	}
	return nil
}

func (r *Region) replayHostedOffboarding(ctx context.Context, regionalClusterID uint64) error {
	l := r.deletionLedger
	revision, err := l.revision(ctx, regionalClusterID)
	if err != nil {
		return err
	}
	prefix := l.prefix + "tenants/"
	for cursor := prefix; ; {
		rows, err := l.client.Get(ctx, cursor, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(64), clientv3.WithRev(revision))
		if err != nil {
			return err
		}
		if err := l.verifyCluster(rows.Header.ClusterId); err != nil {
			return err
		}
		for _, row := range rows.Kvs {
			decision, err := decodeOffboarding(strings.TrimPrefix(string(row.Key), prefix), row.Value)
			if err != nil {
				return err
			}
			if err := r.applyHostedOffboarding(ctx, *decision); err != nil {
				return err
			}
		}
		if !rows.More {
			return nil
		}
		cursor = string(rows.Kvs[len(rows.Kvs)-1].Key) + "\x00"
	}
}

func (r *Region) reconcileHostedOffboarding(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var appliedRevision int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			call, cancel := context.WithTimeout(ctx, 4*time.Second)
			if err := r.syncHostedOffboarding(call, &appliedRevision); err != nil && ctx.Err() == nil {
				logger.Warn("Hosted offboarding replay will retry", "error", err)
			}
			cancel()
		}
	}
}

func (r *Region) syncHostedOffboarding(ctx context.Context, applied *int64) error {
	row, err := r.client.Get(ctx, r.keys[0], clientv3.WithCountOnly())
	if err != nil {
		return err
	}
	revision, err := r.deletionLedger.revision(ctx, row.Header.ClusterId)
	if err != nil || revision == *applied {
		return err
	}
	if err := r.replayHostedOffboarding(ctx, row.Header.ClusterId); err != nil {
		return err
	}
	*applied = revision
	return nil
}
