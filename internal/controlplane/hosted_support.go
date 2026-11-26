package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type hostedSupportPolicy struct {
	ClientID    string                    `json:"clientId"`
	AuthContext string                    `json:"authenticationContext"`
	Pools       map[string][]netip.Prefix `json:"pools"`
}

func (p *hostedRegionPolicy) validateSupport() error {
	if p.Support == nil {
		return nil
	}
	if p.DeletionLedger == nil || len(p.Support.Pools) == 0 {
		return errors.New("hosted support requires the independent ledger and approved ingress pools")
	}
	var approved []netip.Prefix
	for pool, prefixes := range p.Support.Pools {
		if !p.allowsPool(pool) || len(prefixes) == 0 {
			return errors.New("hosted support must use an approved pool with registered ingress prefixes")
		}
		slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		for _, prefix := range prefixes {
			if !prefix.IsValid() || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				return errors.New("hosted support ingress prefixes must use canonical, bounded addresses")
			}
			for _, other := range approved {
				if prefix.Overlaps(other) {
					return errors.New("hosted support ingress prefixes must be disjoint")
				}
			}
			approved = append(approved, prefix)
		}
	}
	return nil
}

func (r *Region) bootstrapHostedSupport(ctx context.Context) error {
	if r.hosted == nil {
		return nil
	}
	var expected []byte
	if r.hosted.Support != nil {
		var err error
		expected, err = json.Marshal(r.hosted.Support)
		if err != nil {
			return err
		}
	}
	return r.bootstrapHostedApproval(ctx, r.root+"/support/policy", "support", expected)
}

func (r *Region) supportGrantKey(tenant, grant string) string {
	return r.deletionLedger.prefix + "support-grants/" + tenant + "/" + grant
}

func (r *Region) loadSupportGrant(ctx context.Context, tenant, id string) (identity.HostedSupportGrant, int64, clientv3.LeaseID, error) {
	var grant identity.HostedSupportGrant
	rows, err := r.deletionLedger.client.Get(ctx, r.supportGrantKey(tenant, id))
	if err != nil {
		return grant, 0, 0, err
	}
	if err := r.deletionLedger.verifyCluster(rows.Header.ClusterId); err != nil {
		return grant, 0, 0, err
	}
	if len(rows.Kvs) == 0 {
		return grant, 0, 0, identity.ErrSupportMissing
	}
	row := rows.Kvs[0]
	if json.Unmarshal(row.Value, &grant) != nil || grant.ID != id || grant.TenantID != tenant ||
		!validScope(arm.SubscriptionScope{TenantID: tenant, SubscriptionID: grant.SubscriptionID}) ||
		grant.ExpiresAt.IsZero() || grant.ResourceCreatedAt.IsZero() || grant.ApprovedAt.IsZero() || row.Lease == 0 {
		return grant, 0, 0, errors.New("invalid hosted support ledger record")
	}
	return grant, row.ModRevision, clientv3.LeaseID(row.Lease), nil
}

func (r *Region) ManageHostedSupport(ctx context.Context, principal identity.ARMPrincipal, grantID, method string,
	request *identity.HostedSupportRequest) (identity.HostedSupportGrant, error) {
	var empty identity.HostedSupportGrant
	scope := arm.SubscriptionScope{TenantID: principal.Subscription.TenantID, SubscriptionID: principal.Subscription.SubscriptionID}
	reserved, err := r.LookupTenant(ctx, scope.TenantID)
	if err != nil {
		return empty, err
	}
	if reserved == nil || !reserved.Valid(scope.TenantID) || reserved.SubscriptionID != scope.SubscriptionID ||
		reserved.Administrator != principal.Subject || !slices.Contains(principal.Subscription.Members, principal.Subject) {
		return empty, identity.ErrSupportDenied
	}
	grant, revision, lease, err := r.loadSupportGrant(ctx, scope.TenantID, grantID)
	if errors.Is(err, identity.ErrSupportMissing) && method == http.MethodPut && request != nil {
		grant, err = r.createSupportGrant(ctx, scope, principal.Subject, grantID, *request)
	}
	if err != nil {
		return empty, err
	}
	if grant.SubscriptionID != scope.SubscriptionID {
		return empty, identity.ErrSupportMissing
	}
	switch method {
	case http.MethodPut:
		if request == nil || grant.PrincipalID != request.PrincipalID || grant.OperatorPool != request.OperatorPool ||
			!strings.EqualFold(grant.ResourceID, request.ResourceID) || !grant.ExpiresAt.Equal(request.ExpiresAt) {
			return empty, identity.ErrSupportConflict
		}
		err = r.recordSupportDecision(ctx, scope, grant, "grant", grant.ApprovedBy, grant.ApprovedAt)
	case http.MethodDelete:
		if grant.RevokedAt.IsZero() {
			grant, err = r.revokeSupportGrant(ctx, grant, revision, lease, principal.Subject)
			if err != nil {
				return empty, err
			}
		}
		err = r.recordSupportDecision(ctx, scope, grant, "revoke", grant.RevokedBy, grant.RevokedAt)
	}
	return grant, err
}

func (r *Region) createSupportGrant(ctx context.Context, scope arm.SubscriptionScope, approver, id string,
	request identity.HostedSupportRequest) (identity.HostedSupportGrant, error) {
	var empty identity.HostedSupportGrant
	now := time.Now().UTC()
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(time.Hour)) || len(r.hosted.Support.Pools[request.OperatorPool]) == 0 {
		return empty, identity.ErrSupportInvalid
	}
	resource, _, _, err := r.supportResource(ctx, scope, request.ResourceID)
	if err != nil {
		return empty, err
	}
	if _, err := r.hostedPoolGuard(ctx, scope, request.OperatorPool, 0); err != nil {
		if errors.Is(err, ErrPlacementPolicy) {
			return empty, identity.ErrSupportDenied
		}
		return empty, err
	}
	request.ResourceID = resource.Address.ID(scope)
	request.ExpiresAt = request.ExpiresAt.UTC()
	grant := identity.HostedSupportGrant{HostedSupportRequest: request, ID: id, TenantID: scope.TenantID,
		SubscriptionID: scope.SubscriptionID, ApprovedBy: approver, ApprovedAt: now, ResourceCreatedAt: resource.CreatedAt}
	// Keep the decision available for retries and review for one day after
	// expiry. Authorization always uses the exact earlier deadline.
	ledger := r.deletionLedger
	lease, err := ledger.client.Grant(ctx, int64(time.Until(grant.ExpiresAt.Add(24*time.Hour))/time.Second)+1)
	if err != nil {
		return empty, err
	}
	if err := ledger.verifyCluster(lease.ResponseHeader.ClusterId); err != nil {
		return empty, err
	}
	key := r.supportGrantKey(scope.TenantID, id)
	result, err := ledger.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0),
		clientv3.Compare(clientv3.Version(ledger.prefix+"tenants/"+scope.TenantID), "=", 0)).
		Then(putSupportGrant(key, grant, lease.ID)).Commit()
	if err != nil {
		return empty, err
	}
	if result.Succeeded {
		return grant, nil
	}
	existing, _, _, err := r.loadSupportGrant(ctx, scope.TenantID, id)
	if errors.Is(err, identity.ErrSupportMissing) {
		return empty, identity.ErrSupportDenied
	}
	return existing, err
}

func putSupportGrant(key string, grant identity.HostedSupportGrant, lease clientv3.LeaseID) clientv3.Op {
	data, _ := json.Marshal(grant)
	return clientv3.OpPut(key, string(data), clientv3.WithLease(lease))
}

func (r *Region) revokeSupportGrant(ctx context.Context, grant identity.HostedSupportGrant, revision int64,
	lease clientv3.LeaseID, actor string) (identity.HostedSupportGrant, error) {
	key := r.supportGrantKey(grant.TenantID, grant.ID)
	grant.RevokedAt, grant.RevokedBy = time.Now().UTC(), actor
	result, err := r.deletionLedger.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision)).
		Then(putSupportGrant(key, grant, lease)).Commit()
	if err != nil || result.Succeeded {
		return grant, err
	}
	current, _, _, err := r.loadSupportGrant(ctx, grant.TenantID, grant.ID)
	if err == nil && current.RevokedAt.IsZero() {
		return current, errors.New("hosted support decision changed during revocation")
	}
	return current, err
}

func (r *Region) recordSupportDecision(ctx context.Context, scope arm.SubscriptionScope, grant identity.HostedSupportGrant,
	action, actor string, at time.Time) error {
	key := r.armPrefix(scope) + "audit/s-" + grant.ID + "-" + strconv.FormatInt(grant.ApprovedAt.UnixNano(), 36) + "-" + action
	_, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(putJSON(key, supportAudit(grant, action, actor, arm.OperationSucceeded, at))).Commit()
	return err
}

func supportAudit(grant identity.HostedSupportGrant, action, actor, outcome string, at time.Time) arm.AuditEvent {
	return arm.AuditEvent{Time: at, Actor: actor, Target: grant.ResourceID, CorrelationID: grant.ID, Outcome: outcome,
		Action: "Ocean.Hosted/support/" + action}
}

func (r *Region) ReadHostedSupport(ctx context.Context, tenant, id, actor string, peer netip.Addr) (identity.HostedSupportDiagnostic, error) {
	var empty identity.HostedSupportDiagnostic
	grant, revision, _, err := r.loadSupportGrant(ctx, tenant, id)
	if errors.Is(err, identity.ErrSupportMissing) {
		return empty, identity.ErrSupportDenied
	}
	if err != nil {
		return empty, err
	}
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: grant.SubscriptionID}
	if grant.PrincipalID != actor {
		return empty, identity.ErrSupportDenied
	}
	deny := func() (identity.HostedSupportDiagnostic, error) {
		if err := r.RecordAudit(ctx, scope, supportAudit(grant, "read", actor, "Denied", time.Now().UTC())); err != nil {
			return empty, err
		}
		return empty, identity.ErrSupportDenied
	}
	if !grant.RevokedAt.IsZero() {
		if err := r.recordSupportDecision(ctx, scope, grant, "revoke", grant.RevokedBy, grant.RevokedAt); err != nil {
			return empty, err
		}
		return deny()
	}
	if !grant.ExpiresAt.After(time.Now()) ||
		!slices.ContainsFunc(r.hosted.Support.Pools[grant.OperatorPool], func(prefix netip.Prefix) bool { return prefix.Contains(peer) }) {
		return deny()
	}
	if _, err := r.readPlacementSubscription(ctx, scope); err != nil {
		if errors.Is(err, identity.ErrPlacementTenantGone) {
			return deny()
		}
		return empty, err
	}
	resource, key, rows, err := r.supportResource(ctx, scope, grant.ResourceID)
	if errors.Is(err, identity.ErrSupportMissing) || err == nil && !resource.CreatedAt.Equal(grant.ResourceCreatedAt) {
		return deny()
	}
	if err != nil {
		return empty, err
	}
	pool, err := r.hostedPoolGuard(ctx, scope, grant.OperatorPool, rows.Header.Revision)
	if errors.Is(err, ErrPlacementPolicy) {
		return deny()
	}
	if err != nil {
		return empty, err
	}
	_, latest, _, err := r.loadSupportGrant(ctx, tenant, id)
	if errors.Is(err, identity.ErrSupportMissing) || err == nil && (latest != revision || !grant.ExpiresAt.After(time.Now())) {
		return deny()
	}
	if err != nil {
		return empty, err
	}
	if err := r.recordSupportDecision(ctx, scope, grant, "grant", grant.ApprovedBy, grant.ApprovedAt); err != nil {
		return empty, err
	}
	event := supportAudit(grant, "read", actor, arm.OperationSucceeded, time.Now().UTC())
	committed, err := r.client.Txn(ctx).If(pool, clientv3.Compare(clientv3.ModRevision(key), "=", rows.Kvs[0].ModRevision)).
		Then(r.auditOp(scope, event)).Commit()
	if err != nil {
		return empty, err
	}
	if !committed.Succeeded {
		return deny()
	}
	return identity.HostedSupportDiagnostic{GrantID: id, ResourceID: grant.ResourceID, Location: resource.Location,
		APIVersion: resource.APIVersion, ProvisioningState: resource.ProvisioningState, ChangedAt: resource.ChangedAt}, nil
}

func (r *Region) supportResource(ctx context.Context, scope arm.SubscriptionScope, resourceID string) (arm.InventoryResource, string, *clientv3.GetResponse, error) {
	var empty arm.InventoryResource
	parts := strings.SplitN(resourceID, "/", 7)
	if len(parts) != 7 || parts[0] != "" || !strings.EqualFold(parts[1], "subscriptions") || parts[2] != scope.SubscriptionID ||
		!strings.EqualFold(parts[3], "resourceGroups") || !strings.EqualFold(parts[5], "providers") {
		return empty, "", nil, identity.ErrSupportInvalid
	}
	address := arm.ResourceAddress{Group: parts[4], Path: parts[6]}
	if !address.Valid() {
		return empty, "", nil, identity.ErrSupportInvalid
	}
	key := r.inventoryPrefix(scope) + address.Key()
	rows, err := r.client.Get(ctx, key)
	if err != nil {
		return empty, "", nil, err
	}
	if len(rows.Kvs) != 1 {
		return empty, "", nil, identity.ErrSupportMissing
	}
	resource, err := decodeInventoryResource(rows.Kvs[0].Value, address.Key())
	return resource, key, rows, err
}
