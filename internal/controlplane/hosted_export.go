package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedExportPageSize = 64

type hostedExportSection struct {
	kind   string
	prefix string
}

func (r *Region) ReadHostedExport(ctx context.Context, principal identity.ARMPrincipal, cursor identity.HostedExportCursor) (identity.HostedExportPage, error) {
	var empty identity.HostedExportPage
	scope := arm.SubscriptionScope{TenantID: principal.Subscription.TenantID, SubscriptionID: principal.Subscription.SubscriptionID}
	if r.deletionLedger == nil || !validScope(scope) {
		return empty, identity.ErrExportDenied
	}
	if err := r.requireActiveHostedTenant(ctx, scope.TenantID); err != nil {
		return empty, err
	}
	registrationKey, subscriptionKey := r.tenantKeys(scope.TenantID)
	live, err := r.client.Txn(ctx).Then(clientv3.OpGet(registrationKey), clientv3.OpGet(subscriptionKey)).Commit()
	if err != nil {
		return empty, err
	}
	registrations, subscriptions := live.Responses[0].GetResponseRange().Kvs, live.Responses[1].GetResponseRange().Kvs
	var registration identity.TenantReservation
	var subscription identity.Subscription
	if len(registrations) != 1 || len(subscriptions) != 1 || json.Unmarshal(registrations[0].Value, &registration) != nil ||
		json.Unmarshal(subscriptions[0].Value, &subscription) != nil || !registration.Valid(scope.TenantID) || !subscription.Valid(scope.TenantID) ||
		registration.SubscriptionID != scope.SubscriptionID || subscription.SubscriptionID != scope.SubscriptionID ||
		registration.Administrator != principal.Subject || !slices.Contains(subscription.Members, principal.Subject) {
		return empty, identity.ErrExportDenied
	}
	page := identity.HostedExportPage{Records: make([]identity.HostedExportRecord, 0, hostedExportPageSize)}
	if cursor.Revision == 0 {
		cursor.ClusterID = live.Header.ClusterId
		cursor.Revision, cursor.CapturedAt = live.Header.Revision, time.Now().UTC()
		page.Records, err = r.hostedExportMetadata(ctx, scope, registration, subscription, cursor.Revision)
		if err != nil {
			if errors.Is(err, rpctypes.ErrCompacted) {
				return empty, identity.ErrExportExpired
			}
			return empty, err
		}
	} else if cursor.ClusterID != live.Header.ClusterId {
		return empty, identity.ErrExportExpired
	}
	page.CapturedAt = cursor.CapturedAt
	if err := r.fillHostedExportPage(ctx, scope, &cursor, &page); err != nil {
		if errors.Is(err, rpctypes.ErrCompacted) || errors.Is(err, rpctypes.ErrFutureRev) {
			return empty, identity.ErrExportExpired
		}
		return empty, err
	}
	if err := r.requireActiveHostedTenant(ctx, scope.TenantID); err != nil {
		return empty, err
	}
	audit := r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: principal.Subject, Action: "Ocean.Hosted/dataExports/read",
		Target: "/subscriptions/" + scope.SubscriptionID + "/providers/Ocean.Hosted/dataExports/default", Outcome: arm.OperationSucceeded})
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(registrationKey), "=", registrations[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(subscriptionKey), "=", subscriptions[0].ModRevision)).Then(audit).Commit()
	if err != nil {
		return empty, err
	}
	if !result.Succeeded {
		return empty, identity.ErrExportDenied
	}
	return page, nil
}

func (r *Region) hostedExportMetadata(ctx context.Context, scope arm.SubscriptionScope, tenant identity.TenantReservation,
	subscription identity.Subscription, revision int64) ([]identity.HostedExportRecord, error) {
	policy, _, err := r.placementPolicy(ctx, r.armPrefix(scope)+"placement-policy", true, clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	usage, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage", clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	rows, err := r.client.Get(ctx, r.managedDirectoryKey(scope.TenantID), clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	metadata := []identity.HostedExportRecord{{Kind: "subscription", Data: subscription},
		{Kind: "placement", Data: map[string]any{"allowedPools": policy.Pools, "quota": policy.Quota, "reserved": usage.used}}}
	if len(rows.Kvs) == 1 {
		var directory identity.ManagedDirectory
		if json.Unmarshal(rows.Kvs[0].Value, &directory) != nil || !directory.Valid(tenant) {
			return nil, errors.New("invalid managed directory in hosted export")
		}
		metadata = append(metadata, identity.HostedExportRecord{Kind: "managedDirectory", Data: map[string]any{"directoryId": directory.ID,
			"dnsName": directory.Spec.DNSName, "netbiosName": directory.Spec.NetBIOSName, "domainSid": directory.DomainSID,
			"requestedAt": directory.RequestedAt, "provisionedAt": directory.ProvisionedAt}})
	}
	return metadata, nil
}

func (r *Region) fillHostedExportPage(ctx context.Context, scope arm.SubscriptionScope, cursor *identity.HostedExportCursor,
	page *identity.HostedExportPage) error {
	base := r.armPrefix(scope)
	sections := []hostedExportSection{{"resourceGroup", r.groupPrefix(scope)}, {"resource", r.inventoryPrefix(scope)},
		{"roleAssignment", base + "role-assignments/"}, {"application", r.appPrefix(scope.TenantID) + "apps/"}, {"activity", base + "audit/"}}
	if cursor.Section < 0 || cursor.Section >= len(sections) || len(cursor.After) > 4096 {
		return identity.ErrExportDenied
	}
	var expiry time.Time
	if r.auditRetention > 0 {
		expiry = time.Now().Add(-r.auditRetention)
	}
	for capacity := 256; len(page.Records) < hostedExportPageSize && cursor.Section < len(sections) && capacity > 0; {
		section := sections[cursor.Section]
		start := section.prefix
		if cursor.After != "" {
			start += cursor.After + "\x00"
		}
		limit := min(32, hostedExportPageSize-len(page.Records), capacity)
		rows, err := r.client.Get(ctx, start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(section.prefix)),
			clientv3.WithLimit(int64(limit)), clientv3.WithRev(cursor.Revision))
		if err != nil {
			return err
		}
		for _, row := range rows.Kvs {
			key := strings.TrimPrefix(string(row.Key), section.prefix)
			data, err := hostedExportRecord(scope, section.kind, key, row.Value, cursor.CapturedAt, expiry)
			if err != nil {
				return err
			}
			cursor.After = key
			if data != nil {
				page.Records = append(page.Records, identity.HostedExportRecord{Kind: section.kind, Data: data})
			}
		}
		capacity -= len(rows.Kvs)
		if !rows.More {
			cursor.Section++
			cursor.After = ""
		}
	}
	if cursor.Section < len(sections) {
		page.Next = cursor
	}
	return nil
}

func hostedExportRecord(scope arm.SubscriptionScope, kind, key string, value []byte, capturedAt, expiry time.Time) (any, error) {
	switch kind {
	case "resourceGroup":
		group, err := decodeGroup(value, key)
		return map[string]any{"name": group.Name, "location": group.Location}, err
	case "resource":
		resource, err := decodeInventoryResource(value, key)
		if err != nil {
			return nil, err
		}
		references := make([]string, 0, len(resource.References))
		for _, address := range resource.References {
			references = append(references, address.ID(scope))
		}
		return map[string]any{"id": resource.Address.ID(scope), "location": resource.Location, "apiVersion": resource.APIVersion,
			"references": references, "provisioningState": resource.ProvisioningState, "createdAt": resource.CreatedAt, "changedAt": resource.ChangedAt}, nil
	case "roleAssignment":
		group, id, found := strings.Cut(key, "/")
		if !found {
			return nil, errors.New("invalid hosted export role assignment key")
		}
		assignment, err := decodeAssignment(value, group, id)
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": assignment.ResourceID(scope), "principalId": assignment.PrincipalID,
			"roleId": assignment.RoleID, "createdOn": assignment.CreatedAt}, nil
	case "application":
		var app identity.Application
		if json.Unmarshal(value, &app) != nil || !app.Valid(scope.TenantID) || app.ID != key {
			return nil, errors.New("invalid hosted export application")
		}
		return map[string]string{"id": app.ID, "appId": app.ClientID, "displayName": app.DisplayName, "principalId": app.PrincipalID}, nil
	case "activity":
		var event arm.AuditEvent
		if json.Unmarshal(value, &event) != nil || event.Time.IsZero() || event.Action == "" {
			return nil, errors.New("invalid hosted export activity entry")
		}
		if event.Time.After(capturedAt) || !expiry.IsZero() && !event.Time.After(expiry) {
			return nil, nil
		}
		return map[string]any{"id": key, "time": event.Time, "actor": event.Actor, "action": event.Action,
			"target": event.Target, "outcome": event.Outcome}, nil
	default:
		return nil, fmt.Errorf("invalid hosted export section %q", kind)
	}
}
