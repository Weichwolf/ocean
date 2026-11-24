package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) armPrefix(scope arm.SubscriptionScope) string {
	return r.root + "/tenants/" + scope.TenantID + "/arm/" + scope.SubscriptionID + "/"
}

func (r *Region) assignmentPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "role-assignments/" + strings.ToLower(group) + "/"
}

func (r *Region) grantPrefix(scope arm.SubscriptionScope) string {
	return r.armPrefix(scope) + "group-access/"
}

func (r *Region) groupGrantPrefix(scope arm.SubscriptionScope, group string) string {
	return r.grantPrefix(scope) + strings.ToLower(group) + "/"
}

func (r *Region) GroupGrant(ctx context.Context, scope arm.SubscriptionScope, group, subject string) (bool, error) {
	result, err := r.client.Get(ctx, r.groupGrantPrefix(scope, group)+subject, clientv3.WithCountOnly())
	return err == nil && result.Count == 1, err
}

func (r *Region) SubscriptionGrant(ctx context.Context, scope arm.SubscriptionScope, subject string) (bool, error) {
	names, _, err := r.grantedGroupNames(ctx, scope, subject, "", 1)
	return len(names) != 0, err
}

func (r *Region) GetGrantedGroup(ctx context.Context, scope arm.SubscriptionScope, group, subject string) (*arm.Group, error) {
	grant := r.groupGrantPrefix(scope, group) + subject
	key := r.groupPrefix(scope) + strings.ToLower(group)
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(grant), ">", 0)).Then(clientv3.OpGet(key)).Commit()
	if err != nil || !result.Succeeded {
		return nil, err
	}
	groups := result.Responses[0].GetResponseRange().Kvs
	if len(groups) != 1 {
		return nil, errors.New("role grant has no resource group")
	}
	record, err := decodeGroup(groups[0].Value, strings.ToLower(group))
	return &record, err
}

func (r *Region) ListGrantedGroups(ctx context.Context, scope arm.SubscriptionScope, subject, after string, limit int) ([]arm.Group, error) {
	names, revision, err := r.grantedGroupNames(ctx, scope, subject, after, limit)
	if err != nil {
		return nil, err
	}
	groups := make([]arm.Group, 0, len(names))
	for _, name := range names {
		result, err := r.client.Get(ctx, r.groupPrefix(scope)+name, clientv3.WithRev(revision))
		if err != nil {
			return nil, err
		}
		if len(result.Kvs) != 1 {
			return nil, errors.New("role grant has no resource group")
		}
		group, err := decodeGroup(result.Kvs[0].Value, name)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (r *Region) grantedGroupNames(ctx context.Context, scope arm.SubscriptionScope, subject, after string, limit int) ([]string, int64, error) {
	prefix := r.grantPrefix(scope)
	end := clientv3.GetPrefixRangeEnd(prefix)
	start := prefix
	if after != "" {
		start = clientv3.GetPrefixRangeEnd(prefix + after + "/")
	}
	names := make([]string, 0, limit)
	var revision int64
	for {
		result, err := r.client.Get(ctx, start, clientv3.WithRange(end), clientv3.WithKeysOnly(), clientv3.WithLimit(128), clientv3.WithRev(revision))
		if err != nil {
			return nil, 0, err
		}
		if revision == 0 {
			revision = result.Header.Revision
		}
		for _, item := range result.Kvs {
			group, principal, ok := strings.Cut(strings.TrimPrefix(string(item.Key), prefix), "/")
			if ok && principal == subject {
				names = append(names, group)
				if len(names) == limit {
					return names, revision, nil
				}
			}
		}
		if !result.More {
			return names, revision, nil
		}
		start = string(result.Kvs[len(result.Kvs)-1].Key) + "\x00"
	}
}

func (r *Region) hasSubscriptionGrant(ctx context.Context, subscription identity.Subscription, subject string) (bool, error) {
	scope := arm.SubscriptionScope{TenantID: subscription.TenantID, SubscriptionID: subscription.SubscriptionID}
	return r.SubscriptionGrant(ctx, scope, subject)
}

func (r *Region) GetAssignment(ctx context.Context, scope arm.SubscriptionScope, reader, group, id string) (*arm.RoleAssignment, error) {
	key := r.assignmentPrefix(scope, group) + id
	result, err := r.readAssignmentKeys(ctx, scope, reader, group, clientv3.OpGet(key))
	if err != nil || len(result.Kvs) == 0 {
		return nil, err
	}
	return decodeAssignment(result.Kvs[0].Value, group, id)
}

func (r *Region) ListAssignments(ctx context.Context, scope arm.SubscriptionScope, reader, group, after string, limit int) ([]arm.RoleAssignment, error) {
	prefix := r.assignmentPrefix(scope, group)
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	list := clientv3.OpGet(start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithLimit(int64(limit)))
	result, err := r.readAssignmentKeys(ctx, scope, reader, group, list)
	if err != nil {
		return nil, err
	}
	assignments := make([]arm.RoleAssignment, 0, len(result.Kvs))
	for _, item := range result.Kvs {
		assignment, err := decodeAssignment(item.Value, group, strings.TrimPrefix(string(item.Key), prefix))
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, *assignment)
	}
	return assignments, nil
}

func (r *Region) readAssignmentKeys(ctx context.Context, scope arm.SubscriptionScope, reader, group string, request clientv3.Op) (*clientv3.GetResponse, error) {
	if reader == "" {
		result, err := r.client.Do(ctx, request)
		if err != nil {
			return nil, err
		}
		return result.Get(), nil
	}
	key := r.groupGrantPrefix(scope, group) + reader
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), ">", 0)).Then(request).Commit()
	if err != nil {
		return nil, err
	}
	if !result.Succeeded {
		return nil, arm.ErrRoleDenied
	}
	return (*clientv3.GetResponse)(result.Responses[0].GetResponseRange()), nil
}

func (r *Region) PutAssignment(ctx context.Context, scope arm.SubscriptionScope, assignment arm.RoleAssignment) (arm.RoleAssignment, bool, error) {
	groupKey := r.groupPrefix(scope) + strings.ToLower(assignment.Group)
	assignmentKey := r.assignmentPrefix(scope, assignment.Group) + assignment.ID
	grantKey := r.groupGrantPrefix(scope, assignment.Group) + assignment.PrincipalID
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(assignmentKey), clientv3.OpGet(grantKey)).Commit()
		if err != nil {
			return arm.RoleAssignment{}, false, err
		}
		groups := snapshot.Responses[0].GetResponseRange().Kvs
		if len(groups) == 0 {
			return arm.RoleAssignment{}, false, arm.ErrGroupMissing
		}
		if existing := snapshot.Responses[1].GetResponseRange().Kvs; len(existing) != 0 {
			current, err := decodeAssignment(existing[0].Value, assignment.Group, assignment.ID)
			if err != nil {
				return arm.RoleAssignment{}, false, err
			}
			if current.PrincipalID != assignment.PrincipalID || current.PrincipalType != assignment.PrincipalType ||
				current.RoleID != assignment.RoleID || current.Description != assignment.Description {
				return arm.RoleAssignment{}, false, arm.ErrAssignmentChanged
			}
			return *current, false, nil
		}
		if len(snapshot.Responses[2].GetResponseRange().Kvs) != 0 {
			return arm.RoleAssignment{}, false, arm.ErrAssignmentExists
		}
		group, err := decodeGroup(groups[0].Value, strings.ToLower(assignment.Group))
		if err != nil {
			return arm.RoleAssignment{}, false, err
		}
		assignment.Group = group.Name
		data, _ := json.Marshal(assignment)
		event := arm.AuditEvent{Time: assignment.CreatedAt, Actor: assignment.CreatedBy, Action: "Microsoft.Authorization/roleAssignments/write",
			Target: assignment.ResourceID(scope), Outcome: "Succeeded"}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(groupKey), "=", groups[0].CreateRevision),
			clientv3.Compare(clientv3.Version(assignmentKey), "=", 0), clientv3.Compare(clientv3.Version(grantKey), "=", 0)).
			Then(clientv3.OpPut(assignmentKey, string(data)), clientv3.OpPut(grantKey, assignment.ID), r.auditOp(scope, event)).Commit()
		if err != nil || result.Succeeded {
			return assignment, err == nil, err
		}
	}
	return arm.RoleAssignment{}, false, errors.New("role assignment changed concurrently")
}

func (r *Region) DeleteAssignment(ctx context.Context, scope arm.SubscriptionScope, group, id, actor string) (*arm.RoleAssignment, error) {
	key := r.assignmentPrefix(scope, group) + id
	for range 8 {
		current, err := r.client.Get(ctx, key)
		if err != nil || len(current.Kvs) == 0 {
			return nil, err
		}
		item := current.Kvs[0]
		assignment, err := decodeAssignment(item.Value, group, id)
		if err != nil {
			return nil, err
		}
		grant := r.groupGrantPrefix(scope, group) + assignment.PrincipalID
		event := arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: "Microsoft.Authorization/roleAssignments/delete",
			Target: assignment.ResourceID(scope), Outcome: "Succeeded"}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision)).
			Then(clientv3.OpDelete(key), clientv3.OpDelete(grant), r.auditOp(scope, event)).Commit()
		if err != nil || result.Succeeded {
			return assignment, err
		}
	}
	return nil, errors.New("role assignment changed concurrently")
}

func (r *Region) RecordAudit(ctx context.Context, scope arm.SubscriptionScope, event arm.AuditEvent) error {
	_, err := r.client.Do(ctx, r.auditOp(scope, event))
	return err
}

func (r *Region) auditOp(scope arm.SubscriptionScope, event arm.AuditEvent) clientv3.Op {
	data, _ := json.Marshal(event)
	return clientv3.OpPut(r.armPrefix(scope)+"audit/"+rand.Text(), string(data))
}

func decodeAssignment(data []byte, group, id string) (*arm.RoleAssignment, error) {
	var assignment arm.RoleAssignment
	if err := json.Unmarshal(data, &assignment); err != nil {
		return nil, err
	}
	if assignment.ID != id || !strings.EqualFold(assignment.Group, group) || assignment.RoleID != arm.ReaderRoleID || assignment.PrincipalID == "" {
		return nil, errors.New("invalid role assignment record")
	}
	return &assignment, nil
}
