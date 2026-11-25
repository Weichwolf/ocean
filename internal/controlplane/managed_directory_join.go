package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const directoryJoinAudit = "Ocean.Identity/directories/joinAuthorizations/"

type pendingDirectoryJoin struct {
	ID             string `json:"requestId"`
	Attempt        string `json:"attempt"`
	Generation     string `json:"generation"`
	Command        string `json:"command"`
	EncryptedInput []byte `json:"encryptedInput"`
}

func (p pendingDirectoryJoin) label(key string) []byte {
	return []byte(key + "/" + p.Generation + "/" + p.Attempt + "/" + p.ID + "/" + p.Command)
}

func (r *Region) directoryJoinKey(directory identity.ManagedDirectory, id string) string {
	return r.root + "/managed-directory-joins/" + directory.TenantID + "/" + directory.ID + "/" + id
}

func (r *Region) LookupDirectoryJoin(ctx context.Context, tenant identity.TenantReservation, id string) (*identity.DirectoryJoinAuthorization, error) {
	if !enrollment.ValidDirectoryJoinID(id) {
		return nil, identity.ErrDirectoryJoinNotFound
	}
	directory, _, revision, err := r.managedDirectorySnapshot(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if directory == nil {
		return nil, identity.ErrDirectoryJoinNotFound
	}
	view, _, err := r.readDirectoryJoin(ctx, r.directoryJoinKey(*directory, id), id, revision)
	if view != nil && view.State != identity.DirectoryJoinClosed && view.State != identity.DirectoryJoinRejected &&
		time.Now().Unix() >= view.ExpiresAt {
		view.State = identity.DirectoryJoinExpired
	}
	return view, err
}

func (r *Region) readDirectoryJoin(ctx context.Context, key, id string, revision int64) (*identity.DirectoryJoinAuthorization, int64, error) {
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil || len(rows.Kvs) == 0 {
		return nil, 0, err
	}
	var view identity.DirectoryJoinAuthorization
	if json.Unmarshal(rows.Kvs[0].Value, &view) != nil || view.ID != id ||
		!(enrollment.DirectoryJoinInput{ID: id, Machine: view.Machine, ExpiresAt: view.ExpiresAt}).Valid(false) {
		return nil, 0, errors.New("invalid directory join authorization")
	}
	return &view, rows.Kvs[0].ModRevision, nil
}

func (r *Region) RequestDirectoryJoin(ctx context.Context, tenant identity.TenantReservation, input enrollment.DirectoryJoinInput) (*identity.DirectoryJoinAuthorization, error) {
	if !input.Valid(true) {
		return nil, identity.ErrDirectoryJoinConflict
	}
	return r.queueDirectoryJoin(ctx, tenant, enrollment.StageDirectoryJoin, input)
}

func (r *Region) RequestDirectoryJoinClose(ctx context.Context, tenant identity.TenantReservation, id string) (*identity.DirectoryJoinAuthorization, error) {
	if !enrollment.ValidDirectoryJoinID(id) {
		return nil, identity.ErrDirectoryJoinNotFound
	}
	return r.queueDirectoryJoin(ctx, tenant, enrollment.CloseDirectoryJoin, enrollment.DirectoryJoinInput{ID: id})
}

func (r *Region) queueDirectoryJoin(ctx context.Context, tenant identity.TenantReservation, command string, input enrollment.DirectoryJoinInput) (*identity.DirectoryJoinAuthorization, error) {
	if r.workloads == nil {
		return nil, identity.ErrDirectoryJoinUnavailable
	}
	stage := command == enrollment.StageDirectoryJoin
	for range 6 {
		directory, guards, revision, err := r.managedDirectorySnapshot(ctx, tenant)
		if err != nil {
			return nil, err
		}
		if directory == nil || directory.ProvisionedAt.IsZero() {
			return nil, identity.ErrDirectoryJoinUnavailable
		}
		key := r.directoryJoinKey(*directory, input.ID)
		prior, mod, err := r.readDirectoryJoin(ctx, key, input.ID, revision)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		switch {
		case stage && prior != nil:
			if prior.Machine != input.Machine || prior.ExpiresAt != input.ExpiresAt {
				return nil, identity.ErrDirectoryJoinConflict
			}
			return r.LookupDirectoryJoin(ctx, tenant, input.ID)
		case stage && !identity.DirectoryJoinExpiryValid(now, input.ExpiresAt):
			return nil, identity.ErrDirectoryJoinExpiry
		case !stage && prior == nil:
			return nil, identity.ErrDirectoryJoinNotFound
		case !stage:
			if prior.State == identity.DirectoryJoinClosed || prior.State == identity.DirectoryJoinClosing || now.Unix() >= prior.ExpiresAt {
				return r.LookupDirectoryJoin(ctx, tenant, input.ID)
			}
			if prior.State != identity.DirectoryJoinReady {
				return nil, identity.ErrDirectoryJoinConflict
			}
			input.Machine, input.ExpiresAt = prior.Machine, prior.ExpiresAt
		}
		scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
		placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
		rows, err := r.client.Get(ctx, placementKey, clientv3.WithRev(revision))
		if err != nil {
			return nil, err
		}
		var placement directoryPlacement
		if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placement) != nil || placement.DirectoryID != directory.ID {
			return nil, identity.ErrDirectoryJoinUnavailable
		}
		writer := placement.Controllers[0]
		sid, writerGuards, err := r.directoryControllerHealth(ctx, *directory, scope, writer, 0, revision)
		if err != nil {
			return nil, err
		}
		if sid == "" {
			return nil, identity.ErrDirectoryJoinUnavailable
		}
		queue := r.directoryJoinKey(*directory, "pending")
		active, err := r.client.Get(ctx, queue, clientv3.WithRev(revision), clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if active.Count != 0 {
			return nil, identity.ErrDirectoryJoinConflict
		}
		lease, err := r.client.Grant(ctx, input.ExpiresAt-now.Unix())
		if err != nil {
			return nil, err
		}
		pending := pendingDirectoryJoin{ID: input.ID, Attempt: operationID(), Generation: writer.Generation, Command: command}
		data, _ := json.Marshal(input)
		pending.EncryptedInput = r.workloads.sealer.Seal(nil, nil, data, pending.label(queue))
		clear(data)
		sealed, _ := json.Marshal(pending)
		view := identity.DirectoryJoinAuthorization{ID: input.ID, Machine: input.Machine, ExpiresAt: input.ExpiresAt,
			State: identity.DirectoryJoinPending}
		if !stage {
			view = *prior
			view.State = identity.DirectoryJoinClosing
		}
		guards = append(guards, writerGuards...)
		guards = append(guards, clientv3.Compare(clientv3.ModRevision(placementKey), "=", rows.Kvs[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", mod), clientv3.Compare(clientv3.Version(queue), "=", 0))
		committed, err := r.client.Txn(ctx).If(guards...).Then(putJSON(key, view), clientv3.OpPut(queue, string(sealed), clientv3.WithLease(lease.ID)),
			r.auditOp(scope, arm.AuditEvent{Time: now, Actor: tenant.Administrator,
				Action: directoryJoinAudit + command, Target: input.ID, Outcome: view.State})).Commit()
		if err != nil {
			// The transaction may have committed before the response was lost.
			return nil, err
		}
		if committed.Succeeded {
			return &view, nil
		}
		_, _ = r.client.Revoke(ctx, lease.ID)
	}
	return nil, identity.ErrDirectoryJoinConflict
}

func (r *Region) readHostDirectoryJoin(ctx context.Context, host string, certificate []byte, tenant, generation string) (
	*authorizedDirectoryController, string, *pendingDirectoryJoin, int64, int64, error) {
	binding, err := r.authorizeDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return nil, "", nil, 0, 0, err
	}
	if binding.index != 0 {
		return nil, "", nil, 0, 0, enrollment.ErrHostDenied
	}
	if binding.directory.ProvisionedAt.IsZero() {
		return binding, "", nil, 0, 0, nil
	}
	key := r.directoryJoinKey(binding.directory, "pending")
	rows, err := r.client.Txn(ctx).If(binding.guards...).Then(clientv3.OpGet(key)).Commit()
	if err != nil {
		return nil, "", nil, 0, 0, err
	}
	if !rows.Succeeded {
		return nil, "", nil, 0, 0, enrollment.ErrDirectoryAssignmentChanged
	}
	items := rows.Responses[0].GetResponseRange().Kvs
	if len(items) == 0 {
		return binding, key, nil, 0, rows.Header.Revision, nil
	}
	var pending pendingDirectoryJoin
	if json.Unmarshal(items[0].Value, &pending) != nil || !enrollment.ValidDirectoryJoinID(pending.ID) ||
		!enrollment.ValidDirectoryJoinID(pending.Attempt) || pending.Generation != generation ||
		pending.Command != enrollment.StageDirectoryJoin && pending.Command != enrollment.CloseDirectoryJoin {
		return nil, "", nil, 0, 0, enrollment.ErrDirectoryAssignmentChanged
	}
	return binding, key, &pending, items[0].ModRevision, rows.Header.Revision, nil
}

func (r *Region) HostDirectoryJoinTask(ctx context.Context, host string, certificate []byte, tenant, generation string) (*enrollment.DirectoryJoinTask, error) {
	_, key, pending, _, _, err := r.readHostDirectoryJoin(ctx, host, certificate, tenant, generation)
	if err != nil || pending == nil {
		return nil, err
	}
	data, err := r.workloads.sealer.Open(nil, nil, pending.EncryptedInput, pending.label(key))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	task := enrollment.DirectoryJoinTask{Attempt: pending.Attempt, Command: pending.Command}
	if json.Unmarshal(data, &task.Input) != nil || task.Input.ID != pending.ID || !task.Valid() {
		return nil, errors.New("invalid persisted directory join task")
	}
	if time.Now().Unix() >= task.Input.ExpiresAt {
		return nil, nil
	}
	return &task, nil
}

func (r *Region) FinishDirectoryJoin(ctx context.Context, host string, certificate []byte, tenant, generation string, result enrollment.DirectoryJoinResult) error {
	binding, queue, pending, queueRev, revision, err := r.readHostDirectoryJoin(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	if pending == nil || pending.Attempt != result.Attempt || result.Succeeded == nil {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	directory := binding.directory
	key := r.directoryJoinKey(directory, pending.ID)
	view, mod, err := r.readDirectoryJoin(ctx, key, pending.ID, revision)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if view == nil || now.Unix() >= view.ExpiresAt ||
		pending.Command == enrollment.StageDirectoryJoin && view.State != identity.DirectoryJoinPending ||
		pending.Command == enrollment.CloseDirectoryJoin && view.State != identity.DirectoryJoinClosing {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	outcome := "Rejected"
	if *result.Succeeded {
		outcome = "Succeeded"
	}
	if pending.Command == enrollment.StageDirectoryJoin {
		view.State = identity.DirectoryJoinRejected
		if *result.Succeeded {
			view.State = identity.DirectoryJoinReady
			view.UPN = (enrollment.DirectoryJoinInput{ID: view.ID}).Username() + "@" + directory.Spec.DNSName
		}
	} else {
		view.State = identity.DirectoryJoinReady
		if *result.Succeeded {
			view.State = identity.DirectoryJoinClosed
		}
	}
	guards := append(binding.guards, clientv3.Compare(clientv3.ModRevision(queue), "=", queueRev), clientv3.Compare(clientv3.ModRevision(key), "=", mod))
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: directory.SubscriptionID}
	committed, err := r.client.Txn(ctx).If(guards...).Then(putJSON(key, view), clientv3.OpDelete(queue),
		r.auditOp(scope, arm.AuditEvent{Time: now, Actor: host, Action: directoryJoinAudit + pending.Command, Target: view.ID, Outcome: outcome})).Commit()
	if err == nil && !committed.Succeeded {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	return err
}
