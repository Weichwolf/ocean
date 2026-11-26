package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

var (
	ErrHostedPurgeScope   = errors.New("the share resource ID must belong to the requested subscription")
	ErrHostedPurgeState   = errors.New("file share deletion requires a suspended tenant and a completed share operation")
	ErrHostedPurgeChanged = errors.New("this request ID or volume already has a different deletion decision")
)

// HostedFilePurge binds an operator approval to one immutable file volume. The
// recorded worker identifies the queue at approval time. For a redundant SMB
// member, an independently fenced replacement in the same pool can execute it.
// CompletedAt is regional evidence and is never written to the deletion ledger.
type HostedFilePurge struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenantId"`
	SubscriptionID string    `json:"subscriptionId"`
	ShareID        string    `json:"shareId"`
	VolumeID       string    `json:"volumeId"`
	Worker         string    `json:"worker"`
	Pool           string    `json:"operatorPool"`
	Actor          string    `json:"actor"`
	ApprovalID     string    `json:"approvalId"`
	DecidedAt      time.Time `json:"decidedAt"`
	CompletedAt    time.Time `json:"completedAt,omitzero"`
}

func (d HostedFilePurge) Valid(tenant, id string) bool {
	return d.ID == id && d.TenantID == tenant && tenantID.MatchString(tenant) && tenantID.MatchString(id) &&
		tenantID.MatchString(d.SubscriptionID) && tenantID.MatchString(d.Actor) && tenantID.MatchString(d.ApprovalID) &&
		d.ShareID != "" && !d.DecidedAt.IsZero() && (d.CompletedAt.IsZero() || !d.CompletedAt.Before(d.DecidedAt))
}

type HostedFilePurgeRequest struct {
	SubscriptionID string `json:"subscriptionId"`
	ShareID        string `json:"shareId"`
	ApprovalID     string `json:"approvalId"`
}

type HostedFilePurgeStore interface {
	HostedFilePurge(context.Context, string, string) (*HostedFilePurge, error)
	RequestHostedFilePurge(context.Context, string, string, string, HostedFilePurgeRequest) (*HostedFilePurge, error)
}

func (c *Compatibility) EnableHostedFilePurge(store HostedFilePurgeStore) error {
	if c.offboarding == nil || store == nil {
		return errors.New("hosted file deletion requires the independent offboarding ledger")
	}
	c.filePurge = store
	return nil
}

func (c *Compatibility) hostedFilePurge(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 8*time.Second)
	defer cancel()
	tenant, actor, ok := c.hostedOperator(ctx, w, req)
	if !ok {
		return
	}
	id := req.PathValue("decision")
	if !tenantID.MatchString(id) {
		armError(w, http.StatusBadRequest, "InvalidDecisionId", "Use a UUID for the deletion decision.")
		return
	}
	var decision *HostedFilePurge
	var err error
	if req.Method == http.MethodPut {
		var input HostedFilePurgeRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !tenantID.MatchString(input.SubscriptionID) ||
			!tenantID.MatchString(input.ApprovalID) || input.ShareID == "" {
			armError(w, http.StatusBadRequest, "InvalidRequestContent", "Submit the subscription ID, full file share resource ID and recorded approval ID.")
			return
		}
		decision, err = c.filePurge.RequestHostedFilePurge(ctx, tenant, id, actor, input)
	} else {
		decision, err = c.filePurge.HostedFilePurge(ctx, tenant, id)
	}
	switch {
	case errors.Is(err, ErrHostedPurgeScope):
		armError(w, http.StatusBadRequest, "InvalidShareId", err.Error())
	case errors.Is(err, ErrHostedPurgeState):
		armError(w, http.StatusConflict, "FileShareDeletionUnavailable", err.Error())
	case errors.Is(err, ErrHostedPurgeChanged):
		armError(w, http.StatusConflict, "FileShareDeletionConflict", err.Error())
	case errors.Is(err, ErrPlacementTenantGone) || err == nil && decision == nil:
		armError(w, http.StatusNotFound, "ResourceNotFound", "The file share or deletion decision does not exist.")
	case err != nil:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The hosted file deletion decision is temporarily unavailable.")
	default:
		state := "Pending"
		if !decision.CompletedAt.IsZero() {
			state = "Succeeded"
		}
		writeJSON(w, http.StatusOK, struct {
			HostedFilePurge
			State string `json:"state"`
		}{*decision, state})
	}
}
