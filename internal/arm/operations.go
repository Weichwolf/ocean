package arm

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	OperationInProgress = "InProgress"
	OperationSucceeded  = "Succeeded"
	OperationFailed     = "Failed"
)

type Operation struct {
	ID         string     `json:"operationId"`
	Kind       string     `json:"kind"`
	Group      string     `json:"group"`
	Actor      string     `json:"actor"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startTime"`
	FinishedAt *time.Time `json:"endTime,omitempty"`
}

type OperationStore interface {
	GetOperation(context.Context, SubscriptionScope, string) (*Operation, error)
}

func operationPath(scope SubscriptionScope, kind, id string) string {
	return "/subscriptions/" + scope.SubscriptionID + "/providers/Microsoft.Resources/" + kind + "/" + id
}

func (s Server) acceptOperation(w http.ResponseWriter, scope SubscriptionScope, operation Operation) {
	query := "?api-version=" + resourceAPIVersion
	w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+query)
	w.Header().Set("Location", s.Origin+operationPath(scope, "operationResults", operation.ID)+query)
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
}

func (s Server) operation(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, kind, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if _, ok := readQuery(w, r, resourceAPIVersion, nil); !ok {
		return
	}
	if !validUUID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "InvalidOperationId", "The operation identifier must be a UUID.")
		return
	}
	operation, err := s.Operations.GetOperation(ctx, scope, strings.ToLower(id))
	if err != nil {
		unavailable(w)
		return
	}
	if operation == nil {
		writeError(w, http.StatusNotFound, "OperationNotFound", "The operation could not be found.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if operation.Status == OperationInProgress {
		w.Header().Set("Retry-After", "1")
	}
	const targetChanged = "OperationTargetChanged"
	const targetChangedMessage = "The operation target changed before completion."
	if kind == "operationresults" {
		switch operation.Status {
		case OperationSucceeded:
			w.WriteHeader(http.StatusNoContent)
		case OperationFailed:
			writeError(w, http.StatusConflict, targetChanged, targetChangedMessage)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
		return
	}
	status := map[string]any{"id": operationPath(scope, "operationStatuses", operation.ID), "name": operation.ID,
		"status": operation.Status, "startTime": operation.StartedAt}
	if operation.FinishedAt != nil {
		status["endTime"] = operation.FinishedAt
	}
	if operation.Status == OperationFailed {
		status["error"] = map[string]string{"code": targetChanged, "message": targetChangedMessage}
	}
	writeJSON(w, http.StatusOK, status)
}

// AwaitOperation waits until an assigned worker has confirmed a provider operation.
func AwaitOperation(ctx context.Context, store OperationStore, scope SubscriptionScope, operation *Operation) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for operation != nil && operation.Status == OperationInProgress {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := store.GetOperation(ctx, scope, operation.ID)
			if err != nil {
				return err
			}
			if current == nil {
				return ErrContainerMissing
			}
			operation = current
		}
	}
	if operation != nil && operation.Status != OperationSucceeded {
		return ErrContainerBusy
	}
	return nil
}
