package arm

import (
	"context"
	"errors"
	"net/http"

	"github.com/Weichwolf/ocean/internal/smb"
)

var (
	ErrSMBUnavailable = errors.New("the subscription has no ready SMB member")
	ErrSMBPolicy      = errors.New("the SMB policy is invalid for this directory")
	ErrSMBConflict    = errors.New("the SMB share is in use or its request conflicts with a pending operation")
	ErrSMBCapacity    = errors.New("the SMB member has reached its share limit")
	ErrSMBQuota       = errors.New("changing the size of an existing SMB volume is unsupported")
)

type SMBStore interface {
	PutSMBShare(context.Context, SubscriptionScope, string, ResourceAddress, smb.Policy) (InventoryResource, *Operation, bool, error)
	DeleteSMBShare(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func (s Server) smbShare(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, name string) {
	if s.SMBShares == nil {
		unavailable(w)
		return
	}
	if !smb.ValidName(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The SMB share name is invalid.")
		return
	}
	if _, ok := readQuery(w, r, smb.APIVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: smb.ResourceType + "/" + name}
	switch r.Method {
	case http.MethodGet:
		s.showStorageResource(ctx, w, scope, reader, address)
	case http.MethodPut:
		var input struct {
			Location   string     `json:"location"`
			Properties smb.Policy `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 16<<10), &input); err != nil || input.Location != s.Location || !input.Properties.Valid() {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", ErrSMBPolicy.Error())
			return
		}
		resource, operation, created, err := s.SMBShares.PutSMBShare(ctx, scope, actor, address, input.Properties)
		if err != nil {
			smbError(w, err)
		} else if operation == nil || operation.Status == OperationSucceeded {
			writeJSON(w, createdStatus(created), resource.view(scope))
		} else {
			w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+"?api-version="+resourceAPIVersion)
			w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+smb.APIVersion)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusAccepted, resource.view(scope))
		}
	case http.MethodDelete:
		operation, err := s.SMBShares.DeleteSMBShare(ctx, scope, actor, address)
		if err != nil {
			smbError(w, err)
		} else if operation == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			s.acceptOperation(w, scope, *operation)
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func smbError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrSMBPolicy):
		writeError(w, http.StatusBadRequest, "InvalidSMBPolicy", err.Error())
	case errors.Is(err, ErrSMBUnavailable):
		writeError(w, http.StatusServiceUnavailable, "SMBMemberUnavailable", err.Error())
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupDeleting", err.Error())
	case errors.Is(err, ErrSMBConflict), errors.Is(err, ErrSMBCapacity), errors.Is(err, ErrSMBQuota):
		writeError(w, http.StatusConflict, "SMBShareConflict", err.Error())
	default:
		inventoryError(w, err)
	}
}
