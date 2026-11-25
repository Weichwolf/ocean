package arm

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/workload"
)

var ErrReplicaSetChanged = errors.New("the installed replica set profile is immutable while its slots are reserved")

type ReplicaSetStore interface {
	PutReplicaSet(context.Context, SubscriptionScope, string, ResourceAddress, workload.ReplicaSetSpec) (InventoryResource, *Operation, bool, error)
	DeleteReplicaSet(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func (s Server) replicaSet(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, name string) {
	if s.ReplicaSets == nil {
		unavailable(w)
		return
	}
	if !workload.ValidReplicaSetName(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "Use a supported replica set name.")
		return
	}
	if _, ok := readQuery(w, r, workload.ReplicaSetAPIVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: workload.ReplicaSetType + "/" + name}
	switch r.Method {
	case http.MethodGet:
		result, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if result == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The replica set does not exist.")
		} else {
			writeJSON(w, http.StatusOK, result.view(scope))
		}
	case http.MethodPut:
		var spec workload.ReplicaSetSpec
		if strictJSON(http.MaxBytesReader(w, r.Body, 96<<10), &spec) != nil || spec.Validate(s.Location) != nil {
			s.replicaSetError(w, workload.ErrInvalidReplicaSet)
			return
		}
		vnet, _, ok := SubnetParent(scope, spec.Properties.SubnetID)
		if !ok || !strings.EqualFold(vnet.Group, group) {
			s.replicaSetError(w, workload.ErrInvalidReplicaSet)
			return
		}
		result, op, created, err := s.ReplicaSets.PutReplicaSet(ctx, scope, actor, address, spec)
		if err != nil {
			s.replicaSetError(w, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		if op != nil && op.Status == OperationInProgress {
			s.replicaOperationHeaders(w, scope, *op, address)
			status = http.StatusAccepted
		}
		writeJSON(w, status, result.view(scope))
	case http.MethodDelete:
		op, err := s.ReplicaSets.DeleteReplicaSet(ctx, scope, actor, address)
		if err != nil {
			s.replicaSetError(w, err)
		} else if op == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			s.replicaOperationHeaders(w, scope, *op, address)
			writeJSON(w, http.StatusAccepted, map[string]string{"status": op.Status})
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) replicaOperationHeaders(w http.ResponseWriter, scope SubscriptionScope, operation Operation, address ResourceAddress) {
	query := "?api-version=" + resourceAPIVersion
	w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+query)
	w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+workload.ReplicaSetAPIVersion)
	w.Header().Set("Retry-After", "1")
}

func (s Server) replicaSetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workload.ErrInvalidReplicaSet):
		writeError(w, http.StatusBadRequest, "InvalidReplicaSet", err.Error())
	case errors.Is(err, ErrReplicaSetChanged):
		writeError(w, http.StatusConflict, "ImmutableReplicaSet", err.Error())
	default:
		containerError(w, err)
	}
}
