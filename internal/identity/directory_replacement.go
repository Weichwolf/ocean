package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const ReplaceDirectoryReplica = "ReplaceDirectoryReplica"
const ReplaceDirectoryPrimary = "ReplaceDirectoryPrimary"

// DirectoryReplicaFence binds a power-off observation to the exact assignment
// being retired. The authority signs the serialized attestation.
type DirectoryReplicaFence struct {
	Action         string    `json:"action"`
	TenantID       string    `json:"tenantId"`
	SubscriptionID string    `json:"subscriptionId"`
	DirectoryID    string    `json:"directoryId"`
	HostID         string    `json:"hostId"`
	PlacementID    string    `json:"placementId"`
	Generation     string    `json:"generation"`
	Observation    string    `json:"observation"`
	ObservedAt     time.Time `json:"observedAt"`
}

type SignedDirectoryFence struct {
	Attestation []byte `json:"attestation"`
	Signature   []byte `json:"signature"`
}

var (
	ErrDirectoryFenceDenied  = errors.New("the directory fence evidence is unavailable or invalid")
	ErrDirectoryFencePending = errors.New("the directory replica is unavailable for fenced replacement")
)

type directoryReplacementStore interface {
	RequestDirectoryReplicaReplacement(context.Context, TenantReservation, SignedDirectoryFence) error
}

type directoryPrimaryReplacementStore interface {
	RequestDirectoryPrimaryReplacement(context.Context, TenantReservation, SignedDirectoryFence) error
}

func (c *Compatibility) replaceDirectoryController(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation, primary bool) {
	var replace func(context.Context, TenantReservation, SignedDirectoryFence) error
	code, pending := "DirectoryReplicaUnavailable", ErrDirectoryFencePending.Error()
	if primary {
		if store, enabled := c.directories.(directoryPrimaryReplacementStore); enabled {
			replace = store.RequestDirectoryPrimaryReplacement
		}
		code, pending = "DirectoryPrimaryUnavailable", "The directory primary is unavailable for fenced replacement."
	} else if store, enabled := c.directories.(directoryReplacementStore); enabled {
		replace = store.RequestDirectoryReplicaReplacement
	}
	if replace == nil {
		http.NotFound(w, req)
		return
	}
	var fence SignedDirectoryFence
	decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fence) != nil || decoder.Decode(new(any)) != io.EOF {
		armError(w, http.StatusBadRequest, "InvalidRequest", "Submit one signed directory fence attestation.")
		return
	}
	switch err := replace(ctx, tenant, fence); {
	case errors.Is(err, ErrDirectoryFenceDenied):
		armError(w, http.StatusForbidden, "InvalidDirectoryFence", ErrDirectoryFenceDenied.Error())
	case errors.Is(err, ErrDirectoryFencePending):
		armError(w, http.StatusConflict, code, pending)
	case err != nil:
		directoryError(w, err)
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", c.cloud.ResourceManager+directoryPath(tenant.TenantID)+"?api-version="+directoryAPIVersion)
		w.WriteHeader(http.StatusAccepted)
	}
}
