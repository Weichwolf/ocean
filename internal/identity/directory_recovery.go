package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

var directoryBackupChecksum = regexp.MustCompile(`^[a-f0-9]{64}$`)

const (
	RecoverDirectory        = "RecoverDirectory"
	DirectoryRecoveryFenced = "Fenced"
	DirectoryRecoveryStaged = "AwaitingRestore"
	DirectoryRecoveryReady  = "Succeeded"
)

type DirectoryRecoveryController struct {
	HostID      string `json:"hostId"`
	PlacementID string `json:"placementId"`
	Generation  string `json:"generation"`
}

// DirectoryRecoveryFence binds an independent archive and two powered-off
// controller assignments to the same signed disaster-recovery operation.
type DirectoryRecoveryFence struct {
	Action         string                        `json:"action"`
	TenantID       string                        `json:"tenantId"`
	SubscriptionID string                        `json:"subscriptionId"`
	DirectoryID    string                        `json:"directoryId"`
	RecoveryID     string                        `json:"recoveryId"`
	BackupSHA256   string                        `json:"backupSha256"`
	Controllers    []DirectoryRecoveryController `json:"controllers"`
	Observation    string                        `json:"observation"`
	ObservedAt     time.Time                     `json:"observedAt"`
}

func (p DirectoryRecoveryFence) Valid(tenant TenantReservation, id string) bool {
	return p.Action == RecoverDirectory && p.TenantID == tenant.TenantID && p.SubscriptionID == tenant.SubscriptionID &&
		p.RecoveryID == id && enrollment.ValidDirectoryJoinID(id) && directoryBackupChecksum.MatchString(p.BackupSHA256) &&
		len(p.Controllers) == 2 && p.Observation == "PoweredOff" && !p.ObservedAt.IsZero()
}

type DirectoryRecovery struct {
	ID        string `json:"recoveryId"`
	State     string `json:"state"`
	Writer    string `json:"writerHostId,omitempty"`
	BackupSHA string `json:"backupSha256"`
}

type directoryRecoveryStore interface {
	RequestDirectoryRecovery(context.Context, TenantReservation, string, SignedDirectoryFence) (*DirectoryRecovery, error)
	LookupDirectoryRecovery(context.Context, TenantReservation, string) (*DirectoryRecovery, error)
}

func (c *Compatibility) recoverDirectory(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation) {
	store, enabled := c.directories.(directoryRecoveryStore)
	if !enabled {
		http.NotFound(w, req)
		return
	}
	id := req.PathValue("recovery")
	if !enrollment.ValidDirectoryJoinID(id) {
		armError(w, http.StatusBadRequest, "InvalidRequest", "Use a lowercase UUID for the recovery operation.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var view *DirectoryRecovery
	var err error
	if req.Method == http.MethodPut {
		var fence SignedDirectoryFence
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&fence) != nil || decoder.Decode(new(any)) != io.EOF {
			armError(w, http.StatusBadRequest, "InvalidRequest", "Submit a signed fence attestation for the two directory controllers.")
			return
		}
		view, err = store.RequestDirectoryRecovery(ctx, tenant, id, fence)
	} else {
		view, err = store.LookupDirectoryRecovery(ctx, tenant, id)
	}
	switch {
	case errors.Is(err, ErrDirectoryFenceDenied):
		armError(w, http.StatusForbidden, "InvalidDirectoryFence", ErrDirectoryFenceDenied.Error())
	case errors.Is(err, ErrDirectoryFencePending):
		armError(w, http.StatusConflict, "DirectoryRecoveryUnavailable", "Directory recovery requires two inactive controller hosts and no conflicting operation.")
	case err != nil:
		directoryError(w, err)
	case view == nil:
		armError(w, http.StatusNotFound, "ResourceNotFound", "The directory recovery operation does not exist.")
	default:
		status := http.StatusOK
		if req.Method == http.MethodPut && view.State != DirectoryRecoveryReady {
			status = http.StatusAccepted
			w.Header().Set("Location", c.cloud.ResourceManager+directoryPath(tenant.TenantID)+"/recoveries/"+id+"?api-version="+directoryAPIVersion)
			w.Header().Set("Retry-After", "2")
		}
		writeJSON(w, status, view)
	}
}
