package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

const (
	DirectoryJoinPending  = "Pending"
	DirectoryJoinReady    = "Ready"
	DirectoryJoinClosing  = "Closing"
	DirectoryJoinClosed   = "Closed"
	DirectoryJoinRejected = "Rejected"
	DirectoryJoinExpired  = "Expired"
	DirectoryJoinRevoked  = "Revoked"
)

var (
	ErrDirectoryJoinNotFound    = errors.New("join authorization does not exist")
	ErrDirectoryJoinConflict    = errors.New("the join authorization differs or another directory operation is pending")
	ErrDirectoryJoinUnavailable = errors.New("the directory writer is unavailable")
	ErrDirectoryJoinExpiry      = errors.New("set expiresAt to a Unix timestamp between 15 seconds and 10 minutes from now")
)

type DirectoryJoinAuthorization struct {
	ID            string `json:"requestId"`
	Machine       string `json:"machineName"`
	ExpiresAt     int64  `json:"expiresAt"`
	State         string `json:"state"`
	UPN           string `json:"userPrincipalName,omitempty"`
	RecoveryEpoch string `json:"recoveryEpoch,omitempty"`
}

type directoryJoinStore interface {
	RequestDirectoryJoin(context.Context, TenantReservation, enrollment.DirectoryJoinInput) (*DirectoryJoinAuthorization, error)
	LookupDirectoryJoin(context.Context, TenantReservation, string) (*DirectoryJoinAuthorization, error)
	RequestDirectoryJoinClose(context.Context, TenantReservation, string) (*DirectoryJoinAuthorization, error)
}

func (c *Compatibility) manageDirectoryJoin(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation) {
	store, enabled := c.directories.(directoryJoinStore)
	if !enabled {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := req.PathValue("authorization")
	if !enrollment.ValidDirectoryJoinID(id) {
		armError(w, http.StatusBadRequest, "InvalidRequest", "Use a lowercase UUID for the authorization.")
		return
	}
	var view *DirectoryJoinAuthorization
	var err error
	switch req.Method {
	case http.MethodPut:
		var fields struct {
			Machine   string `json:"machineName"`
			ExpiresAt int64  `json:"expiresAt"`
			Password  string `json:"password"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&fields) != nil || decoder.Decode(new(any)) != io.EOF {
			armError(w, http.StatusBadRequest, "InvalidRequest", "Submit one join authorization.")
			return
		}
		input := enrollment.DirectoryJoinInput{ID: id, Machine: fields.Machine, ExpiresAt: fields.ExpiresAt, Password: fields.Password}
		if !input.Valid(true) {
			armError(w, http.StatusBadRequest, "InvalidRequest", "Specify an uppercase machine name and a strong temporary password of 32 to 128 printable ASCII characters.")
			return
		}
		view, err = store.RequestDirectoryJoin(ctx, tenant, input)
	case http.MethodPost:
		if _, readErr := io.ReadAll(http.MaxBytesReader(w, req.Body, 0)); readErr != nil {
			armError(w, http.StatusBadRequest, "InvalidRequest", "Closing a join authorization takes no body.")
			return
		}
		view, err = store.RequestDirectoryJoinClose(ctx, tenant, id)
	default:
		view, err = store.LookupDirectoryJoin(ctx, tenant, id)
	}
	switch {
	case errors.Is(err, ErrDirectoryJoinConflict):
		armError(w, http.StatusConflict, "DirectoryJoinConflict", ErrDirectoryJoinConflict.Error())
	case errors.Is(err, ErrDirectoryJoinExpiry):
		armError(w, http.StatusBadRequest, "InvalidDirectoryJoinExpiry", ErrDirectoryJoinExpiry.Error())
	case errors.Is(err, ErrDirectoryJoinUnavailable):
		armError(w, http.StatusServiceUnavailable, "DirectoryWriterUnavailable", ErrDirectoryJoinUnavailable.Error())
	case errors.Is(err, ErrDirectoryJoinNotFound):
		armError(w, http.StatusNotFound, "ResourceNotFound", ErrDirectoryJoinNotFound.Error())
	case err != nil:
		directoryError(w, err)
	case view == nil:
		armError(w, http.StatusNotFound, "ResourceNotFound", ErrDirectoryJoinNotFound.Error())
	default:
		status := http.StatusOK
		if req.Method != http.MethodGet && (view.State == DirectoryJoinPending || view.State == DirectoryJoinClosing) {
			status = http.StatusAccepted
			w.Header().Set("Location", c.cloud.ResourceManager+directoryPath(tenant.TenantID)+"/joinAuthorizations/"+id+"?api-version="+directoryAPIVersion)
			w.Header().Set("Retry-After", "2")
		}
		response := *view
		response.RecoveryEpoch = ""
		writeJSON(w, status, response)
	}
}

func DirectoryJoinExpiryValid(now time.Time, expires int64) bool {
	return expires >= now.Unix()+15 && expires <= now.Unix()+600
}
