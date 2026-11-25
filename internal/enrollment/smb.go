package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/smb"
)

var ErrSMBPlanChanged = errors.New("the SMB member plan has changed")

type smbStore interface {
	HostSMBPlan(context.Context, string, []byte) (smb.Plan, error)
	CompleteSMBPlan(context.Context, string, []byte, int64) error
}

func (a *Authority) smbPlan(w http.ResponseWriter, r *http.Request) {
	backend, supported := a.store.(smbStore)
	host := r.PathValue("host")
	if !supported || !hostName.MatchString(host) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		plan, err := backend.HostSMBPlan(ctx, host, peer.Raw)
		defer plan.ClearKeys()
		if err != nil {
			replySMBPlanError(w, err)
			return
		}
		respond(w, http.StatusOK, plan)
		return
	}
	var receipt struct {
		Revision int64 `json:"revision"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF || receipt.Revision < 1 {
		reject(w, http.StatusBadRequest, "InvalidSMBPlanReceipt")
		return
	}
	if err := backend.CompleteSMBPlan(ctx, host, peer.Raw, receipt.Revision); err != nil {
		replySMBPlanError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func replySMBPlanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrSMBPlanChanged):
		reject(w, http.StatusConflict, "SMBPlanChanged")
	default:
		reject(w, http.StatusServiceUnavailable, "SMBPlanUnavailable")
	}
}
