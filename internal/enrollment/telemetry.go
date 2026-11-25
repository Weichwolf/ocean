package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
)

type telemetryStore interface {
	ReportTelemetry(context.Context, string, []byte, telemetry.Batch) error
}

func (a *Authority) telemetry(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	store, supported := a.store.(telemetryStore)
	if !supported || !hostName.MatchString(host) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, telemetry.MaxBody))
	decoder.DisallowUnknownFields()
	var batch telemetry.Batch
	if decoder.Decode(&batch) != nil || decoder.Decode(new(any)) != io.EOF || len(batch.Observations) < 1 ||
		len(batch.Observations) > telemetry.MaxBatch {
		reject(w, http.StatusBadRequest, "InvalidTelemetryBatch")
		return
	}
	now := time.Now()
	for _, entry := range batch.Observations {
		if !entry.Sample.Valid(now) {
			reject(w, http.StatusBadRequest, "InvalidTelemetrySample")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := store.ReportTelemetry(ctx, host, peer.Raw, batch); err != nil {
		switch {
		case errors.Is(err, telemetry.ErrDisabled):
			reject(w, http.StatusServiceUnavailable, "TelemetryDisabled")
		case errors.Is(err, ErrHostDenied):
			reject(w, http.StatusForbidden, "HostIdentityDenied")
		default:
			reject(w, http.StatusServiceUnavailable, "TelemetryIngestionUnavailable")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
