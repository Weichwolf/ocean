package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

type storageStore interface {
	HostShareJobs(context.Context, string, []byte) ([]storage.Job, error)
	CompleteShareJob(context.Context, string, []byte, string) error
}

func (a *Authority) storageJobs(w http.ResponseWriter, r *http.Request) {
	backend, supported := a.store.(storageStore)
	host, job := r.PathValue("host"), r.PathValue("job")
	if !supported || !hostName.MatchString(host) || r.Method == http.MethodPost && !hostName.MatchString(job) || r.URL.RawQuery != "" {
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
	var assignments []storage.Job
	var err error
	if job == "" {
		assignments, err = backend.HostShareJobs(ctx, host, peer.Raw)
	} else {
		err = backend.CompleteShareJob(ctx, host, peer.Raw, job)
	}
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "ShareOperationUnavailable")
	case job == "":
		defer func() {
			for _, assignment := range assignments {
				clear(assignment.VolumeKey)
			}
		}()
		respond(w, http.StatusOK, map[string][]storage.Job{"jobs": assignments})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

type mountStore interface {
	HostVolumeMounts(context.Context, string, []byte) ([]storage.MountTask, error)
	ReportVolumeUnmount(context.Context, string, []byte, storage.UnmountReceipt) error
}

func (a *Authority) volumeMounts(w http.ResponseWriter, r *http.Request) {
	backend, supported := a.store.(mountStore)
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
	mounts, err := backend.HostVolumeMounts(ctx, host, peer.Raw)
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "VolumeMountUnavailable")
	default:
		defer func() {
			for _, mount := range mounts {
				clear(mount.VolumeKey)
			}
		}()
		respond(w, http.StatusOK, map[string][]storage.MountTask{"mounts": mounts})
	}
}

func (a *Authority) volumeUnmount(w http.ResponseWriter, r *http.Request) {
	backend, supported := a.store.(mountStore)
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
	var receipt storage.UnmountReceipt
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF ||
		!storage.ValidID(receipt.VolumeID) || !hostName.MatchString(receipt.TenantID) || !hostName.MatchString(receipt.SubscriptionID) ||
		!hostName.MatchString(receipt.PlacementID) || !hostName.MatchString(receipt.Generation) || !hostName.MatchString(receipt.Revision) {
		reject(w, http.StatusBadRequest, "InvalidVolumeUnmountReceipt")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if err := backend.ReportVolumeUnmount(ctx, host, peer.Raw, receipt); err != nil {
		replyWorkloadError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
