package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
)

var ErrDirectoryAssignmentChanged = errors.New("directory assignment changed")
var directoryDomainSID = regexp.MustCompile(`^S-1-5-21(-[0-9]{1,10}){3}$`)

type DirectoryHealth struct {
	Ready     bool   `json:"ready"`
	DomainSID string `json:"domainSid,omitempty"`
}

func (h DirectoryHealth) Valid() bool {
	if h.Ready {
		return directoryDomainSID.MatchString(h.DomainSID)
	}
	return h.DomainSID == ""
}

type directoryBootstrapStore interface {
	HostDirectoryBootstrap(context.Context, string, []byte, string, string) ([]byte, error)
}

type directoryHealthStore interface {
	ReportDirectoryHealth(context.Context, string, []byte, string, string, DirectoryHealth) error
}

func (a *Authority) directoryHealth(w http.ResponseWriter, r *http.Request) {
	store, enabled := a.store.(directoryHealthStore)
	host, tenant, generation := r.PathValue("host"), r.PathValue("tenant"), r.PathValue("generation")
	if !enabled || !hostName.MatchString(host) || !hostName.MatchString(tenant) || !hostName.MatchString(generation) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	var report struct {
		Ready     *bool  `json:"ready"`
		DomainSID string `json:"domainSid"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || report.Ready == nil || decoder.Decode(new(any)) != io.EOF {
		reject(w, http.StatusBadRequest, "InvalidDirectoryHealth")
		return
	}
	health := DirectoryHealth{Ready: *report.Ready, DomainSID: report.DomainSID}
	if !health.Valid() {
		reject(w, http.StatusBadRequest, "InvalidDirectoryHealth")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	switch err := store.ReportDirectoryHealth(ctx, host, peer.Raw, tenant, generation, health); {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrDirectoryAssignmentChanged):
		reject(w, http.StatusConflict, "DirectoryAssignmentChanged")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "DirectoryUnavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *Authority) directoryBootstrap(w http.ResponseWriter, r *http.Request) {
	store, enabled := a.store.(directoryBootstrapStore)
	host, tenant, generation := r.PathValue("host"), r.PathValue("tenant"), r.PathValue("generation")
	if !enabled || !hostName.MatchString(host) || !hostName.MatchString(tenant) || !hostName.MatchString(generation) || r.URL.RawQuery != "" {
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
	secret, err := store.HostDirectoryBootstrap(ctx, host, peer.Raw, tenant, generation)
	if errors.Is(err, ErrHostDenied) {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "DirectoryUnavailable")
		return
	}
	defer clear(secret)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(secret)
}
