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

const DirectoryDomainSIDHeader = "Ocean-Directory-Domain-Sid"

type DirectoryBootstrap struct {
	Credential []byte
	DomainSID  string
}

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
	HostDirectoryBootstrap(context.Context, string, []byte, string, string) (DirectoryBootstrap, error)
	CommitDirectoryIdentity(context.Context, string, []byte, string, string, string) error
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
	bootstrap, err := store.HostDirectoryBootstrap(ctx, host, peer.Raw, tenant, generation)
	if errors.Is(err, ErrHostDenied) {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "DirectoryUnavailable")
		return
	}
	defer clear(bootstrap.Credential)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set(DirectoryDomainSIDHeader, bootstrap.DomainSID)
	_, _ = w.Write(bootstrap.Credential)
}

func (a *Authority) directoryIdentity(w http.ResponseWriter, r *http.Request) {
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
	var proposed struct {
		DomainSID string `json:"domainSid"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proposed) != nil || !directoryDomainSID.MatchString(proposed.DomainSID) || decoder.Decode(new(any)) != io.EOF {
		reject(w, http.StatusBadRequest, "InvalidDirectoryIdentity")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	switch err := store.CommitDirectoryIdentity(ctx, host, peer.Raw, tenant, generation, proposed.DomainSID); {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrDirectoryAssignmentChanged):
		reject(w, http.StatusConflict, "DirectoryIdentityMismatch")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "DirectoryUnavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
