package enrollment

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type directoryBootstrapStore interface {
	HostDirectoryBootstrap(context.Context, string, []byte, string, string) ([]byte, error)
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
