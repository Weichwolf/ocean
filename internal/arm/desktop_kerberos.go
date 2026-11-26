package arm

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
)

type DesktopCIFSStore interface {
	DesktopCIFSCache(context.Context, []byte, desktop.KerberosRequest) ([]byte, error)
}

func (s Server) desktopKerberos(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.DesktopCIFS == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		writeError(w, http.StatusForbidden, "DesktopGuestDenied", "Desktop guest access denied.")
		return
	}
	peer := r.TLS.PeerCertificates[0]
	now := time.Now()
	if peer == nil || now.Before(peer.NotBefore) || !now.Before(peer.NotAfter) {
		writeError(w, http.StatusForbidden, "DesktopGuestDenied", "Desktop guest access denied.")
		return
	}
	var input desktop.KerberosRequest
	defer func() { clear(input.Credential) }()
	if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" ||
		strictJSON(http.MaxBytesReader(w, r.Body, 1024), &input) != nil || !desktop.IsLaunchPassword(input.Credential) {
		writeError(w, http.StatusBadRequest, "InvalidDesktopGuestRequest", "A desktop launch credential is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cache, err := s.DesktopCIFS.DesktopCIFSCache(ctx, peer.Raw, input)
	defer clear(cache)
	if errors.Is(err, desktop.ErrLaunchDenied) {
		writeError(w, http.StatusForbidden, "DesktopGuestDenied", "Desktop guest access denied.")
		return
	}
	if err != nil || len(cache) == 0 || len(cache) > desktop.MaxCIFSCache {
		writeError(w, http.StatusServiceUnavailable, "DesktopKerberosUnavailable", "The desktop Kerberos service is unavailable.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(cache)
}
