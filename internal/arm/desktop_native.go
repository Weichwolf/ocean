package arm

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
)

type DesktopNativeStore interface {
	AuthorizeNativeDesktop(context.Context, []byte, desktop.NativeAdmissionRequest) error
}

func (s Server) desktopNativeAdmission(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.DesktopNative == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	peer := desktopPeer(r)
	if peer == nil {
		writeError(w, http.StatusForbidden, "DesktopGuestDenied", "Desktop guest access denied.")
		return
	}
	var input desktop.NativeAdmissionRequest
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Type") != "application/json" ||
		strictJSON(http.MaxBytesReader(w, r.Body, 512), &input) != nil || !desktop.ValidNativeAccount(input.User) {
		writeError(w, http.StatusBadRequest, "InvalidDesktopGuestRequest", "A canonical workforce account name is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	err := s.DesktopNative.AuthorizeNativeDesktop(ctx, peer.Raw, input)
	switch {
	case errors.Is(err, ErrDesktopDenied):
		writeError(w, http.StatusForbidden, "DesktopGuestDenied", "Desktop guest access denied.")
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "DesktopAdmissionUnavailable", "Desktop guest admission is unavailable.")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
