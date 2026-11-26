package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/Weichwolf/ocean/internal/network"
)

type IPsecAssignment struct {
	Slot              string             `json:"slot"`
	Generation        string             `json:"generation"`
	Remove            bool               `json:"remove,omitempty"`
	ReleaseAddress    bool               `json:"releaseAddress,omitempty"`
	PublicIPv4        netip.Addr         `json:"publicIPv4"`
	InsideIPv4        netip.Prefix       `json:"insideIPv4"`
	ProtectedPrefixes []netip.Prefix     `json:"protectedPrefixes"`
	Peer              *network.IPsecPeer `json:"peer,omitempty"`
	SharedKey         []byte             `json:"sharedKey,omitempty"`
}

type IPsecStatus struct {
	Generation string `json:"generation"`
	Ready      bool   `json:"ready"`
	Connected  bool   `json:"connected"`
	Removed    bool   `json:"removed"`
}

type ipsecStore interface {
	IPsecAssignments(context.Context, string, []byte) ([]IPsecAssignment, error)
	ReportIPsecStatus(context.Context, string, []byte, string, IPsecStatus) error
}

func (a *Authority) ipsecAssignment(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(ipsecStore)
	host, slot := r.PathValue("host"), r.PathValue("slot")
	if !supported || !hostName.MatchString(host) || slot != "" && !hostName.MatchString(slot) || r.URL.RawQuery != "" {
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
	if r.Method == http.MethodGet {
		assignments, err := store.IPsecAssignments(ctx, host, peer.Raw)
		defer func() {
			for _, assignment := range assignments {
				clear(assignment.SharedKey)
			}
		}()
		if !ipsecAssignmentError(w, err) {
			respond(w, http.StatusOK, map[string]any{"assignments": assignments})
		}
		return
	}
	var status IPsecStatus
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&status) != nil || decoder.Decode(new(any)) != io.EOF || !hostName.MatchString(status.Generation) ||
		status.Connected && !status.Ready || status.Removed && status.Ready {
		reject(w, http.StatusBadRequest, "InvalidGatewayStatus")
		return
	}
	if !ipsecAssignmentError(w, store.ReportIPsecStatus(ctx, host, peer.Raw, slot, status)) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func ipsecAssignmentError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrGatewayAssignmentChanged):
		reject(w, http.StatusConflict, "GatewayAssignmentChanged")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "GatewayAssignmentUnavailable")
	default:
		return false
	}
	return true
}
