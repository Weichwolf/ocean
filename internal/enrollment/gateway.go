package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// HTTPSAssignment is available to the registered gateway hosts for one slot.
type HTTPSAssignment struct {
	Slot              string         `json:"slot"`
	Generation        string         `json:"generation"`
	Delete            bool           `json:"delete,omitempty"`
	PublicIPv4        netip.Addr     `json:"publicIPv4"`
	Hostname          string         `json:"hostname"`
	Backend           netip.AddrPort `json:"backend"`
	BackendSubnet     netip.Prefix   `json:"backendSubnet"`
	CertificateBundle []byte         `json:"certificateBundle,omitempty"`
}

type HTTPSGatewayStatus struct {
	Generation  string `json:"generation"`
	Ready       bool   `json:"ready"`
	OwnsAddress bool   `json:"ownsAddress"`
	Removed     bool   `json:"removed,omitempty"`
}

var ErrGatewayAssignmentChanged = errors.New("gateway assignment has changed")

type gatewayStore interface {
	HTTPSAssignments(context.Context, string, []byte) ([]HTTPSAssignment, error)
	ReportHTTPSGatewayStatus(context.Context, string, []byte, string, HTTPSGatewayStatus) error
}

func (a *Authority) reportHTTPSStatus(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(gatewayStore)
	hostID, slot := r.PathValue("host"), r.PathValue("slot")
	if !supported || !hostName.MatchString(hostID) || !hostName.MatchString(slot) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	var status HTTPSGatewayStatus
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&status) != nil || decoder.Decode(new(any)) != io.EOF ||
		!hostName.MatchString(status.Generation) || !status.Ready && status.OwnsAddress || status.Removed && status.Ready {
		reject(w, http.StatusBadRequest, "InvalidGatewayStatus")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	switch err := store.ReportHTTPSGatewayStatus(ctx, hostID, peer.Raw, slot, status); {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrGatewayAssignmentChanged):
		reject(w, http.StatusConflict, "GatewayAssignmentChanged")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "GatewayAssignmentUnavailable")
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *Authority) httpsAssignments(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(gatewayStore)
	hostID := r.PathValue("host")
	if !supported || !hostName.MatchString(hostID) || r.URL.RawQuery != "" {
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
	assignments, err := store.HTTPSAssignments(ctx, hostID, peer.Raw)
	if errors.Is(err, ErrHostDenied) {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "GatewayAssignmentUnavailable")
		return
	}
	respond(w, http.StatusOK, map[string]any{"assignments": assignments})
}
