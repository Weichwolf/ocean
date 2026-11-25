package arm

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

const (
	DesktopType       = "Ocean.Desktop/personalDesktops"
	DesktopAPIVersion = "2026-11-01"
)

var (
	ErrDesktopPolicy    = errors.New("the desktop principal is not an enabled workforce user or managed security group in this tenant")
	ErrDesktopVM        = errors.New("the desktop requires a prepared Linux VM in the same resource group")
	ErrDesktopConflict  = errors.New("this VM already backs a desktop or the assignment would change the bound VM or directory")
	ErrDesktopDirectory = errors.New("the tenant's managed directory is unavailable")
	ErrDesktopDenied    = errors.New("the user has no current access to this desktop")
	ErrDesktopOffline   = errors.New("the assigned desktop is unavailable")
	ErrDesktopGateway   = errors.New("the desktop gateway has no current authorization")
)

type DesktopPolicy struct {
	VirtualMachineID string `json:"virtualMachineId"`
	PrincipalType    string `json:"principalType"`
	PrincipalID      string `json:"principalId"`
}

func (p DesktopPolicy) ValidPrincipal() bool {
	return (p.PrincipalType == "User" || p.PrincipalType == "Group") && enrollment.ValidDirectoryJoinID(p.PrincipalID)
}

type DesktopStore interface {
	PutPersonalDesktop(context.Context, SubscriptionScope, string, ResourceAddress, DesktopPolicy) (*InventoryResource, bool, error)
	DeletePersonalDesktop(context.Context, SubscriptionScope, string, ResourceAddress) error
	AuthorizePersonalDesktop(context.Context, identity.DesktopPrincipal, ResourceAddress) (DesktopAdmission, error)
}

type DesktopAdmission struct {
	AssignmentID string    `json:"assignmentId"`
	MachineID    string    `json:"machineId"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type DesktopLaunchStore interface {
	LaunchPersonalDesktop(context.Context, identity.DesktopPrincipal, ResourceAddress, string, []byte) (DesktopLaunch, error)
	RenewPersonalDesktop(context.Context, identity.DesktopPrincipal, ResourceAddress, string, []byte) (DesktopSession, error)
}

// DesktopSession describes the route and placement a gateway may continue to use.
type DesktopSession struct {
	DesktopAdmission
	User             string     `json:"user"`
	PrivateIP        netip.Addr `json:"privateIp"`
	NetworkInterface string     `json:"networkInterfaceId"`
	SubnetID         string     `json:"subnetId"`
	Generation       string     `json:"generation"`
}

// DesktopLaunch is sent only to an authorized gateway over mutual TLS.
type DesktopLaunch struct {
	DesktopSession
	Credential string `json:"credential"`
}

func (s Server) authorizePersonalDesktop(w http.ResponseWriter, r *http.Request, subscription, group, name, action string) {
	gatewayAction := action != "desktopAuthorization"
	if s.Desktops == nil || s.AuthenticateDesktop == nil || gatewayAction && s.DesktopLaunch == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if !vmResourceName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The personal desktop name is invalid.")
		return
	}
	if _, ok := readQuery(w, r, DesktopAPIVersion, nil); !ok {
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeError(w, http.StatusBadRequest, "InvalidDesktopRequest", "The desktop access action takes no request body.")
		return
	}
	var peer *x509.Certificate
	if gatewayAction {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusForbidden, "DesktopGatewayDenied", ErrDesktopGateway.Error())
			return
		}
		peer = r.TLS.PeerCertificates[0]
		now := time.Now()
		if peer == nil || now.Before(peer.NotBefore) || !now.Before(peer.NotAfter) {
			writeError(w, http.StatusForbidden, "DesktopGatewayDenied", ErrDesktopGateway.Error())
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 24*time.Second)
	defer cancel()
	principal, err := s.AuthenticateDesktop(ctx, r)
	switch {
	case errors.Is(err, identity.ErrInvalidDesktopToken):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "InvalidDesktopToken", err.Error())
		return
	case err != nil:
		unavailable(w)
		return
	case !strings.EqualFold(subscription, principal.Tenant.SubscriptionID):
		writeError(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription could not be found.")
		return
	}
	address := ResourceAddress{Group: group, Path: DesktopType + "/" + name}
	if gatewayAction {
		if peer.NotAfter.Before(principal.ExpiresAt) {
			principal.ExpiresAt = peer.NotAfter
		}
		var result any
		var err error
		if action == "desktopLaunch" {
			result, err = s.DesktopLaunch.LaunchPersonalDesktop(ctx, principal, address, peer.Subject.CommonName, peer.Raw)
		} else {
			result, err = s.DesktopLaunch.RenewPersonalDesktop(ctx, principal, address, peer.Subject.CommonName, peer.Raw)
		}
		if err != nil {
			desktopError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	admission, err := s.Desktops.AuthorizePersonalDesktop(ctx, principal, address)
	if err != nil {
		desktopError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, admission)
}

func (s Server) personalDesktop(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, name string) {
	if s.Desktops == nil {
		unavailable(w)
		return
	}
	if !vmResourceName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The personal desktop name is invalid.")
		return
	}
	if _, ok := readQuery(w, r, DesktopAPIVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: DesktopType + "/" + name}
	switch r.Method {
	case http.MethodGet:
		s.showResource(ctx, w, r, scope, reader, address)
	case http.MethodPut:
		var input struct {
			Location   string        `json:"location"`
			Properties DesktopPolicy `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err != nil || input.Location != s.Location || !input.Properties.ValidPrincipal() {
			writeError(w, http.StatusBadRequest, "InvalidDesktopPolicy", "Specify the regional location, a virtual machine ID, and one managed user or group object ID.")
			return
		}
		vm, ok := NetworkResourceAddress(scope, input.Properties.VirtualMachineID, VirtualMachineType)
		if !ok || !strings.EqualFold(vm.Group, group) {
			writeError(w, http.StatusBadRequest, "InvalidDesktopVM", ErrDesktopVM.Error())
			return
		}
		resource, created, err := s.Desktops.PutPersonalDesktop(ctx, scope, actor, address, input.Properties)
		if err != nil {
			desktopError(w, err)
			return
		}
		writeJSON(w, createdStatus(created), resource.view(scope))
	case http.MethodDelete:
		if err := s.Desktops.DeletePersonalDesktop(ctx, scope, actor, address); err != nil {
			desktopError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func desktopError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrDesktopPolicy):
		writeError(w, http.StatusBadRequest, "InvalidDesktopPolicy", err.Error())
	case errors.Is(err, ErrDesktopVM):
		writeError(w, http.StatusBadRequest, "InvalidDesktopVM", err.Error())
	case errors.Is(err, ErrDesktopConflict):
		writeError(w, http.StatusConflict, "DesktopBindingConflict", err.Error())
	case errors.Is(err, ErrDesktopDirectory):
		writeError(w, http.StatusServiceUnavailable, "DesktopDirectoryUnavailable", err.Error())
	case errors.Is(err, ErrDesktopDenied):
		writeError(w, http.StatusForbidden, "DesktopAccessDenied", err.Error())
	case errors.Is(err, ErrDesktopGateway):
		writeError(w, http.StatusForbidden, "DesktopGatewayDenied", err.Error())
	case errors.Is(err, ErrDesktopOffline):
		writeError(w, http.StatusServiceUnavailable, "DesktopUnavailable", err.Error())
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupDeleting", err.Error())
	default:
		inventoryError(w, err)
	}
}
