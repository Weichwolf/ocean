package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

type desktopNativeConfig struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	DesktopID      string `json:"desktopId"`
	MachineID      string `json:"machineId"`
	Certificate    string `json:"certificateSha256"`
}

type desktopNativeGuest struct {
	scope     arm.SubscriptionScope
	address   arm.ResourceAddress
	machineID string
}

func configureDesktopNative(settings []desktopNativeConfig) (map[[sha256.Size]byte]desktopNativeGuest, string, error) {
	if len(settings) == 0 {
		return nil, "", nil
	}
	if len(settings) > 1024 {
		return nil, "", errors.New("too many native desktop guest bindings")
	}
	manifest := slices.Clone(settings)
	bindings := make(map[[sha256.Size]byte]desktopNativeGuest, len(manifest))
	machines := make(map[string]bool, len(manifest))
	desktops := make(map[string]bool, len(manifest))
	for i, guest := range manifest {
		scope := arm.SubscriptionScope{TenantID: guest.TenantID, SubscriptionID: guest.SubscriptionID}
		address, valid := arm.NetworkResourceAddress(scope, guest.DesktopID, arm.DesktopType)
		digest, err := hex.DecodeString(guest.Certificate)
		desktopID := strings.ToLower(address.ID(scope))
		if !valid || err != nil || len(digest) != sha256.Size || !enrollment.ValidDirectoryJoinID(guest.TenantID) ||
			!enrollment.ValidDirectoryJoinID(guest.SubscriptionID) || !enrollment.ValidDirectoryJoinID(guest.MachineID) ||
			machines[guest.MachineID] || desktops[desktopID] {
			return nil, "", errors.New("invalid or duplicate native desktop guest binding")
		}
		fingerprint := [sha256.Size]byte(digest)
		if _, duplicate := bindings[fingerprint]; duplicate {
			return nil, "", errors.New("native desktop guests require distinct client certificates")
		}
		machines[guest.MachineID] = true
		desktops[desktopID] = true
		bindings[fingerprint] = desktopNativeGuest{scope: scope, address: address, machineID: guest.MachineID}
		manifest[i].Certificate = hex.EncodeToString(digest)
		manifest[i].DesktopID = desktopID
	}
	slices.SortFunc(manifest, func(a, b desktopNativeConfig) int { return strings.Compare(a.MachineID, b.MachineID) })
	data, err := json.Marshal(manifest)
	return bindings, string(data), err
}

func (r *Region) AuthorizeNativeDesktop(ctx context.Context, certificate []byte, input desktop.NativeAdmissionRequest) error {
	if r.desktopLaunch == nil || len(certificate) == 0 || !desktop.ValidNativeAccount(input.User) {
		return arm.ErrDesktopDenied
	}
	guest, bound := r.desktopLaunch.nativeGuests[sha256.Sum256(certificate)]
	if !bound {
		return arm.ErrDesktopDenied
	}
	tenant, err := r.LookupTenant(ctx, guest.scope.TenantID)
	if err != nil {
		return err
	}
	if tenant == nil || !tenant.Valid(guest.scope.TenantID) || tenant.SubscriptionID != guest.scope.SubscriptionID {
		return arm.ErrDesktopDenied
	}
	_, err = r.resolvePersonalDesktop(ctx, identity.DesktopPrincipal{Tenant: *tenant, ExpiresAt: time.Now().Add(desktop.LaunchLifetime)},
		guest.address, desktopAccessOptions{nativeUser: input.User, machineID: guest.machineID})
	return err
}
