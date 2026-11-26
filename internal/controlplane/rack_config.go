package controlplane

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/rack"
)

type rackProvisioningConfig struct {
	InventoryFile string                `json:"inventoryFile"`
	SignatureFile string                `json:"signatureFile"`
	PublicKeyFile string                `json:"publicKeyFile"`
	BMCCAFile     string                `json:"bmcCAFile"`
	IronicOrigin  string                `json:"ironicOrigin"`
	IronicCAFile  string                `json:"ironicCAFile"`
	IronicToken   string                `json:"ironicTokenFile"`
	DNS           rack.DNSConfig        `json:"dns"`
	Racks         map[string]rackPolicy `json:"racks"`
}

type rackPolicy struct {
	Network          netip.Prefix         `json:"network"`
	First            netip.Addr           `json:"firstAddress"`
	Last             netip.Addr           `json:"lastAddress"`
	Gateway          netip.Addr           `json:"gateway"`
	DNSZone          string               `json:"dnsZone"`
	BMCCredential    string               `json:"bmcCredentialFile"`
	Profile          string               `json:"profile"`
	Cell             string               `json:"cell"`
	Pool             string               `json:"pool"`
	Roles            []string             `json:"roles"`
	MinimumCPU       int                  `json:"minimumCPU"`
	MinimumMemoryMiB int                  `json:"minimumMemoryMiB"`
	RequireKVM       bool                 `json:"requireKVM"`
	Reserved         *enrollment.Capacity `json:"reserved,omitempty"`
}

func (p rackPolicy) valid() bool {
	netAddress := p.Network.Addr()
	if !netAddress.Is4() || p.Network != p.Network.Masked() || p.Network.Bits() > 30 ||
		!p.containsHostAddress(p.First) || !p.containsHostAddress(p.Last) ||
		!p.containsHostAddress(p.Gateway) || p.First.Compare(p.Last) > 0 ||
		(p.Gateway.Compare(p.First) >= 0 && p.Gateway.Compare(p.Last) <= 0) {
		return false
	}
	return rack.ValidDNSZone(p.DNSZone) && p.BMCCredential != "" && p.placement().ValidPlacementPolicy()
}

func (p rackPolicy) containsHostAddress(address netip.Addr) bool {
	// The last address of the subnet has no successor inside the subnet.
	return address.Is4() && address.IsGlobalUnicast() && p.Network.Contains(address) &&
		address != p.Network.Addr() && p.Network.Contains(address.Next())
}

func (p rackPolicy) placement() enrollment.Approval {
	return enrollment.Approval{Profile: p.Profile, Cell: p.Cell, Pool: p.Pool,
		Roles: p.Roles, MinimumCPU: p.MinimumCPU, MinimumMemoryMiB: p.MinimumMemoryMiB, RequireKVM: p.RequireKVM, Reserved: p.Reserved}
}

type rackProvisioning struct {
	cfg    rackProvisioningConfig
	bmcs   map[string]*rack.Redfish
	ironic *rack.Ironic
	dns    *rack.DNS
}

func openRackProvisioning(cfg *rackProvisioningConfig) (*rackProvisioning, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.InventoryFile == "" || cfg.SignatureFile == "" || cfg.PublicKeyFile == "" || len(cfg.Racks) == 0 {
		return nil, errors.New("rack provisioning requires signed inventory paths and rack policies")
	}
	bmcs := make(map[string]*rack.Redfish, len(cfg.Racks))
	for name, policy := range cfg.Racks {
		if !identifier.MatchString(name) || strings.HasSuffix(name, "-") || !policy.valid() {
			return nil, fmt.Errorf("invalid provisioning policy for rack %q", name)
		}
		bmc, err := rack.OpenRedfish(cfg.BMCCAFile, policy.BMCCredential)
		if err != nil {
			return nil, fmt.Errorf("configure rack %s: %w", name, err)
		}
		bmcs[name] = bmc
	}
	ironic, err := rack.OpenIronic(cfg.IronicOrigin, cfg.IronicCAFile, cfg.IronicToken)
	if err != nil {
		return nil, err
	}
	dns, err := rack.OpenDNS(cfg.DNS)
	if err != nil {
		return nil, err
	}
	return &rackProvisioning{cfg: *cfg, bmcs: bmcs, ironic: ironic, dns: dns}, nil
}
