package network

import "net/netip"

// SubnetPolicy is the current network configuration for a reserved address.
// All fields come from the same regional revision as the host assignment.
type SubnetPolicy struct {
	Revision      int64          `json:"revision"`
	VNetID        string         `json:"virtualNetworkId"`
	Prefixes      []string       `json:"virtualNetworkPrefixes"`
	Address       netip.Prefix   `json:"address"`
	Gateway       netip.Addr     `json:"gateway"`
	SecurityRules []SecurityRule `json:"securityRules"`
	NATGatewayID  string         `json:"natGatewayId,omitempty"`
	PublicIPv4    netip.Addr     `json:"publicIPv4,omitzero"`
}

func (p SubnetPolicy) ValidFor(address netip.Addr) bool {
	return p.Revision > 0 && p.VNetID != "" && p.Address.Addr() == address && p.Address.Masked().Contains(p.Gateway) &&
		p.Gateway == p.Address.Masked().Addr().Next() && IsUsableSubnetAddress(p.Address.Masked(), address) &&
		(p.NATGatewayID == "") == !p.PublicIPv4.IsValid() && (!p.PublicIPv4.IsValid() || p.PublicIPv4.Is4() && p.PublicIPv4.IsGlobalUnicast())
}

func FirstUsableSubnetAddress(prefix netip.Prefix) netip.Addr {
	if !prefix.Addr().Is4() || prefix.Bits() > 29 || prefix != prefix.Masked() {
		return netip.Addr{}
	}
	address := prefix.Addr()
	for range 4 {
		address = address.Next()
	}
	return address
}

func IsUsableSubnetAddress(prefix netip.Prefix, address netip.Addr) bool {
	first := FirstUsableSubnetAddress(prefix)
	return first.IsValid() && prefix.Contains(address) && address.Compare(first) >= 0 && prefix.Contains(address.Next())
}
