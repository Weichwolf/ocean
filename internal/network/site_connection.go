package network

import (
	"errors"
	"net/netip"
	"slices"
)

const (
	SiteConnectionType       = "Ocean.Network/siteConnections"
	SiteConnectionAPIVersion = "2026-11-01"
)

// SiteConnectionProperties is the requested customer network and its two
// WireGuard peers. Gateway private keys remain on the enrolled gateway hosts.
type SiteConnectionProperties struct {
	Subnet           ResourceReference `json:"subnet"`
	CustomerPrefixes []netip.Prefix    `json:"customerPrefixes"`
	Peers            []SitePeer        `json:"peers"`
}

type SitePeer struct {
	PublicKey      string         `json:"publicKey"`
	Endpoint       netip.AddrPort `json:"endpoint"`
	GatewayTunnel  netip.Prefix   `json:"gatewayTunnel"`
	CustomerTunnel netip.Addr     `json:"customerTunnel"`
}

func privateNetworkPrefix(prefix netip.Prefix) bool {
	return prefix.Addr().Is4() && prefix == prefix.Masked() &&
		slices.ContainsFunc(privateBlocks, func(block netip.Prefix) bool {
			return block.Bits() <= prefix.Bits() && block.Contains(prefix.Addr())
		})
}

func (connection SiteConnectionProperties) Validate() error {
	if connection.Subnet.ID == "" || len(connection.CustomerPrefixes) == 0 ||
		len(connection.CustomerPrefixes) > 16 || len(connection.Peers) != 2 {
		return errors.New("a site connection requires a subnet, one to 16 customer prefixes, and two peers")
	}
	var networks []netip.Prefix
	for _, prefix := range connection.CustomerPrefixes {
		if !privateNetworkPrefix(prefix) || slices.ContainsFunc(networks, prefix.Overlaps) {
			return errors.New("customer prefixes must be disjoint canonical private IPv4 networks")
		}
		networks = append(networks, prefix)
	}
	for index, peer := range connection.Peers {
		tunnel := peer.GatewayTunnel.Masked()
		endpoint := peer.Endpoint.Addr()
		if !validWireGuardKey(peer.PublicKey) || peer.Endpoint.Port() == 0 || !endpoint.Is4() || !endpoint.IsGlobalUnicast() ||
			!privateNetworkPrefix(tunnel) || tunnel.Bits() != 31 || !tunnel.Contains(peer.CustomerTunnel) ||
			peer.GatewayTunnel.Addr() == peer.CustomerTunnel || tunnel.Contains(endpoint) ||
			slices.ContainsFunc(networks, tunnel.Overlaps) || slices.ContainsFunc(networks, func(prefix netip.Prefix) bool {
			return prefix.Contains(endpoint)
		}) {
			return errors.New("each site peer requires a distinct endpoint, public key, and private /31 tunnel outside the customer prefixes")
		}
		if index == 1 && (peer.PublicKey == connection.Peers[0].PublicKey || endpoint == connection.Peers[0].Endpoint.Addr()) {
			return errors.New("the site connection requires two independent peers")
		}
		networks = append(networks, tunnel, netip.PrefixFrom(endpoint, 32))
	}
	return nil
}
