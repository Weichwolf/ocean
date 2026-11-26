// Package federation reconciles pre-authorized farms over authenticated paths.
package federation

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/config"
)

type Config struct {
	config.Server
	Policy     Policy           `json:"policy"`
	Path       string           `json:"path"`
	DNSServers []netip.AddrPort `json:"dnsServers,omitempty"`
}

type Policy struct {
	Farm      string                    `json:"farm"`
	DNSName   string                    `json:"dnsName"`
	Exports   []netip.Prefix            `json:"exports"`
	LocalPath map[string]netip.AddrPort `json:"localPaths"`
	Peers     map[string]Peer           `json:"peers"`
}

type Peer struct {
	DNSName string                    `json:"dnsName"`
	Imports []netip.Prefix            `json:"imports"`
	Paths   map[string]netip.AddrPort `json:"paths"`
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validate(cfg Config) (Config, error) {
	if err := cfg.Server.Validate(); err != nil {
		return Config{}, err
	}
	if cfg.TLS == nil || cfg.TLS.ClientCAFile == "" || cfg.TLS.OptionalClientCA {
		return Config{}, errors.New("federation requires a dedicated mutual TLS listener")
	}
	listener, err := netip.ParseAddrPort(cfg.ListenAddress)
	if err != nil || listener != cfg.Policy.LocalPath[cfg.Path] {
		return Config{}, errors.New("the listener must match the selected local federation path")
	}
	for _, address := range cfg.DNSServers {
		if !address.IsValid() || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return Config{}, errors.New("invalid federation DNS server")
		}
	}
	cfg.Policy, err = canonicalPolicy(cfg.Policy, listener.Addr().IsLoopback())
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func canonicalPolicy(policy Policy, loopback bool) (Policy, error) {
	if !label.MatchString(policy.Farm) || !validDNSName(policy.DNSName) ||
		len(policy.LocalPath) != 2 || len(policy.Peers) == 0 || len(policy.Peers) > 32 {
		return Policy{}, errors.New("federation requires an identified farm with two paths and one to 32 approved peers")
	}
	addresses := make(map[netip.Addr]bool)
	for path, endpoint := range policy.LocalPath {
		if !label.MatchString(path) || !validPath(endpoint, loopback) || addresses[endpoint.Addr()] {
			return Policy{}, errors.New("the local federation paths require distinct valid IPv4 endpoints")
		}
		addresses[endpoint.Addr()] = true
	}
	routes, err := canonicalRoutes(policy.Exports, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("local federation routes: %w", err)
	}
	policy.Exports = routes
	dnsNames := map[string]bool{policy.DNSName: true}
	peers := make(map[string]Peer, len(policy.Peers))
	allRoutes := slices.Clone(policy.Exports)
	for farm, peer := range policy.Peers {
		if !label.MatchString(farm) || farm == policy.Farm || !validDNSName(peer.DNSName) || dnsNames[peer.DNSName] || len(peer.Paths) != 2 {
			return Policy{}, errors.New("invalid approved federation peer")
		}
		dnsNames[peer.DNSName] = true
		for path := range policy.LocalPath {
			endpoint := peer.Paths[path]
			if !validPath(endpoint, loopback) || addresses[endpoint.Addr()] {
				return Policy{}, fmt.Errorf("peer %s requires a distinct endpoint on path %s", farm, path)
			}
			addresses[endpoint.Addr()] = true
		}
		peer.Imports, err = canonicalRoutes(peer.Imports, allRoutes)
		if err != nil {
			return Policy{}, fmt.Errorf("peer %s routes: %w", farm, err)
		}
		allRoutes = append(allRoutes, peer.Imports...)
		peers[farm] = peer
	}
	for address := range addresses {
		if slices.ContainsFunc(allRoutes, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
			return Policy{}, errors.New("advertised routes must exclude federation path endpoints")
		}
	}
	policy.Peers = peers
	return policy, nil
}

func validPath(endpoint netip.AddrPort, loopback bool) bool {
	address := endpoint.Addr()
	return endpoint.Port() != 0 && address.Is4() &&
		(address.IsPrivate() && !loopback || address.IsLoopback() && loopback)
}

func validDNSName(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for part := range strings.SplitSeq(name, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}

func canonicalRoutes(prefixes, forbidden []netip.Prefix) ([]netip.Prefix, error) {
	if len(prefixes) == 0 || len(prefixes) > 32 {
		return nil, errors.New("one to 32 routes are required")
	}
	routes := slices.Clone(prefixes)
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}
	for index, prefix := range routes {
		if prefix != prefix.Masked() || !prefix.Addr().Is4() ||
			!slices.ContainsFunc(private, func(pool netip.Prefix) bool { return pool.Bits() <= prefix.Bits() && pool.Contains(prefix.Addr()) }) ||
			slices.ContainsFunc(routes[:index], prefix.Overlaps) || slices.ContainsFunc(forbidden, prefix.Overlaps) {
			return nil, errors.New("routes must be canonical private IPv4 prefixes without overlap")
		}
	}
	slices.SortFunc(routes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return routes, nil
}
