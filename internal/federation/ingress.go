package federation

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/Weichwolf/ocean/internal/network"
)

type GeoIngressConfig struct {
	Policy          Policy                            `json:"policy"`
	Listen          netip.AddrPort                    `json:"listen"`
	Hostname        string                            `json:"hostname"`
	CertificateFile string                            `json:"certificateFile"`
	HealthPath      string                            `json:"healthPath"`
	Origins         map[string]network.GeoHTTPSOrigin `json:"origins"`
}

// GeoIngressHAProxy checks service origins against their farms' approved routes.
func GeoIngressHAProxy(cfg GeoIngressConfig) (string, error) {
	policy, err := canonicalPolicy(cfg.Policy, false)
	if err != nil {
		return "", err
	}
	origins := make([]network.GeoHTTPSOrigin, 0, len(cfg.Origins))
	for _, farm := range slices.Sorted(maps.Keys(cfg.Origins)) {
		origin := cfg.Origins[farm]
		routes := policy.Peers[farm].Imports
		if farm == policy.Farm {
			routes = policy.Exports
		}
		if !slices.ContainsFunc(routes, func(prefix netip.Prefix) bool {
			return prefix.Contains(origin.Address.Addr())
		}) {
			return "", fmt.Errorf("origin for farm %q is outside its approved routes", farm)
		}
		origins = append(origins, origin)
	}
	return network.GeoHTTPS(cfg.Listen, cfg.Hostname, cfg.CertificateFile, cfg.HealthPath, origins)
}
