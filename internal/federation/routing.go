package federation

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// RoutingConfig describes one farm's private BGP edge. The same policy
// supplies the exact import and export sets used by farm pairing.
type RoutingConfig struct {
	Policy        Policy                 `json:"policy"`
	FarmAS        uint32                 `json:"farmAS"`
	PeerAS        map[string]uint32      `json:"peerAS"`
	FabricAS      uint32                 `json:"fabricAS"`
	FabricNetwork netip.Prefix           `json:"fabricNetwork"`
	FabricLink    string                 `json:"fabricLink"`
	ExportLinks   []string               `json:"exportLinks"`
	Routers       []netip.Addr           `json:"routers"`
	Gateways      map[string]GatewayPath `json:"gateways"`
	PreferredPath string                 `json:"preferredPath"`
}

type GatewayPath struct {
	FabricAddress netip.Addr `json:"fabricAddress"`
	WireGuardLink string     `json:"wireGuardLink"`
}

var routingLink = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// BIRDConfig renders a complete BIRD 2 IPv4 config for one gateway or fabric router.
func BIRDConfig(cfg RoutingConfig, path string, router netip.Addr) (string, error) {
	policy, err := canonicalPolicy(cfg.Policy, false)
	if err != nil {
		return "", err
	}
	cfg.Policy = policy
	if err := checkRouting(cfg); err != nil {
		return "", err
	}
	gateway, hasPath := cfg.Gateways[path]
	if path != "" && (!hasPath || router.IsValid()) ||
		path == "" && !slices.Contains(cfg.Routers, router) {
		return "", errors.New("select one configured gateway path or fabric router")
	}
	peers := slices.Sorted(maps.Keys(policy.Peers))
	imports := make([]netip.Prefix, 0, len(peers))
	for _, farm := range peers {
		imports = append(imports, policy.Peers[farm].Imports...)
	}
	local := router
	if hasPath {
		local = gateway.FabricAddress
	}
	var output strings.Builder
	fmt.Fprintf(&output, "log stderr { warning, error, fatal };\nrouter id %s;\n", local)
	output.WriteString("protocol device { scan time 1; }\n")
	// Use BFD for both direct LAN neighbors and the exact WireGuard overlay endpoints.
	fmt.Fprintf(&output, "protocol bfd {\n  interface %q { interval 300 ms; multiplier 3; };\n  multihop { interval 300 ms; multiplier 3; };\n}\n", cfg.FabricLink)
	kernelRoutes := slices.Clone(imports)
	if hasPath {
		kernelRoutes = append(kernelRoutes, policy.Exports...)
	}
	fmt.Fprintf(&output, "protocol kernel farm_kernel {\n  scan time 2;\n  ipv4 { import none; export filter {\n    if net ~ %s && (source = RTS_BGP || source = RTS_STATIC) then accept;\n    reject;\n  }; };\n}\n", prefixSet(kernelRoutes))
	// Prevent an unavailable approved destination from falling back to a default route.
	output.WriteString("protocol static unavailable {\n  ipv4 { preference 1; };\n")
	for _, prefix := range kernelRoutes {
		fmt.Fprintf(&output, "  route %s unreachable;\n", prefix)
	}
	output.WriteString("}\n")
	if hasPath {
		gatewayRoutes(&output, cfg, path, gateway, peers, imports)
	} else {
		fabricRoutes(&output, cfg, router, imports)
	}
	return output.String(), nil
}

func checkRouting(cfg RoutingConfig) error {
	fabric, err := canonicalRoutes([]netip.Prefix{cfg.FabricNetwork}, nil)
	if err != nil || fabric[0].Bits() > 30 || !routingLink.MatchString(cfg.FabricLink) ||
		len(cfg.Gateways) != 2 || len(cfg.Routers) < 1 || len(cfg.Routers) > 2 ||
		len(cfg.ExportLinks) == 0 || len(cfg.ExportLinks) > 16 || len(cfg.PeerAS) != len(cfg.Policy.Peers) {
		return errors.New("invalid private federation fabric configuration")
	}
	if _, ok := cfg.Policy.LocalPath[cfg.PreferredPath]; !ok {
		return errors.New("the preferred path must belong to the farm policy")
	}
	asns := map[uint32]bool{}
	for _, asn := range []uint32{cfg.FarmAS, cfg.FabricAS} {
		if !privateAS(asn) || asns[asn] {
			return errors.New("the farm and fabric require distinct private AS numbers")
		}
		asns[asn] = true
	}
	for _, endpoint := range cfg.Policy.LocalPath {
		if cfg.FabricNetwork.Contains(endpoint.Addr()) {
			return errors.New("a local overlay endpoint overlaps the fabric")
		}
	}
	overlapsFabric := func(prefix netip.Prefix) bool { return prefix.Overlaps(cfg.FabricNetwork) }
	if slices.ContainsFunc(cfg.Policy.Exports, overlapsFabric) {
		return errors.New("a local advertised prefix overlaps the fabric")
	}
	for name, peer := range cfg.Policy.Peers {
		asn := cfg.PeerAS[name]
		if !privateAS(asn) || asns[asn] {
			return fmt.Errorf("peer %s needs a distinct private AS number", name)
		}
		asns[asn] = true
		if slices.ContainsFunc(peer.Imports, overlapsFabric) {
			return fmt.Errorf("peer %s advertises a prefix overlapping the fabric", name)
		}
		for _, endpoint := range peer.Paths {
			if cfg.FabricNetwork.Contains(endpoint.Addr()) {
				return fmt.Errorf("peer %s has an overlay endpoint on the fabric", name)
			}
		}
	}
	for _, link := range cfg.ExportLinks {
		if !routingLink.MatchString(link) || link == cfg.FabricLink {
			return errors.New("exports require named workload interfaces distinct from the fabric")
		}
	}
	addresses := slices.Clone(cfg.Routers)
	for path := range cfg.Policy.LocalPath {
		gateway := cfg.Gateways[path]
		if !routingLink.MatchString(gateway.WireGuardLink) || gateway.WireGuardLink == cfg.FabricLink ||
			slices.Contains(cfg.ExportLinks, gateway.WireGuardLink) {
			return fmt.Errorf("path %s requires a separate WireGuard interface", path)
		}
		addresses = append(addresses, gateway.FabricAddress)
	}
	for index, address := range addresses {
		if !address.Is4() || !cfg.FabricNetwork.Contains(address) ||
			cfg.FabricNetwork.Addr() == address || !cfg.FabricNetwork.Contains(address.Next()) ||
			slices.Contains(addresses[:index], address) {
			return errors.New("gateway and router addresses must be unique hosts on the fabric")
		}
	}
	return nil
}

func privateAS(asn uint32) bool {
	return asn >= 64512 && asn <= 65534 || asn >= 4200000000 && asn <= 4294967294
}

func gatewayRoutes(output *strings.Builder, cfg RoutingConfig, path string, gateway GatewayPath, peers []string, imports []netip.Prefix) {
	output.WriteString("protocol static overlay_next_hops {\n  ipv4;\n")
	for _, farm := range peers {
		fmt.Fprintf(output, "  route %s/32 via %q;\n", cfg.Policy.Peers[farm].Paths[path].Addr(), gateway.WireGuardLink)
	}
	output.WriteString("}\n")
	for index, farm := range peers {
		peer := cfg.Policy.Peers[farm]
		bgpSession(output, fmt.Sprintf("peer_%d", index), cfg.Policy.LocalPath[path].Addr(), peer.Paths[path].Addr(),
			cfg.FarmAS, cfg.PeerAS[farm], 100, true, peer.Imports, cfg.Policy.Exports)
	}
	for index, router := range cfg.Routers {
		bgpSession(output, fmt.Sprintf("fabric_%d", index), gateway.FabricAddress, router,
			cfg.FarmAS, cfg.FabricAS, 100, false, cfg.Policy.Exports, imports)
	}
}

func fabricRoutes(output *strings.Builder, cfg RoutingConfig, local netip.Addr, imports []netip.Prefix) {
	output.WriteString("protocol direct farm_exports {\n")
	for _, link := range cfg.ExportLinks {
		fmt.Fprintf(output, "  interface %q;\n", link)
	}
	fmt.Fprintf(output, "  ipv4 { import filter { if net ~ %s then accept; reject; }; };\n}\n", prefixSet(cfg.Policy.Exports))
	for index, path := range slices.Sorted(maps.Keys(cfg.Gateways)) {
		preference := 100
		if path == cfg.PreferredPath {
			preference = 150
		}
		bgpSession(output, fmt.Sprintf("gateway_%d", index), local, cfg.Gateways[path].FabricAddress,
			cfg.FabricAS, cfg.FarmAS, preference, false, imports, cfg.Policy.Exports)
	}
}

func bgpSession(output *strings.Builder, name string, local, remote netip.Addr, localAS, remoteAS uint32, preference int,
	multihop bool, imports, exports []netip.Prefix) {
	fmt.Fprintf(output, "protocol bgp %s {\n  local %s as %d;\n  neighbor %s as %d;\n", name, local, localAS, remote, remoteAS)
	if multihop {
		output.WriteString("  multihop 2;\n")
	}
	output.WriteString("  strict bind on;\n  enforce first as on;\n  bfd on;\n  graceful restart off;\n  hold time 9;\n  connect delay time 1;\n  connect retry time 2;\n  error wait time 1, 3;\n")
	fmt.Fprintf(output, "  ipv4 {\n    preference %d;\n    next hop self;\n", preference)
	fmt.Fprintf(output, "    import filter {\n      if net ~ %s && bgp_next_hop = %s then accept;\n      reject;\n    };\n", prefixSet(imports), remote)
	fmt.Fprintf(output, "    export filter {\n      if net ~ %s && source != RTS_STATIC then accept;\n      reject;\n    };\n  };\n}\n", prefixSet(exports))
}

func prefixSet(prefixes []netip.Prefix) string {
	rendered := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		rendered[index] = prefix.String()
	}
	return "[" + strings.Join(rendered, ", ") + "]"
}
