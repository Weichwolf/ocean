// Package network models tenant virtual networks and their address space.
package network

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

const (
	VNetAPIVersion   = "2025-07-01"
	SubnetAPIVersion = "2024-07-01"
)

var resourceName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?$`)

var privateBlocks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

func ValidName(name string) bool { return resourceName.MatchString(name) }

type AddressSpace struct {
	Prefixes []string `json:"addressPrefixes"`
}

type VNetProperties struct {
	AddressSpace      AddressSpace `json:"addressSpace"`
	Subnets           []Subnet     `json:"subnets"`
	ProvisioningState string       `json:"provisioningState"`
}

type Subnet struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	Properties SubnetProperties `json:"properties"`
}

type SubnetProperties struct {
	AddressPrefix                     string   `json:"addressPrefix,omitempty"`
	AddressPrefixes                   []string `json:"addressPrefixes,omitempty"`
	PrivateEndpointNetworkPolicies    string   `json:"privateEndpointNetworkPolicies,omitempty"`
	PrivateLinkServiceNetworkPolicies string   `json:"privateLinkServiceNetworkPolicies,omitempty"`
	DefaultOutboundAccess             *bool    `json:"defaultOutboundAccess,omitempty"`
	ProvisioningState                 string   `json:"provisioningState,omitempty"`
}

func (s SubnetProperties) prefixes() ([]netip.Prefix, error) {
	if s.AddressPrefix != "" && len(s.AddressPrefixes) > 0 {
		return nil, errors.New("specify either addressPrefix or addressPrefixes")
	}
	if s.PrivateEndpointNetworkPolicies != "" && s.PrivateEndpointNetworkPolicies != "Disabled" ||
		s.PrivateLinkServiceNetworkPolicies != "" && s.PrivateLinkServiceNetworkPolicies != "Enabled" ||
		s.DefaultOutboundAccess != nil && *s.DefaultOutboundAccess {
		return nil, errors.New("the requested subnet policy is unsupported")
	}
	prefixes := s.AddressPrefixes
	if s.AddressPrefix != "" {
		prefixes = []string{s.AddressPrefix}
	}
	return parsePrefixes(prefixes, 29)
}

func parsePrefixes(values []string, maxBits int) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one IPv4 prefix is required")
	}
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > maxBits || !slices.ContainsFunc(privateBlocks, func(block netip.Prefix) bool {
			return block.Bits() <= prefix.Bits() && block.Contains(prefix.Addr())
		}) {
			return nil, errors.New("address prefixes must be canonical private IPv4 networks")
		}
		if slices.ContainsFunc(result, prefix.Overlaps) {
			return nil, errors.New("address prefixes overlap")
		}
		result = append(result, prefix)
	}
	return result, nil
}

func (v VNetProperties) Validate() error {
	parents, err := parsePrefixes(v.AddressSpace.Prefixes, 29)
	if err != nil {
		return err
	}
	var allocated []netip.Prefix
	seen := make(map[string]bool)
	for _, subnet := range v.Subnets {
		name := strings.ToLower(subnet.Name)
		if !ValidName(subnet.Name) || seen[name] {
			return errors.New("subnet names must be valid and unique within a virtual network")
		}
		seen[name] = true
		children, err := subnet.Properties.prefixes()
		if err != nil {
			return err
		}
		for _, child := range children {
			if !slices.ContainsFunc(parents, func(parent netip.Prefix) bool {
				return parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
			}) {
				return errors.New("the subnet is outside every virtual network prefix")
			}
			if slices.ContainsFunc(allocated, child.Overlaps) {
				return errors.New("the subnet overlaps an existing subnet")
			}
			allocated = append(allocated, child)
		}
	}
	return nil
}

func NewSubnet(parentID, name string, properties SubnetProperties) Subnet {
	properties.ProvisioningState = "Succeeded"
	if properties.DefaultOutboundAccess == nil {
		value := false
		properties.DefaultOutboundAccess = &value
	}
	return Subnet{ID: parentID + "/subnets/" + name, Name: name, Type: "Microsoft.Network/virtualNetworks/subnets", Properties: properties}
}

func (v VNetProperties) SubnetIndex(name string) int {
	return slices.IndexFunc(v.Subnets, func(subnet Subnet) bool { return strings.EqualFold(subnet.Name, name) })
}
