package network

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

const SecurityGroupAPIVersion = "2022-01-01"

type SecurityGroupProperties struct {
	SecurityRules        []SecurityRule `json:"securityRules"`
	DefaultSecurityRules []SecurityRule `json:"defaultSecurityRules"`
	ProvisioningState    string         `json:"provisioningState"`
}

type SecurityRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Properties SecurityRuleProperties `json:"properties"`
}

type SecurityRuleProperties struct {
	Access                     string   `json:"access"`
	Direction                  string   `json:"direction"`
	Protocol                   string   `json:"protocol"`
	Priority                   int      `json:"priority"`
	Description                string   `json:"description,omitempty"`
	SourceAddressPrefix        string   `json:"sourceAddressPrefix,omitempty"`
	SourceAddressPrefixes      []string `json:"sourceAddressPrefixes,omitempty"`
	DestinationAddressPrefix   string   `json:"destinationAddressPrefix,omitempty"`
	DestinationAddressPrefixes []string `json:"destinationAddressPrefixes,omitempty"`
	SourcePortRange            string   `json:"sourcePortRange,omitempty"`
	SourcePortRanges           []string `json:"sourcePortRanges,omitempty"`
	DestinationPortRange       string   `json:"destinationPortRange,omitempty"`
	DestinationPortRanges      []string `json:"destinationPortRanges,omitempty"`
	ProvisioningState          string   `json:"provisioningState,omitempty"`
}

func (p SecurityRuleProperties) Validate() error {
	if p.Access != "Allow" && p.Access != "Deny" || p.Direction != "Inbound" && p.Direction != "Outbound" ||
		p.Priority < 100 || p.Priority > 4096 || utf8.RuneCountInString(p.Description) > 140 ||
		p.ProvisioningState != "" {
		return errors.New("invalid rule access, direction, priority, description, or provisioning state")
	}
	switch p.Protocol {
	case "*", "Tcp", "Udp", "Icmp":
	default:
		return errors.New("the rule protocol is unsupported")
	}
	if !validSelectors(p.SourceAddressPrefix, p.SourceAddressPrefixes, validRuleAddress) ||
		!validSelectors(p.DestinationAddressPrefix, p.DestinationAddressPrefixes, validRuleAddress) {
		return errors.New("address selectors must contain IPv4 addresses, IPv4 prefixes, or a single wildcard")
	}
	if !validSelectors(p.SourcePortRange, p.SourcePortRanges, validRulePortRange) ||
		!validSelectors(p.DestinationPortRange, p.DestinationPortRanges, validRulePortRange) {
		return errors.New("port selectors must contain ports, ordered ranges, or a single wildcard")
	}
	if (p.Protocol == "*" || p.Protocol == "Icmp") &&
		(!wildcardSelector(p.SourcePortRange, p.SourcePortRanges) || !wildcardSelector(p.DestinationPortRange, p.DestinationPortRanges)) {
		return errors.New("port constraints require TCP or UDP")
	}
	return nil
}

func wildcardSelector(single string, multiple []string) bool {
	return single == "*" || len(multiple) == 1 && multiple[0] == "*"
}

func validSelectors(single string, multiple []string, valid func(string) bool) bool {
	if single != "" {
		return len(multiple) == 0 && (single == "*" || valid(single))
	}
	if len(multiple) == 0 || len(multiple) > 32 {
		return false
	}
	for _, value := range multiple {
		if !(value == "*" && len(multiple) == 1) && !valid(value) {
			return false
		}
	}
	return true
}

func validRuleAddress(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4()
	}
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4() && prefix == prefix.Masked()
}

func validRulePortRange(value string) bool {
	first, last, rangeSpecified := strings.Cut(value, "-")
	start, err := strconv.ParseUint(first, 10, 16)
	if err != nil {
		return false
	}
	if !rangeSpecified {
		return true
	}
	end, err := strconv.ParseUint(last, 10, 16)
	return err == nil && start <= end
}

func NewSecurityRule(parentID, name, collection string, properties SecurityRuleProperties) SecurityRule {
	properties.ProvisioningState = "Succeeded"
	return SecurityRule{ID: parentID + "/" + collection + "/" + name, Name: name,
		Type: "Microsoft.Network/networkSecurityGroups/" + collection, Properties: properties}
}

func DefaultSecurityRules(parentID string) []SecurityRule {
	rule := func(name, direction, access string, priority int, source, destination string) SecurityRule {
		return NewSecurityRule(parentID, name, "defaultSecurityRules", SecurityRuleProperties{
			Access: access, Direction: direction, Protocol: "*", Priority: priority,
			SourceAddressPrefix: source, DestinationAddressPrefix: destination, SourcePortRange: "*", DestinationPortRange: "*",
		})
	}
	return []SecurityRule{
		rule("AllowVnetInBound", "Inbound", "Allow", 65000, "VirtualNetwork", "VirtualNetwork"),
		rule("AllowAzureLoadBalancerInBound", "Inbound", "Allow", 65001, "AzureLoadBalancer", "*"),
		rule("DenyAllInBound", "Inbound", "Deny", 65500, "*", "*"),
		rule("AllowVnetOutBound", "Outbound", "Allow", 65000, "VirtualNetwork", "VirtualNetwork"),
		rule("AllowInternetOutBound", "Outbound", "Allow", 65001, "*", "Internet"),
		rule("DenyAllOutBound", "Outbound", "Deny", 65500, "*", "*"),
	}
}
