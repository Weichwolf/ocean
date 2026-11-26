package arm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

const (
	VPNVirtualGatewayType     = "Microsoft.Network/virtualNetworkGateways"
	VPNLocalGatewayType       = "Microsoft.Network/localNetworkGateways"
	VPNConnectionType         = "Microsoft.Network/connections"
	VPNGatewayAPIVersion      = "2025-01-01"
	VPNLocalGatewayAPIVersion = "2021-08-01"
)

type VPNVirtualGatewayRequest struct {
	Address, PublicIP, Subnet ResourceAddress
	Location, IPConfigName    string
	Tags                      map[string]string
}

type VPNLocalGatewayRequest struct {
	Address  ResourceAddress
	Location string
	Tags     map[string]string
	Peer     network.IPsecPeer
}

type VPNConnectionDeployment struct {
	Address, Deployment, VirtualGateway, LocalGateway ResourceAddress
	Location                                          string
	Tags                                              map[string]string
	// The handler clears SharedKey when DeployVPNConnection returns.
	SharedKey []byte `json:"-"`
}

type VPNChangeResult struct {
	Resource  InventoryResource
	Operation *Operation
	Created   bool
}

type VPNStore interface {
	PutVPNVirtualGateway(context.Context, SubscriptionScope, string, VPNVirtualGatewayRequest) (VPNChangeResult, error)
	PutVPNLocalGateway(context.Context, SubscriptionScope, string, VPNLocalGatewayRequest) (VPNChangeResult, error)
	DeployVPNConnection(context.Context, SubscriptionScope, string, VPNConnectionDeployment, bool) (VPNChangeResult, error)
	DeleteVPNResource(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func vpnResourceType(collection string) (kind, version string) {
	switch strings.ToLower(collection) {
	case "virtualnetworkgateways":
		return VPNVirtualGatewayType, VPNGatewayAPIVersion
	case "localnetworkgateways":
		return VPNLocalGatewayType, VPNLocalGatewayAPIVersion
	case "connections":
		return VPNConnectionType, VPNGatewayAPIVersion
	default:
		return "", ""
	}
}

func (s Server) vpnResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, path string) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || !network.ValidName(parts[2]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The VPN resource identifier is invalid.")
		return
	}
	kind, version := vpnResourceType(parts[1])
	if _, ok := readQuery(w, r, version, nil); !ok {
		return
	}
	if s.VPN == nil {
		unavailable(w)
		return
	}
	address := ResourceAddress{Group: group, Path: kind + "/" + parts[2]}
	switch r.Method {
	case http.MethodGet:
		resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if resource == nil || resource.APIVersion != version {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The VPN resource does not exist.")
		} else {
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, resource.view(scope))
		}
	case http.MethodDelete:
		op, err := s.VPN.DeleteVPNResource(ctx, scope, actor, address)
		if err != nil {
			deploymentError(w, err)
		} else if op == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			s.acceptOperation(w, scope, *op)
		}
	case http.MethodPut:
		if kind == VPNConnectionType {
			methodNotAllowed(w, "GET, DELETE")
			return
		}
		s.putVPNGateway(ctx, w, r, scope, actor, address, kind, version)
	default:
		if kind == VPNConnectionType {
			methodNotAllowed(w, "GET, DELETE")
		} else {
			methodNotAllowed(w, "GET, PUT, DELETE")
		}
	}
}

func (s Server) putVPNGateway(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor string, address ResourceAddress, kind, version string) {
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	var result VPNChangeResult
	var err error
	if kind == VPNVirtualGatewayType {
		desired, decode := readVPNVirtualGateway(body, scope, address, s.Location)
		if decode != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", decode.Error())
			return
		}
		result, err = s.VPN.PutVPNVirtualGateway(ctx, scope, actor, desired)
	} else {
		desired, decode := readVPNLocalGateway(body, address, s.Location)
		if decode != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", decode.Error())
			return
		}
		result, err = s.VPN.PutVPNLocalGateway(ctx, scope, actor, desired)
	}
	if err != nil {
		deploymentError(w, err)
		return
	}
	s.writeVPNChange(w, scope, address, version, result, true)
}

func readVPNVirtualGateway(body io.Reader, scope SubscriptionScope, address ResourceAddress, location string) (VPNVirtualGatewayRequest, error) {
	var input struct {
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties struct {
			GatewayType      string      `json:"gatewayType"`
			VPNType          string      `json:"vpnType"`
			ActiveActive     bool        `json:"activeActive"`
			EnableBGP        bool        `json:"enableBgp"`
			SKU              ResourceSKU `json:"sku"`
			IPConfigurations []gatewayConfiguration[struct {
				PrivateAllocation string                    `json:"privateIPAllocationMethod"`
				PublicIP          network.ResourceReference `json:"publicIPAddress"`
				Subnet            network.ResourceReference `json:"subnet"`
			}] `json:"ipConfigurations"`
		} `json:"properties"`
	}
	if err := strictJSON(body, &input); err != nil || input.Location != location || !validTags(input.Tags) {
		return VPNVirtualGatewayRequest{}, errors.New("the VPN gateway requires the regional location and supported properties")
	}
	p := input.Properties
	if p.GatewayType != "Vpn" || p.VPNType != "RouteBased" || p.SKU != (ResourceSKU{Name: "VpnGw1", Tier: "VpnGw1"}) ||
		p.ActiveActive || p.EnableBGP || len(p.IPConfigurations) != 1 {
		return VPNVirtualGatewayRequest{}, errors.New("the VPN gateway requires one route-based VpnGw1 IP configuration with BGP disabled")
	}
	config := p.IPConfigurations[0]
	publicIP, publicOK := sameGroupVPNReference(scope, address.Group, config.Properties.PublicIP.ID, network.PublicIPType)
	subnet, subnetOK := sameGroupVPNReference(scope, address.Group, config.Properties.Subnet.ID, network.SubnetType)
	if !publicOK || !subnetOK || !strings.HasSuffix(strings.ToLower(subnet.Path), "/gatewaysubnet") ||
		!network.ValidName(config.Name) || config.Properties.PrivateAllocation != "Dynamic" {
		return VPNVirtualGatewayRequest{}, errors.New("the VPN gateway requires a public IP and GatewaySubnet in its own group")
	}
	return VPNVirtualGatewayRequest{Address: address, PublicIP: publicIP, Subnet: subnet, Location: location,
		IPConfigName: config.Name, Tags: input.Tags}, nil
}

func readVPNLocalGateway(body io.Reader, address ResourceAddress, location string) (VPNLocalGatewayRequest, error) {
	var input struct {
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		Properties struct {
			Address netip.Addr `json:"gatewayIpAddress"`
			Space   struct {
				Prefixes []netip.Prefix `json:"addressPrefixes"`
			} `json:"localNetworkAddressSpace"`
		} `json:"properties"`
	}
	if err := strictJSON(body, &input); err != nil || input.Location != location || !validTags(input.Tags) {
		return VPNLocalGatewayRequest{}, errors.New("the local gateway requires the regional location and supported properties")
	}
	peer := network.IPsecPeer{Endpoint: input.Properties.Address, Prefixes: input.Properties.Space.Prefixes}
	if err := peer.Validate(); err != nil {
		return VPNLocalGatewayRequest{}, err
	}
	return VPNLocalGatewayRequest{Address: address, Location: location, Tags: input.Tags, Peer: peer}, nil
}

func sameGroupVPNReference(scope SubscriptionScope, group, id, kind string) (ResourceAddress, bool) {
	address, ok := NetworkResourceAddress(scope, id, kind)
	return address, ok && strings.EqualFold(address.Group, group)
}

func compileVPNConnection(scope SubscriptionScope, deployment ResourceAddress, location string,
	raw json.RawMessage, supplied map[string]templateValue) (VPNConnectionDeployment, error) {
	var template struct {
		Schema         string                      `json:"$schema"`
		ContentVersion string                      `json:"contentVersion"`
		Parameters     map[string]gatewayParameter `json:"parameters"`
		Variables      map[string]string           `json:"variables"`
		Resources      []templateResource          `json:"resources"`
		Outputs        map[string]templateValue    `json:"outputs"`
	}
	if err := strictJSON(bytes.NewReader(raw), &template); err != nil ||
		template.Schema != gatewayTemplateSchema || template.ContentVersion != "1.0.0.0" ||
		len(template.Parameters) != 1 || len(supplied) != 1 || template.Parameters["sharedKey"].Type != "securestring" ||
		len(template.Resources) != 1 || len(template.Variables) != 0 || len(template.Outputs) != 1 {
		return VPNConnectionDeployment{}, errors.New("expected the single-resource site-to-site VPN template")
	}
	item := template.Resources[0]
	if item.Type != VPNConnectionType || item.APIVersion != VPNGatewayAPIVersion || item.Location != location ||
		!network.ValidName(item.Name) || !validTags(item.Tags) || len(item.DependsOn) != 0 || item.SKU != (ResourceSKU{}) ||
		template.Outputs["resource"] != (templateValue{Type: "object", Value: "[reference('" + item.Name + "')]"}) {
		return VPNConnectionDeployment{}, errors.New("unsupported VPN connection resource or output")
	}
	var p struct {
		Type               string                    `json:"connectionType"`
		EnableBGP          bool                      `json:"enableBgp"`
		PolicySelectors    bool                      `json:"usePolicyBasedTrafficSelectors"`
		RoutingWeight      int                       `json:"routingWeight"`
		ExpressRouteBypass *bool                     `json:"expressRouteGatewayBypass"`
		SharedKey          string                    `json:"sharedKey"`
		VirtualGateway     network.ResourceReference `json:"virtualNetworkGateway1"`
		LocalGateway       network.ResourceReference `json:"localNetworkGateway2"`
	}
	if err := strictJSON(bytes.NewReader(item.Properties), &p); err != nil || p.Type != "IPSec" || p.EnableBGP ||
		p.PolicySelectors || p.RoutingWeight != 10 || p.ExpressRouteBypass != nil || p.SharedKey != "[parameters('sharedKey')]" {
		return VPNConnectionDeployment{}, errors.New("unsupported site-to-site IPsec connection properties")
	}
	virtual, virtualOK := sameGroupVPNReference(scope, deployment.Group, p.VirtualGateway.ID, VPNVirtualGatewayType)
	local, localOK := sameGroupVPNReference(scope, deployment.Group, p.LocalGateway.ID, VPNLocalGatewayType)
	if !virtualOK || !localOK {
		return VPNConnectionDeployment{}, errors.New("the VPN connection requires two gateway references in its own group")
	}
	value, ok := supplied["sharedKey"]
	if !ok || value.Type != "" || len(value.Value) < 16 || len(value.Value) > 128 || strings.ContainsAny(value.Value, "\r\n\x00") {
		return VPNConnectionDeployment{}, errors.New("a bounded secure IPsec shared key is required")
	}
	return VPNConnectionDeployment{Address: ResourceAddress{Group: deployment.Group, Path: VPNConnectionType + "/" + item.Name},
		Deployment: deployment, VirtualGateway: virtual, LocalGateway: local, Location: location, Tags: item.Tags, SharedKey: []byte(value.Value)}, nil
}

func (s Server) vpnConnectionDeployment(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string,
	address ResourceAddress, input deploymentInput, commit bool) {
	if s.VPN == nil {
		unavailable(w)
		return
	}
	desired, err := compileVPNConnection(scope, address, s.Location, input.Properties.Template, input.Properties.Parameters)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidTemplate", err.Error())
		return
	}
	defer clear(desired.SharedKey)
	result, err := s.VPN.DeployVPNConnection(ctx, scope, actor, desired, commit)
	if err != nil {
		deploymentError(w, err)
		return
	}
	s.writeVPNChange(w, scope, address, resourceAPIVersion, result, commit)
}

func (s Server) writeVPNChange(w http.ResponseWriter, scope SubscriptionScope, address ResourceAddress, version string,
	result VPNChangeResult, commit bool) {
	if !result.Resource.Valid() || result.Resource.Address.Key() != address.Key() || result.Resource.APIVersion != version {
		unavailable(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if commit {
		status = createdStatus(result.Created)
		if result.Operation != nil {
			w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", result.Operation.ID)+"?api-version="+resourceAPIVersion)
			w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+version)
			w.Header().Set("Retry-After", "1")
		}
	}
	writeJSON(w, status, result.Resource.view(scope))
}
