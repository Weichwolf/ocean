package arm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

const (
	applicationGatewayType              = "Microsoft.Network/applicationGateways"
	ApplicationGatewayResourceVersion   = "2026-01-01"
	ApplicationGatewayDeploymentVersion = "2024-11-01"
	gatewayTemplateAPIVersion           = "2022-05-01"
	gatewayTemplateSchema               = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
)

var (
	ErrGatewayExecutionUnavailable = errors.New("gateway execution is unavailable")
	ErrGatewayNameInUse            = errors.New("the Application Gateway already has a deployment")
	ErrGatewaySubnetInUse          = errors.New("the subnet already contains an Application Gateway")
)

type ApplicationGatewayDeployment struct {
	ResourceAddress ResourceAddress
	Deployment      ResourceAddress
	PublicIP        ResourceAddress
	Subnet          ResourceAddress
	Backend         netip.AddrPort
	Location        string
	Tags            map[string]string
	CertificateName string
	Certificate     network.HTTPSCertificate `json:"-"`
	certificatePFX  []byte
	password        string
}

type ApplicationGatewayDeploymentStore interface {
	DeployApplicationGateway(context.Context, SubscriptionScope, string, ApplicationGatewayDeployment, bool) (ApplicationGatewayDeploymentResult, error)
	DeleteApplicationGateway(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func (s Server) applicationGatewayResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, path string) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || !network.ValidName(parts[2]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The Application Gateway identifier is invalid.")
		return
	}
	if _, ok := readQuery(w, r, ApplicationGatewayResourceVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: applicationGatewayType + "/" + parts[2]}
	switch r.Method {
	case http.MethodGet:
		gateway, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if gateway == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The Application Gateway does not exist.")
		} else {
			writeJSON(w, http.StatusOK, gateway.view(scope))
		}
	case http.MethodDelete:
		if s.GatewayDeployments == nil {
			unavailable(w)
			return
		}
		operation, err := s.GatewayDeployments.DeleteApplicationGateway(ctx, scope, actor, address)
		if err != nil {
			deploymentError(w, err)
		} else if operation == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			s.acceptOperation(w, scope, *operation)
		}
	default:
		methodNotAllowed(w, "GET, DELETE")
	}
}

type ApplicationGatewayDeploymentResult struct {
	Resource  InventoryResource
	Operation *Operation
	Created   bool
}

func (s Server) applicationGatewayDeployment(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string,
	address ResourceAddress, input deploymentInput, commit bool) {
	desired, err := compileApplicationGateway(scope, address, s.Location, input.Properties.Template, input.Properties.Parameters)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidTemplate", err.Error())
		return
	}
	desired.Certificate, err = network.DecodeHTTPSCertificate(ctx, desired.certificatePFX, desired.password)
	desired.certificatePFX, desired.password = nil, ""
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidCertificate", "The PFX could not provide a valid HTTPS identity.")
		return
	}
	result, err := s.GatewayDeployments.DeployApplicationGateway(ctx, scope, actor, desired, commit)
	if err != nil {
		deploymentError(w, err)
		return
	}
	if !result.Resource.Valid() {
		unavailable(w)
		return
	}
	if commit && result.Operation != nil {
		query := "?api-version=" + resourceAPIVersion
		w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", result.Operation.ID)+query)
		w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+ApplicationGatewayDeploymentVersion)
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		// The pinned deployments SDK accepts 200 and 201 for the initial
		// response and follows Azure-AsyncOperation while the gateway starts.
		writeJSON(w, createdStatus(result.Created), result.Resource.view(scope))
		return
	}
	status := http.StatusOK
	if commit {
		status = createdStatus(result.Created)
	}
	writeJSON(w, status, result.Resource.view(scope))
}

type gatewayTemplate struct {
	Schema         string                      `json:"$schema"`
	ContentVersion string                      `json:"contentVersion"`
	Parameters     map[string]gatewayParameter `json:"parameters"`
	Variables      map[string]string           `json:"variables"`
	Resources      []gatewayTemplateResource   `json:"resources"`
	Outputs        map[string]templateValue    `json:"outputs"`
}

type gatewayParameter struct {
	Type     string `json:"type"`
	Metadata struct {
		Description string `json:"description"`
	} `json:"metadata"`
}

type gatewayTemplateResource struct {
	Type       string               `json:"type"`
	Version    string               `json:"apiVersion"`
	Name       string               `json:"name"`
	Location   string               `json:"location"`
	Tags       map[string]string    `json:"tags"`
	DependsOn  []string             `json:"dependsOn"`
	Zones      []string             `json:"zones"`
	Properties gatewayTemplateProps `json:"properties"`
}

type gatewayConfiguration[T any] struct {
	Name       string `json:"name"`
	Properties T      `json:"properties"`
}

type gatewayBackendPool struct {
	Addresses []struct {
		IP netip.Addr `json:"ipAddress"`
	} `json:"backendAddresses"`
}

type gatewayBackendSettings struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Affinity string `json:"cookieBasedAffinity"`
	Draining struct {
		Enabled bool `json:"enabled"`
		Timeout int  `json:"drainTimeoutInSec"`
	} `json:"connectionDraining"`
}

type gatewayTemplateProps struct {
	BackendPools []gatewayConfiguration[gatewayBackendPool]     `json:"backendAddressPools"`
	BackendHTTP  []gatewayConfiguration[gatewayBackendSettings] `json:"backendHttpSettingsCollection"`
	FrontendIPs  []gatewayConfiguration[struct {
		PublicIP network.ResourceReference `json:"publicIPAddress"`
	}] `json:"frontendIPConfigurations"`
	FrontendPorts []gatewayConfiguration[struct {
		Port string `json:"port"`
	}] `json:"frontendPorts"`
	GatewayIPs []gatewayConfiguration[struct {
		Subnet network.ResourceReference `json:"subnet"`
	}] `json:"gatewayIPConfigurations"`
	Listeners []gatewayConfiguration[struct {
		FrontendIP   network.ResourceReference `json:"frontendIpConfiguration"`
		FrontendPort network.ResourceReference `json:"frontendPort"`
		Protocol     string                    `json:"protocol"`
		Certificate  network.ResourceReference `json:"sslCertificate"`
	}] `json:"httpListeners"`
	Rules []gatewayConfiguration[struct {
		Type     string                    `json:"ruleType"`
		Listener network.ResourceReference `json:"httpListener"`
		Pool     network.ResourceReference `json:"backendAddressPool"`
		Settings network.ResourceReference `json:"backendHttpSettings"`
		Priority int                       `json:"priority"`
	}] `json:"requestRoutingRules"`
	Certificates []gatewayConfiguration[struct {
		Data     string `json:"data"`
		Password string `json:"password"`
	}] `json:"sslCertificates"`
	SKU struct {
		Name     string `json:"name"`
		Tier     string `json:"tier"`
		Capacity int    `json:"capacity"`
	} `json:"sku"`
	PrivateLinks []json.RawMessage `json:"privateLinkConfigurations"`
}

// compileApplicationGateway accepts the single-resource legacy template sent by
// the pinned Azure CLI when its public address and subnet already exist.
func compileApplicationGateway(scope SubscriptionScope, deployment ResourceAddress, location string, raw json.RawMessage,
	supplied map[string]templateValue) (ApplicationGatewayDeployment, error) {
	var desired ApplicationGatewayDeployment
	var template gatewayTemplate
	if len(raw) != 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return desired, errors.New("invalid Application Gateway template")
		}
		raw = json.RawMessage(text)
	}
	if err := strictJSON(bytes.NewReader(raw), &template); err != nil ||
		template.Schema != gatewayTemplateSchema || template.ContentVersion != "1.0.0.0" ||
		len(template.Resources) != 1 || len(template.Outputs) != 1 || len(template.Variables) != 1 ||
		len(template.Parameters) != 1 || len(supplied) != 1 {
		return desired, errors.New("expected the single-resource HTTPS Application Gateway template")
	}
	value, suppliedPassword := supplied["certPassword"]
	password := value.Value
	if template.Parameters["certPassword"].Type != "securestring" || !suppliedPassword || value.Type != "" ||
		password == "" || len(password) > 256 || strings.ContainsAny(password, "\r\n\x00") {
		return desired, errors.New("a bounded secure certificate password is required")
	}
	item := template.Resources[0]
	if item.Type != applicationGatewayType || item.Version != gatewayTemplateAPIVersion || !network.ValidName(item.Name) ||
		item.Location != location || len(item.DependsOn) != 0 || len(item.Zones) != 0 || !validTags(item.Tags) ||
		template.Variables["appGwID"] != fmt.Sprintf("[resourceId('%s', '%s')]", applicationGatewayType, item.Name) ||
		template.Outputs["applicationGateway"] != (templateValue{Type: "object", Value: fmt.Sprintf("[reference('%s')]", item.Name)}) {
		return desired, errors.New("unsupported Application Gateway deployment resource or output")
	}
	properties := item.Properties
	if len(properties.PrivateLinks) != 0 || properties.SKU.Name != "Standard_v2" || properties.SKU.Tier != "Standard_v2" || properties.SKU.Capacity != 2 ||
		len(properties.BackendPools) != 1 || len(properties.BackendHTTP) != 1 || len(properties.FrontendIPs) != 1 ||
		len(properties.FrontendPorts) != 1 || len(properties.GatewayIPs) != 1 || len(properties.Listeners) != 1 ||
		len(properties.Rules) != 1 || len(properties.Certificates) != 1 {
		return desired, errors.New("an Application Gateway requires two instances and one public HTTPS listener and backend")
	}
	pool, backend := properties.BackendPools[0], properties.BackendHTTP[0]
	public, port, gateway := properties.FrontendIPs[0], properties.FrontendPorts[0], properties.GatewayIPs[0]
	listener, rule, certificate := properties.Listeners[0], properties.Rules[0], properties.Certificates[0]
	for _, name := range []string{pool.Name, backend.Name, public.Name, port.Name, gateway.Name, listener.Name, rule.Name, certificate.Name} {
		if !network.ValidName(name) {
			return desired, errors.New("an Application Gateway component name is invalid")
		}
	}
	subresource := func(collection, name string) string {
		return fmt.Sprintf("[concat(variables('appGwID'), '/%s/%s')]", collection, name)
	}
	if port.Properties.Port != "443" || !strings.EqualFold(listener.Properties.Protocol, "https") ||
		listener.Properties.FrontendIP.ID != subresource("frontendIPConfigurations", public.Name) ||
		listener.Properties.FrontendPort.ID != subresource("frontendPorts", port.Name) ||
		listener.Properties.Certificate.ID != subresource("sslCertificates", certificate.Name) ||
		rule.Properties.Type != "Basic" || rule.Properties.Priority < 1 || rule.Properties.Priority > 20000 ||
		rule.Properties.Listener.ID != subresource("httpListeners", listener.Name) ||
		rule.Properties.Pool.ID != subresource("backendAddressPools", pool.Name) ||
		rule.Properties.Settings.ID != subresource("backendHttpSettingsCollection", backend.Name) {
		return desired, errors.New("invalid HTTPS listener or basic Application Gateway routing rule")
	}
	backendPort, err := strconv.ParseUint(backend.Properties.Port, 10, 16)
	if err != nil || backendPort == 0 || strconv.FormatUint(backendPort, 10) != backend.Properties.Port || backend.Properties.Protocol != "Http" ||
		!strings.EqualFold(backend.Properties.Affinity, "disabled") || backend.Properties.Draining.Enabled ||
		backend.Properties.Draining.Timeout != 1 || len(pool.Properties.Addresses) != 1 ||
		!pool.Properties.Addresses[0].IP.Is4() || !pool.Properties.Addresses[0].IP.IsPrivate() {
		return desired, errors.New("the Application Gateway supports one private IPv4 HTTP backend")
	}
	publicIP, validPublic := NetworkResourceAddress(scope, public.Properties.PublicIP.ID, network.PublicIPType)
	subnet, validSubnet := NetworkResourceAddress(scope, gateway.Properties.Subnet.ID, network.SubnetType)
	if !validPublic || !validSubnet || !strings.EqualFold(publicIP.Group, deployment.Group) ||
		!strings.EqualFold(subnet.Group, deployment.Group) {
		return desired, errors.New("the frontend address and subnet must be in the deployment resource group")
	}
	const maxCertificateBytes = 48 << 10
	encoded := certificate.Properties.Data
	if certificate.Properties.Password != "[parameters('certPassword')]" || encoded == "" ||
		len(encoded) > base64.StdEncoding.EncodedLen(maxCertificateBytes) {
		return desired, errors.New("invalid Application Gateway certificate payload")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > maxCertificateBytes || base64.StdEncoding.EncodeToString(data) != encoded {
		return desired, errors.New("invalid Application Gateway certificate encoding")
	}
	return ApplicationGatewayDeployment{
		ResourceAddress: ResourceAddress{Group: deployment.Group, Path: applicationGatewayType + "/" + item.Name},
		Deployment:      deployment, PublicIP: publicIP, Subnet: subnet, Location: location, Tags: item.Tags,
		Backend:         netip.AddrPortFrom(pool.Properties.Addresses[0].IP, uint16(backendPort)),
		CertificateName: certificate.Name, certificatePFX: data, password: password,
	}, nil
}
