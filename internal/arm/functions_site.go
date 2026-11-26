package arm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/network"
)

type FunctionStore interface {
	CreateFunctionSite(context.Context, SubscriptionScope, string, ResourceAddress, ResourceAddress, functions.Site, string, string, string) (InventoryResource, *Operation, bool, error)
	UpdateFunction(context.Context, SubscriptionScope, string, ResourceAddress, string, map[string]string) (*Operation, error)
	GetFunctionSettings(context.Context, SubscriptionScope, ResourceAddress) (map[string]string, error)
	IntegrateFunction(context.Context, SubscriptionScope, string, ResourceAddress, string) (*Operation, error)
	RunFunctionAdmin(context.Context, SubscriptionScope, string, ResourceAddress, functions.AdminRequest) (functions.AdminResult, error)
}

func functionSiteRoute(group string, path []string) (armRoute, bool) {
	if len(path) < 2 || !strings.EqualFold(strings.Join(path[:2], "/"), functions.SiteType) {
		return armRoute{}, false
	}
	return armRoute{collection: "functionSite", group: group, name: strings.Join(path[2:], "/")}, true
}

func (s Server) functionSite(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, path string) {
	if s.Functions == nil {
		unavailable(w)
		return
	}
	version := functions.APIVersion
	if path != "" && !strings.Contains(path, "/") && r.Method == http.MethodGet && r.URL.Query().Get("api-version") == functions.SiteReadAPIVersion {
		version = functions.SiteReadAPIVersion
	}
	_, child, _ := strings.Cut(path, "/")
	query, ok := readQuery(w, r, version, func(name, value string) bool {
		return (path == "" || strings.EqualFold(child, "slots")) && name == "$skiptoken" && value != "" ||
			r.Method == http.MethodDelete && !strings.Contains(path, "/") && name == "deleteEmptyServerFarm" && value == "false"
	})
	if !ok {
		return
	}
	if path == "" {
		s.listFunctionSites(ctx, w, r, scope, reader, group, query)
		return
	}
	name, child, _ := strings.Cut(path, "/")
	if group == "" || !functions.ValidName(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The Functions app identifier is invalid.")
		return
	}
	address := ResourceAddress{Group: group, Path: functions.SiteType + "/" + name}
	switch strings.ToLower(child) {
	case "":
		s.functionSiteResource(ctx, w, r, scope, actor, reader, address, query)
	case "start", "stop", "restart":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.functionLifecycle(ctx, w, scope, actor, address, strings.ToLower(child))
	case "config/slotconfignames":
		s.functionSlotSettings(ctx, w, r, scope, actor, reader, address)
	case "config/web", "config/appsettings", "config/appsettings/list":
		s.functionConfiguration(ctx, w, r, scope, actor, reader, address, strings.ToLower(child))
	case "publishxml":
		s.functionPublishProfile(ctx, w, r, scope, reader, address)
	case "basicpublishingcredentialspolicies/scm":
		s.functionSCMPolicy(ctx, w, r, scope, reader, address)
	case "virtualnetworkconnections":
		s.functionIntegrationList(ctx, w, r, scope, reader, address)
	default:
		lower := strings.ToLower(child)
		if lower == "slots" || strings.HasPrefix(lower, "slots/") {
			s.functionSlot(ctx, w, r, scope, actor, reader, address, child, query)
			return
		}
		if !strings.EqualFold(child, "functions") && !strings.HasPrefix(strings.ToLower(child), "functions/") {
			writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The Functions operation is unsupported.")
			return
		}
		s.functionKeysAndDiscovery(ctx, w, r, scope, actor, reader, address, child)
	}
}

func (s Server) functionSiteResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, address ResourceAddress, query url.Values) {
	switch r.Method {
	case http.MethodGet:
		resource := s.getFunctionSite(ctx, w, scope, reader, address)
		if resource != nil {
			writeJSON(w, http.StatusOK, s.functionSiteView(scope, *resource))
		}
	case http.MethodPut:
		var input functions.Site
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 96<<10), &input); err != nil {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		s.putFunctionSite(ctx, w, scope, actor, address, input)
	case http.MethodDelete:
		if query.Get("deleteEmptyServerFarm") != "false" {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "Set deleteEmptyServerFarm=false to preserve the explicit plan.")
			return
		}
		s.functionLifecycle(ctx, w, scope, actor, address, "delete")
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) putFunctionSite(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string,
	address ResourceAddress, input functions.Site) {
	p := input.Properties
	image := functions.ImageFromFX(p.Config.LinuxFxVersion)
	settings, valid := input.Settings()
	if input.Location != s.Location || input.Kind != functions.SiteKind || !p.Reserved || !p.HTTPSOnly ||
		p.Config.Use32BitWorkerProcess || !p.Config.AlwaysOn || !valid || !validTags(input.Tags) || !functions.ValidImage(image, s.FunctionRegistry) {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	planID := p.ServerFarmID
	if functions.ValidName(planID) {
		planID = (ResourceAddress{Group: address.Group, Path: functions.PlanType + "/" + planID}).ID(scope)
	}
	plan, ok := NetworkResourceAddress(scope, planID, functions.PlanType)
	if !ok || !strings.EqualFold(plan.Group, address.Group) {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	current, err := s.Inventory.GetInventoryResource(ctx, scope, "", address)
	if err != nil {
		containerError(w, err)
		return
	}
	if p.VirtualNetworkSubnetID != "" {
		parent, _, ok := SubnetParent(scope, p.VirtualNetworkSubnetID)
		if !ok || !strings.EqualFold(parent.Group, address.Group) || p.OutboundVNetRouting == nil || !p.OutboundVNetRouting.ApplicationTraffic {
			containerError(w, functions.ErrInvalidSite)
			return
		}
	}
	if len(settings) == 0 && current != nil {
		s.putFunctionIntegration(ctx, w, scope, actor, address, *current, input, planID)
		return
	}
	account, key, valid := functions.ParseHostCredential(settings["AzureWebJobsStorage"], s.StorageSuffix)
	if !valid || len(settings) != 7 || p.Name != "" || p.Enabled != nil || p.ProvisioningState != "" ||
		settings["AzureWebJobsDashboard"] != settings["AzureWebJobsStorage"] ||
		settings["FUNCTIONS_EXTENSION_VERSION"] != "~4" || settings["FUNCTION_APP_EDIT_MODE"] != "readOnly" ||
		settings["DOCKER_CUSTOM_IMAGE_NAME"] != image || settings["WEBSITES_ENABLE_APP_SERVICE_STORAGE"] != "false" ||
		len(settings["MACHINEKEY_DecryptionKey"]) != 64 {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	name, _, _ := address.parts()
	host := name + "." + s.FunctionDomain
	resource, op, _, err := s.Functions.CreateFunctionSite(ctx, scope, actor, address, plan, input, account, key, host)
	if err != nil {
		containerError(w, err)
		return
	}
	s.writeFunctionCreate(w, scope, resource, op)
}

func (s Server) writeFunctionCreate(w http.ResponseWriter, scope SubscriptionScope, resource InventoryResource, op *Operation) {
	status := http.StatusOK
	if op != nil && op.Status != OperationSucceeded {
		status = http.StatusAccepted
		query := "?api-version=" + resourceAPIVersion
		w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", op.ID)+query)
		w.Header().Set("Location", s.Origin+resource.Address.ID(scope)+"?api-version="+functions.APIVersion)
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, status, s.functionSiteView(scope, resource))
}

func (s Server) getFunctionSite(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader string, address ResourceAddress) *InventoryResource {
	resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
	if err != nil {
		inventoryError(w, err)
	} else if resource == nil || resource.Kind != functions.SiteKind {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The Functions app does not exist.")
	} else {
		return resource
	}
	return nil
}

func (s Server) functionLifecycle(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string,
	address ResourceAddress, action string) {
	op, err := s.Containers.MutateContainerGroup(ctx, scope, actor, address, action)
	if err == nil {
		err = AwaitOperation(ctx, s.Operations, scope, op)
	}
	if err != nil {
		containerError(w, err)
		return
	}
	if action == "delete" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s Server) listFunctionSites(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader, group string, query url.Values) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	search, valid := inventoryQuery(query, group)
	if !valid {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The Functions continuation is invalid.")
		return
	}
	search.Type = functions.SiteType
	resources, err := s.Inventory.ListInventoryResources(ctx, scope, reader, search, inventoryPageSize+1)
	if err != nil {
		inventoryError(w, err)
		return
	}
	count := min(len(resources), inventoryPageSize)
	items := make([]map[string]any, 0, count)
	for _, item := range resources[:count] {
		items = append(items, s.functionSiteView(scope, item))
	}
	reply := map[string]any{"value": items}
	if len(resources) > count {
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(resources[count-1].Address.Key())))
		reply["nextLink"] = s.Origin + r.URL.EscapedPath() + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, reply)
}

func (s Server) functionConfiguration(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, address ResourceAddress, path string) {
	resource := s.getFunctionSite(ctx, w, scope, reader, address)
	if resource == nil {
		return
	}
	if path == "config/web" {
		s.functionWebConfig(ctx, w, r, scope, actor, *resource)
		return
	}
	expected := http.MethodPost
	if path == "config/appsettings" {
		expected = http.MethodPut
	}
	if r.Method != expected {
		methodNotAllowed(w, expected)
		return
	}
	settings, err := s.Functions.GetFunctionSettings(ctx, scope, address)
	if err != nil {
		containerError(w, err)
		return
	}
	platform := []string{"FUNCTIONS_EXTENSION_VERSION", "DOCKER_CUSTOM_IMAGE_NAME", "FUNCTION_APP_EDIT_MODE", "WEBSITES_ENABLE_APP_SERVICE_STORAGE"}
	if s.FunctionPackages != nil {
		settings["SCM_DO_BUILD_DURING_DEPLOYMENT"] = "false"
		platform = append(platform, "SCM_DO_BUILD_DURING_DEPLOYMENT")
	}
	if expected == http.MethodPut {
		var input functions.Settings
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 48<<10), &input); err != nil || input.Properties == nil {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		user := maps.Clone(input.Properties)
		for _, key := range platform {
			value, present := user[key]
			if value != settings[key] && (key != "SCM_DO_BUILD_DURING_DEPLOYMENT" || present) {
				containerError(w, functions.ErrInvalidSite)
				return
			}
			delete(user, key)
		}
		if registry, ok := user["DOCKER_REGISTRY_SERVER_URL"]; ok {
			host, _, _ := strings.Cut(settings["DOCKER_CUSTOM_IMAGE_NAME"], "/")
			hostWithoutPort, _, _ := net.SplitHostPort(host)
			if registry != "https://"+host && (hostWithoutPort == "" || registry != "https://"+hostWithoutPort) {
				containerError(w, functions.ErrInvalidSite)
				return
			}
			delete(user, "DOCKER_REGISTRY_SERVER_URL")
		}
		if !functions.ValidSettings(user) {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		op, err := s.Functions.UpdateFunction(ctx, scope, actor, address, "", user)
		if err == nil {
			err = AwaitOperation(ctx, s.Operations, scope, op)
		}
		if err != nil {
			containerError(w, err)
			return
		}
		settings = input.Properties
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, functions.Settings{Properties: settings})
}

func functionSiteDetails(resource InventoryResource) (functions.SiteProperties, error) {
	var value functions.SiteProperties
	err := json.Unmarshal(resource.Properties, &value)
	return value, err
}

func (s Server) functionWebConfig(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor string, resource InventoryResource) {
	props, err := functionSiteDetails(resource)
	if err != nil {
		unavailable(w)
		return
	}
	id := resource.Address.ID(scope) + "/config/web"
	switch r.Method {
	case http.MethodGet:
	case http.MethodPatch:
		var body struct {
			ID         string `json:"id,omitempty"`
			Name       string `json:"name,omitempty"`
			Type       string `json:"type,omitempty"`
			Properties struct {
				LinuxFxVersion        string `json:"linuxFxVersion"`
				AlwaysOn              *bool  `json:"alwaysOn,omitempty"`
				Use32BitWorkerProcess bool   `json:"use32BitWorkerProcess,omitempty"`
			} `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 32<<10), &body); err != nil ||
			body.ID != "" && !strings.EqualFold(body.ID, id) || body.Name != "" && body.Name != "web" ||
			body.Type != "" && !strings.EqualFold(body.Type, functions.SiteType+"/config") ||
			body.Properties.AlwaysOn != nil && !*body.Properties.AlwaysOn || body.Properties.Use32BitWorkerProcess {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		image := functions.ImageFromFX(body.Properties.LinuxFxVersion)
		if !functions.ValidImage(image, s.FunctionRegistry) {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		op, err := s.Functions.UpdateFunction(ctx, scope, actor, resource.Address, image, nil)
		if err == nil {
			err = AwaitOperation(ctx, s.Operations, scope, op)
		}
		if err != nil {
			containerError(w, err)
			return
		}
		props.Config.LinuxFxVersion = body.Properties.LinuxFxVersion
	default:
		methodNotAllowed(w, "GET, PATCH")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": "web", "type": functions.SiteType + "/config", "properties": props.Config})
}

func (s Server) functionIntegrationList(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, address ResourceAddress) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	resource := s.getFunctionSite(ctx, w, scope, reader, address)
	if resource == nil {
		return
	}
	props, err := functionSiteDetails(*resource)
	if err != nil {
		unavailable(w)
		return
	}
	items := []any{}
	if subnet, ok := NetworkResourceAddress(scope, props.VirtualNetworkSubnetID, network.SubnetType); ok {
		parent, name, _ := SubnetParent(scope, props.VirtualNetworkSubnetID)
		items = append(items, map[string]any{"id": address.ID(scope) + "/virtualNetworkConnections/" + name, "name": name,
			"type": functions.SiteType + "/virtualNetworkConnections", "properties": map[string]string{
				"vnetResourceId": parent.ID(scope), "subnetResourceId": subnet.ID(scope)}})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s Server) putFunctionIntegration(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string,
	address ResourceAddress, current InventoryResource, input functions.Site, planID string) {
	props, err := functionSiteDetails(current)
	if err != nil {
		unavailable(w)
		return
	}
	wanted := input.Properties
	if props.ServerFarmID != planID || props.Config.LinuxFxVersion != wanted.Config.LinuxFxVersion ||
		!maps.Equal(current.Tags, input.Tags) || wanted.VirtualNetworkSubnetID == "" ||
		wanted.Name != "" && wanted.Name != props.Name || wanted.Enabled != nil && (props.Enabled == nil || *wanted.Enabled != *props.Enabled) ||
		wanted.ProvisioningState != "" && wanted.ProvisioningState != props.ProvisioningState {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	op, err := s.Functions.IntegrateFunction(ctx, scope, actor, address, input.Properties.VirtualNetworkSubnetID)
	if err == nil {
		err = AwaitOperation(ctx, s.Operations, scope, op)
	}
	if err != nil {
		containerError(w, err)
		return
	}
	updated := s.getFunctionSite(ctx, w, scope, "", address)
	if updated != nil {
		writeJSON(w, http.StatusOK, s.functionSiteView(scope, *updated))
	}
}

func functionNativeError(w http.ResponseWriter, status int) {
	if status == http.StatusNotFound {
		writeError(w, status, "FunctionNotFound", "The Function or key does not exist.")
	} else {
		unavailable(w)
	}
}

func (s Server) functionSiteView(scope SubscriptionScope, resource InventoryResource) map[string]any {
	view := resource.view(scope)
	host, _, _ := resource.Address.parts()
	if app, slot, ok := functions.SlotNames(resource.Address.Path); ok {
		view["name"] = app + "/" + slot
		host = app + "-" + slot
	}
	var properties map[string]any
	if json.Unmarshal(resource.Properties, &properties) == nil && properties != nil {
		properties["sku"] = "Basic"
		if s.FunctionPackages != nil && s.FunctionSCMDomain != "" {
			properties["hostNameSslStates"] = []map[string]string{{"name": host + "." + s.FunctionSCMDomain,
				"hostType": "Repository", "sslState": "Disabled"}}
		}
		view["properties"] = properties
	}
	return view
}

func (s Server) functionPublishProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, address ResourceAddress) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var input struct {
		Format string `json:"format"`
	}
	if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err != nil || input.Format != "WebDeploy" {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	if resource := s.getFunctionSite(ctx, w, scope, reader, address); resource == nil {
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<publishData><publishProfile profileName="OCI image" publishMethod="ContainerImage"/></publishData>`))
}
