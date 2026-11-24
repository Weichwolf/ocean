package arm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

type NetworkStore interface {
	ChangeInventoryResource(context.Context, SubscriptionScope, ResourceAddress, string, string, string,
		func(*InventoryResource, ResourceAddress) (*InventoryResource, error)) (*InventoryResource, bool, error)
}

const virtualNetworkType = "Microsoft.Network/virtualNetworks"

type networkPath struct {
	VNet   string
	Subnet string
	Child  bool
}

func parseNetworkPath(path string) (networkPath, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 || !strings.EqualFold(strings.Join(parts[:2], "/"), virtualNetworkType) {
		return networkPath{}, false
	}
	switch len(parts) {
	case 2:
		return networkPath{}, true
	case 3:
		return networkPath{VNet: parts[2]}, network.ValidName(parts[2])
	case 4, 5:
		if !network.ValidName(parts[2]) || !strings.EqualFold(parts[3], "subnets") {
			return networkPath{}, false
		}
		path := networkPath{VNet: parts[2], Child: true}
		if len(parts) == 5 {
			path.Subnet = parts[4]
			return path, network.ValidName(path.Subnet)
		}
		return path, true
	}
	return networkPath{}, false
}

func (p networkPath) version() string {
	if p.Child {
		return network.SubnetAPIVersion
	}
	return network.VNetAPIVersion
}

func networkAction(method string, path networkPath) string {
	action := virtualNetworkType
	if path.Child {
		action += "/subnets"
	}
	if method == http.MethodDelete {
		return action + "/delete"
	}
	return action + "/write"
}

func (s Server) network(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, rawPath string) {
	path, ok := parseNetworkPath(rawPath)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The virtual network or subnet identifier is invalid.")
		return
	}
	collection := path.VNet == "" || path.Child && path.Subnet == ""
	query, ok := readQuery(w, r, path.version(), func(key, value string) bool {
		return key == "$skiptoken" && value != "" && path.VNet == "" && r.Method == http.MethodGet
	})
	if !ok {
		return
	}
	if collection && r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if path.VNet == "" {
		s.listNetworkResources(ctx, w, scope, reader, group, virtualNetworkType, query)
		return
	}
	address := ResourceAddress{Group: group, Path: virtualNetworkType + "/" + path.VNet}
	switch r.Method {
	case http.MethodGet:
		resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
			return
		}
		if resource == nil {
			writeError(w, http.StatusNotFound, "VirtualNetworkNotFound", "The virtual network could not be found.")
			return
		}
		if !path.Child {
			writeJSON(w, http.StatusOK, resource.view(scope))
			return
		}
		properties, err := storedNetwork(resource)
		if err != nil {
			unavailable(w)
			return
		}
		if path.Subnet == "" {
			writeJSON(w, http.StatusOK, map[string]any{"value": properties.Subnets})
			return
		}
		if index := properties.SubnetIndex(path.Subnet); index >= 0 {
			writeJSON(w, http.StatusOK, properties.Subnets[index])
			return
		}
		writeError(w, http.StatusNotFound, "SubnetNotFound", "The subnet could not be found.")
	case http.MethodPut, http.MethodDelete:
		s.changeNetwork(ctx, w, r, scope, actor, address, path)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) listNetworkResources(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader, group, resourceType string, query url.Values) {
	search, ok := inventoryQuery(query, group)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The network continuation is invalid.")
		return
	}
	search.Type = resourceType
	resources, err := s.Inventory.ListInventoryResources(ctx, scope, reader, search, inventoryPageSize+1)
	if err != nil {
		inventoryError(w, err)
		return
	}
	count := min(len(resources), inventoryPageSize)
	items := make([]map[string]any, 0, count)
	for _, item := range resources[:count] {
		items = append(items, item.view(scope))
	}
	response := map[string]any{"value": items}
	if len(resources) > count {
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(resources[count-1].Address.Key())))
		path := "/subscriptions/" + scope.SubscriptionID
		if group != "" {
			path += "/resourceGroups/" + url.PathEscape(group)
		}
		response["nextLink"] = s.Origin + path + "/providers/" + resourceType + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

type vnetInput struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		Space                network.AddressSpace `json:"addressSpace"`
		Subnets              []subnetInput        `json:"subnets"`
		EnableDDoSProtection bool                 `json:"enableDdosProtection"`
		EnableVMProtection   bool                 `json:"enableVmProtection"`
	} `json:"properties"`
}

type subnetInput struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Type       string                   `json:"type"`
	Properties network.SubnetProperties `json:"properties"`
}

type invalidNetwork struct{ message string }

func (e invalidNetwork) Error() string { return e.message }

var errVirtualNetworkMissing = errors.New("virtual network not found")

func (s Server) changeNetwork(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor string, address ResourceAddress, path networkPath) {
	var requested vnetInput
	var child subnetInput
	if r.Method == http.MethodPut {
		var input any = &requested
		if path.Child {
			input = &child
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The network request contains an unsupported field or value.")
			return
		}
		if path.Child && child.Name != "" && !strings.EqualFold(child.Name, path.Subnet) ||
			!path.Child && (!strings.EqualFold(requested.Location, s.Location) || !validTags(requested.Tags) ||
				requested.Properties.EnableDDoSProtection || requested.Properties.EnableVMProtection) {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The requested network location, name, tags, or protection policy is unsupported.")
			return
		}
		if path.Child {
			child.Name = path.Subnet
		}
	}
	deleting := r.Method == http.MethodDelete
	var createdChild bool
	resource, created, err := s.Networks.ChangeInventoryResource(ctx, scope, address, actor, networkAction(r.Method, path), childPath(path),
		func(current *InventoryResource, canonical ResourceAddress) (*InventoryResource, error) {
			if deleting && !path.Child {
				return nil, nil
			}
			if current == nil && path.Child {
				return nil, errVirtualNetworkMissing
			}
			properties, err := storedNetwork(current)
			if err != nil {
				return nil, err
			}
			result := InventoryResource{Address: canonical, APIVersion: network.VNetAPIVersion, Location: s.Location, ProvisioningState: "Succeeded"}
			if current != nil {
				result.Tags = current.Tags
			}
			if path.Child {
				index := properties.SubnetIndex(path.Subnet)
				createdChild = index < 0
				if deleting {
					if index >= 0 {
						properties.Subnets = slices.Delete(properties.Subnets, index, index+1)
					}
				} else {
					if err := upsertSubnet(&properties, canonical.ID(scope), child); err != nil {
						return nil, err
					}
				}
			} else {
				result.Tags = requested.Tags
				properties.AddressSpace = requested.Properties.Space
				seen := make(map[string]bool)
				for _, subnet := range requested.Properties.Subnets {
					name := strings.ToLower(subnet.Name)
					if seen[name] || !network.ValidName(subnet.Name) {
						return nil, invalidNetwork{"subnet names must be valid and unique within a virtual network"}
					}
					seen[name] = true
					if err := upsertSubnet(&properties, canonical.ID(scope), subnet); err != nil {
						return nil, err
					}
				}
			}
			if err := properties.Validate(); err != nil {
				return nil, invalidNetwork{err.Error()}
			}
			result.Properties, _ = json.Marshal(properties)
			return &result, nil
		})
	var invalid invalidNetwork
	switch {
	case deleting && (errors.Is(err, ErrGroupMissing) || errors.Is(err, errVirtualNetworkMissing)):
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, errVirtualNetworkMissing):
		writeError(w, http.StatusNotFound, "VirtualNetworkNotFound", "The virtual network could not be found.")
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, "InvalidAddressPrefix", invalid.message)
	case err != nil:
		inventoryError(w, err)
	case deleting:
		w.WriteHeader(http.StatusNoContent)
	case path.Child:
		properties, err := storedNetwork(resource)
		index := properties.SubnetIndex(path.Subnet)
		if err != nil || index < 0 {
			unavailable(w)
			return
		}
		writeJSON(w, createdStatus(createdChild), properties.Subnets[index])
	default:
		writeJSON(w, createdStatus(created), resource.view(scope))
	}
}

func createdStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

func childPath(path networkPath) string {
	if path.Child {
		return "/subnets/" + path.Subnet
	}
	return ""
}

func storedNetwork(resource *InventoryResource) (network.VNetProperties, error) {
	properties := network.VNetProperties{ProvisioningState: "Succeeded", Subnets: []network.Subnet{}}
	if resource != nil {
		if err := json.Unmarshal(resource.Properties, &properties); err != nil {
			return network.VNetProperties{}, err
		}
	}
	return properties, nil
}

func upsertSubnet(properties *network.VNetProperties, parentID string, requested subnetInput) error {
	index := properties.SubnetIndex(requested.Name)
	if requested.ID != "" || requested.Type != "" || requested.Properties.ProvisioningState != "" {
		if index < 0 {
			return invalidNetwork{"a new subnet cannot specify existing resource fields"}
		}
		existing := properties.Subnets[index]
		if requested.ID != "" && !strings.EqualFold(requested.ID, existing.ID) ||
			requested.Type != "" && !strings.EqualFold(requested.Type, existing.Type) ||
			requested.Properties.ProvisioningState != "" && requested.Properties.ProvisioningState != existing.Properties.ProvisioningState {
			return invalidNetwork{"subnet resource fields must match the existing resource"}
		}
	}
	if index >= 0 {
		properties.Subnets[index] = network.NewSubnet(parentID, properties.Subnets[index].Name, requested.Properties)
	} else {
		properties.Subnets = append(properties.Subnets, network.NewSubnet(parentID, requested.Name, requested.Properties))
	}
	return nil
}
