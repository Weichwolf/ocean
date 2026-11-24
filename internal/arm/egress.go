package arm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

func egressResourceType(name string) string {
	if strings.EqualFold(name, "publicIPAddresses") {
		return network.PublicIPType
	}
	if strings.EqualFold(name, "natGateways") {
		return network.NATGatewayType
	}
	return ""
}

type egressInput[T any] struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	SKU        ResourceSKU       `json:"sku"`
	Properties T                 `json:"properties"`
}

func (s Server) egressResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, rawPath string) {
	path := strings.Split(rawPath, "/")
	if len(path) < 2 || len(path) > 3 || len(path) == 3 && !network.ValidName(path[2]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The public IP address or NAT gateway identifier is invalid.")
		return
	}
	kind := egressResourceType(path[1])
	version := network.PublicIPAPIVersion
	if kind == network.NATGatewayType {
		version = network.NATAPIVersion
	}
	query, ok := readQuery(w, r, version, func(key, value string) bool {
		return key == "$skiptoken" && value != "" && len(path) == 2 && r.Method == http.MethodGet
	})
	if !ok {
		return
	}
	if len(path) == 2 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		s.listNetworkResources(ctx, w, scope, reader, group, kind, query)
		return
	}
	address := ResourceAddress{Group: group, Path: kind + "/" + path[2]}
	switch r.Method {
	case http.MethodGet:
		resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
			return
		}
		if resource == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The requested network resource does not exist.")
			return
		}
		writeJSON(w, http.StatusOK, resource.view(scope))
	case http.MethodPut, http.MethodDelete:
		s.changeEgressResource(ctx, w, r, scope, actor, address, kind, version)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) changeEgressResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor string, address ResourceAddress, kind, version string) {
	deleting := r.Method == http.MethodDelete
	var desired *InventoryResource
	if !deleting {
		var err error
		desired, err = s.readEgressRequest(http.MaxBytesReader(w, r.Body, 128<<10), scope, address, kind, version)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error())
			return
		}
	}
	action := egressAction(r.Method, kind)
	resource, created, err := s.Networks.ChangeInventoryResource(ctx, scope, address, actor, action, "",
		func(current *InventoryResource, canonical ResourceAddress) (*InventoryResource, error) {
			if deleting {
				return nil, nil
			}
			update := *desired
			update.Address = canonical
			if current != nil && kind == network.PublicIPType {
				if err := retainPublicIPAddress(*current, &update); err != nil {
					return nil, err
				}
			}
			return &update, nil
		})
	switch {
	case deleting && errors.Is(err, ErrGroupMissing):
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
	case errors.Is(err, ErrPublicIPPoolDisabled):
		writeError(w, http.StatusServiceUnavailable, "PublicIPPoolUnavailable", err.Error())
	case errors.Is(err, ErrPublicIPPoolExhausted):
		writeError(w, http.StatusConflict, "PublicIPPoolExhausted", err.Error())
	case errors.Is(err, ErrPublicIPInUse):
		writeError(w, http.StatusConflict, "PublicIPAddressInUse", err.Error())
	case errors.Is(err, ErrLinkedResourceInUse):
		writeError(w, http.StatusConflict, "ResourceInUse", err.Error())
	case errors.Is(err, ErrLinkedResourceMissing):
		writeError(w, http.StatusBadRequest, "InvalidResourceReference", err.Error())
	case err != nil:
		inventoryError(w, err)
	case deleting:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, createdStatus(created), resource.view(scope))
	}
}

func retainPublicIPAddress(current InventoryResource, update *InventoryResource) error {
	var previous, requested network.PublicIPAddressProperties
	if err := json.Unmarshal(current.Properties, &previous); err != nil {
		return err
	}
	if err := json.Unmarshal(update.Properties, &requested); err != nil {
		return err
	}
	requested.Address = previous.Address
	update.Properties, _ = json.Marshal(requested)
	return nil
}

func (s Server) readEgressRequest(body io.Reader, scope SubscriptionScope, address ResourceAddress, kind, version string) (*InventoryResource, error) {
	result := &InventoryResource{Address: address, APIVersion: version, Location: s.Location, ProvisioningState: "Succeeded"}
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if kind == network.PublicIPType {
		var input egressInput[network.PublicIPAddressProperties]
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("the public IP request contains an unsupported field or value")
		}
		p := input.Properties
		if !strings.EqualFold(input.Location, s.Location) || !validTags(input.Tags) ||
			input.SKU.Name != "Standard" || input.SKU.Tier != "" && input.SKU.Tier != "Regional" ||
			p.AllocationMethod != "Static" || p.IPVersion != "IPv4" || p.Address != "" || p.ProvisioningState != "" ||
			p.IdleTimeout != 0 && p.IdleTimeout != 4 {
			return nil, errors.New("the supported public IP is a regional Standard static IPv4 address with a four-minute idle timeout")
		}
		p.IdleTimeout, p.ProvisioningState = 4, "Succeeded"
		result.Tags, result.SKU = input.Tags, ResourceSKU{Name: "Standard", Tier: "Regional"}
		result.Properties, _ = json.Marshal(p)
		return result, nil
	}
	var input egressInput[network.NATGatewayProperties]
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("the NAT gateway request contains an unsupported field or value")
	}
	p := input.Properties
	if !strings.EqualFold(input.Location, s.Location) || !validTags(input.Tags) ||
		input.SKU.Name != "Standard" || input.SKU.Tier != "" || len(p.PublicIPAddresses) != 1 || p.ProvisioningState != "" ||
		p.IdleTimeout != 0 && p.IdleTimeout != 4 {
		return nil, errors.New("the supported Standard NAT gateway uses one regional static IPv4 address and a four-minute idle timeout")
	}
	ref, err := networkReference(scope, address.Group, network.PublicIPType, &p.PublicIPAddresses[0], false)
	if err != nil {
		return nil, err
	}
	p.IdleTimeout, p.ProvisioningState = 4, "Succeeded"
	result.Tags, result.SKU = input.Tags, ResourceSKU{Name: "Standard"}
	result.References = []ResourceAddress{ref}
	result.Properties, _ = json.Marshal(p)
	return result, nil
}

func egressAction(method, kind string) string {
	if method == http.MethodDelete {
		return kind + "/delete"
	}
	return kind + "/write"
}
