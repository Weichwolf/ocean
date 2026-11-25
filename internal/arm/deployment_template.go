package arm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

const deploymentSchema = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"

type templateParameter struct {
	Type         string  `json:"type"`
	DefaultValue *string `json:"defaultValue"`
	MinLength    int     `json:"minLength"`
	MaxLength    int     `json:"maxLength"`
}

type templateValue struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

type templateResource struct {
	Type       string            `json:"type"`
	APIVersion string            `json:"apiVersion"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	SKU        ResourceSKU       `json:"sku"`
	Properties json.RawMessage   `json:"properties"`
	DependsOn  []string          `json:"dependsOn"`
}

type networkTemplate struct {
	Schema         string                       `json:"$schema"`
	ContentVersion string                       `json:"contentVersion"`
	Metadata       json.RawMessage              `json:"metadata"`
	Parameters     map[string]templateParameter `json:"parameters"`
	Resources      []templateResource           `json:"resources"`
	Outputs        map[string]templateValue     `json:"outputs"`
}

type deploymentChange struct {
	ResourceID string         `json:"resourceId"`
	ChangeType string         `json:"changeType"`
	Before     map[string]any `json:"before,omitempty"`
	After      map[string]any `json:"after,omitempty"`
}

type NetworkDeployment struct {
	Address  ResourceAddress
	location string
	scope    SubscriptionScope
	items    []templateResource
	outputs  map[string]templateValue
}

type NetworkDeploymentPlan struct {
	Resources []InventoryResource
	changes   []deploymentChange
}

func strictJSON(input io.Reader, target any) error {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("unexpected content after JSON object")
	}
	return nil
}

func compileNetworkTemplate(scope SubscriptionScope, address ResourceAddress, location string, raw json.RawMessage, supplied map[string]templateValue) (NetworkDeployment, error) {
	var template networkTemplate
	if len(raw) != 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return NetworkDeployment{}, err
		}
		raw = json.RawMessage(text)
	}
	if err := strictJSON(bytes.NewReader(raw), &template); err != nil {
		return NetworkDeployment{}, err
	}
	if template.Schema != deploymentSchema || template.ContentVersion != "1.0.0.0" ||
		len(template.Resources) == 0 || len(template.Resources) > 8 || len(template.Parameters) > 16 || len(template.Outputs) > 16 {
		return NetworkDeployment{}, errors.New("the template must be an ARM resource-group network template with up to eight resources")
	}
	bindings := templateBindings{scope: scope, group: address.Group, location: location}
	parameters := make(map[string]string, len(template.Parameters))
	for name, value := range supplied {
		if _, ok := template.Parameters[name]; !ok || value.Type != "" {
			return NetworkDeployment{}, errors.New("unexpected deployment parameter")
		}
	}
	for name, parameter := range template.Parameters {
		value, ok := supplied[name]
		if !ok && parameter.DefaultValue != nil {
			resolved, err := bindings.evaluate(*parameter.DefaultValue)
			if err != nil {
				return NetworkDeployment{}, err
			}
			value.Value, ok = resolved, true
		}
		if !ok || parameter.Type != "string" || len(value.Value) > 256 ||
			parameter.MinLength < 0 || len(value.Value) < parameter.MinLength ||
			parameter.MaxLength < 0 || parameter.MaxLength != 0 && len(value.Value) > parameter.MaxLength {
			return NetworkDeployment{}, fmt.Errorf("missing or unsupported string parameter %q", name)
		}
		parameters[name] = value.Value
	}
	bindings.parameters = parameters
	resources := make(map[string]int, len(template.Resources))
	for index := range template.Resources {
		item := &template.Resources[index]
		var err error
		item.Name, err = bindings.evaluate(item.Name)
		if err != nil {
			return NetworkDeployment{}, err
		}
		resolved, err := networkTemplateAddress(address.Group, item.Type, item.Name)
		if err != nil {
			return NetworkDeployment{}, err
		}
		id := strings.ToLower(resolved.ID(scope))
		if _, exists := resources[id]; exists {
			return NetworkDeployment{}, errors.New("the template lists the same resource more than once")
		}
		resources[id] = index
		item.Location, err = bindings.evaluate(item.Location)
		if err != nil {
			return NetworkDeployment{}, err
		}
		var properties any
		decoder := json.NewDecoder(bytes.NewReader(item.Properties))
		decoder.UseNumber()
		if err := decoder.Decode(&properties); err != nil {
			return NetworkDeployment{}, err
		}
		if _, ok := properties.(map[string]any); !ok {
			return NetworkDeployment{}, errors.New("network template resource properties must be an object")
		}
		properties, err = bindings.resolve(properties, 0)
		if err != nil {
			return NetworkDeployment{}, err
		}
		item.Properties, _ = json.Marshal(properties)
		for key, value := range item.Tags {
			item.Tags[key], err = bindings.evaluate(value)
			if err != nil {
				return NetworkDeployment{}, err
			}
		}
		if len(item.DependsOn) > 8 {
			return NetworkDeployment{}, errors.New("resource dependency limit exceeded")
		}
		for index, dependency := range item.DependsOn {
			value, err := bindings.evaluate(dependency)
			if err != nil {
				return NetworkDeployment{}, err
			}
			item.DependsOn[index] = strings.ToLower(value)
		}
		if item.Type == network.SubnetType {
			item.DependsOn = append(item.DependsOn, strings.ToLower((ResourceAddress{Group: address.Group,
				Path: strings.Split(resolved.Path, "/subnets/")[0]}).ID(scope)))
		}
	}
	ordered, err := orderNetworkTemplate(template.Resources, resources)
	if err != nil {
		return NetworkDeployment{}, err
	}
	for name, output := range template.Outputs {
		if output.Type != "string" {
			return NetworkDeployment{}, errors.New("only string deployment outputs are supported")
		}
		value, err := bindings.evaluate(output.Value)
		if err != nil {
			return NetworkDeployment{}, err
		}
		template.Outputs[name] = templateValue{Type: "String", Value: value}
	}
	return NetworkDeployment{Address: address, location: location, scope: scope, items: ordered, outputs: template.Outputs}, nil
}

func (b templateBindings) resolve(value any, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("network template properties are too deeply nested")
	}
	switch item := value.(type) {
	case string:
		return b.evaluate(item)
	case []any:
		for index, child := range item {
			next, err := b.resolve(child, depth+1)
			if err != nil {
				return nil, err
			}
			item[index] = next
		}
	case map[string]any:
		for key, child := range item {
			next, err := b.resolve(child, depth+1)
			if err != nil {
				return nil, err
			}
			item[key] = next
		}
	}
	return value, nil
}

func orderNetworkTemplate(items []templateResource, resources map[string]int) ([]templateResource, error) {
	var ordered []templateResource
	visited := make(map[int]bool)
	for len(ordered) < len(items) {
		count := len(ordered)
		for index, item := range items {
			if visited[index] {
				continue
			}
			ready := true
			for _, dependency := range item.DependsOn {
				target, ok := resources[dependency]
				if !ok {
					return nil, errors.New("deployment dependency must name a resource in this template")
				}
				ready = ready && visited[target]
			}
			if ready {
				ordered = append(ordered, item)
				visited[index] = true
			}
		}
		if len(ordered) == count {
			return nil, errors.New("the template contains a dependency cycle")
		}
	}
	return ordered, nil
}

func networkTemplateAddress(group, kind, name string) (ResourceAddress, error) {
	var path string
	switch kind {
	case virtualNetworkType, network.PublicIPType, network.NATGatewayType:
		if network.ValidName(name) {
			path = kind + "/" + name
		}
	case network.SubnetType:
		parent, child, ok := strings.Cut(name, "/")
		if ok && network.ValidName(parent) && network.ValidName(child) {
			path = virtualNetworkType + "/" + parent + "/subnets/" + child
		}
	}
	if path == "" {
		return ResourceAddress{}, fmt.Errorf("unsupported deployment resource type or name for %q", kind)
	}
	return ResourceAddress{Group: group, Path: path}, nil
}

func deploymentInventoryAddress(address ResourceAddress) ResourceAddress {
	address.Path, _, _ = strings.Cut(address.Path, "/subnets/")
	return address
}

func (t NetworkDeployment) Addresses() []ResourceAddress {
	result := []ResourceAddress{t.Address}
	seen := make(map[string]bool)
	for _, item := range t.items {
		address, _ := networkTemplateAddress(t.Address.Group, item.Type, item.Name)
		address = deploymentInventoryAddress(address)
		if !seen[address.Key()] {
			seen[address.Key()] = true
			result = append(result, address)
		}
	}
	return result
}

func (t NetworkDeployment) Plan(group string, snapshot map[string]InventoryResource) (NetworkDeploymentPlan, error) {
	working := make(map[string]InventoryResource, len(snapshot))
	for key, resource := range snapshot {
		working[key] = resource
	}
	var plan NetworkDeploymentPlan
	var references []network.ResourceReference
	for _, item := range t.items {
		address, _ := networkTemplateAddress(group, item.Type, item.Name)
		parent := deploymentInventoryAddress(address)
		current, exists := working[parent.Key()]
		if exists {
			parent = current.Address
		}
		before, after, next, err := t.project(item, parent, current, exists)
		if err != nil {
			return NetworkDeploymentPlan{}, err
		}
		working[parent.Key()] = next
		resourceID, ok := after["id"].(string)
		if !ok || resourceID == "" {
			return NetworkDeploymentPlan{}, fmt.Errorf("missing resource ID for %s %q", item.Type, item.Name)
		}
		references = append(references, network.ResourceReference{ID: resourceID})
		change := deploymentChange{ResourceID: resourceID, Before: before, After: after, ChangeType: "Modify"}
		if before == nil {
			change.ChangeType = "Create"
		} else if reflect.DeepEqual(before, after) {
			change.ChangeType = "NoChange"
		}
		plan.changes = append(plan.changes, change)
	}
	addresses := t.Addresses()
	for _, address := range addresses[1:] {
		resource := working[address.Key()]
		if strings.HasPrefix(resource.Address.Path, virtualNetworkType+"/") {
			properties, err := storedNetwork(&resource)
			if err != nil {
				return NetworkDeploymentPlan{}, err
			}
			if err := properties.Validate(); err != nil {
				return NetworkDeploymentPlan{}, err
			}
		}
		plan.Resources = append(plan.Resources, resource)
	}
	t.Address.Group = group
	if previous, ok := snapshot[t.Address.Key()]; ok {
		t.Address = previous.Address
	}
	properties, _ := json.Marshal(map[string]any{"provisioningState": "Succeeded", "mode": "Incremental",
		"outputs": t.outputs, "outputResources": references})
	plan.Resources = append(plan.Resources, InventoryResource{Address: t.Address, Location: t.location, APIVersion: deploymentAPIVersion,
		Properties: properties, ProvisioningState: "Succeeded"})
	return plan, nil
}

func (t NetworkDeployment) project(item templateResource, address ResourceAddress, current InventoryResource, exists bool) (map[string]any, map[string]any, InventoryResource, error) {
	var before map[string]any
	if exists {
		before = current.view(t.scope)
	}
	if item.Type == network.PublicIPType || item.Type == network.NATGatewayType {
		wantVersion := network.PublicIPAPIVersion
		if item.Type == network.NATGatewayType {
			wantVersion = network.NATAPIVersion
		}
		if item.APIVersion != wantVersion {
			return nil, nil, InventoryResource{}, errors.New("unsupported network resource API version")
		}
		body, _ := json.Marshal(egressInput[json.RawMessage]{Location: item.Location, Tags: item.Tags, SKU: item.SKU, Properties: item.Properties})
		desired, err := (Server{Location: t.location}).readEgressRequest(bytes.NewReader(body), t.scope, address, item.Type, item.APIVersion)
		if err != nil {
			return nil, nil, InventoryResource{}, err
		}
		if exists && item.Type == network.PublicIPType {
			if err := retainPublicIPAddress(current, desired); err != nil {
				return nil, nil, InventoryResource{}, err
			}
		}
		return before, desired.view(t.scope), *desired, nil
	}
	var saved *InventoryResource
	if exists {
		saved = &current
	}
	properties, err := storedNetwork(saved)
	if err != nil {
		return nil, nil, InventoryResource{}, err
	}
	next := InventoryResource{Address: address, Location: t.location, APIVersion: network.VNetAPIVersion,
		Tags: current.Tags, ProvisioningState: "Succeeded"}
	var after map[string]any
	switch item.Type {
	case virtualNetworkType:
		var input struct {
			Space network.AddressSpace `json:"addressSpace"`
		}
		if item.APIVersion != network.VNetAPIVersion || !strings.EqualFold(item.Location, t.location) ||
			item.SKU != (ResourceSKU{}) || !validTags(item.Tags) || strictJSON(bytes.NewReader(item.Properties), &input) != nil {
			return nil, nil, InventoryResource{}, errors.New("unsupported virtual network template properties")
		}
		next.Tags = item.Tags
		properties.AddressSpace = input.Space
	case network.SubnetType:
		var input network.SubnetProperties
		if !exists || item.APIVersion != network.SubnetAPIVersion || item.Location != "" || item.SKU != (ResourceSKU{}) ||
			len(item.Tags) != 0 || strictJSON(bytes.NewReader(item.Properties), &input) != nil || input.ProvisioningState != "" {
			return nil, nil, InventoryResource{}, errors.New("unsupported subnet template properties")
		}
		_, name, _ := strings.Cut(item.Name, "/")
		before = nil
		if index := properties.SubnetIndex(name); index >= 0 {
			old := properties.Subnets[index]
			before = subnetProjection(old)
			if input.NetworkSecurityGroup == nil {
				input.NetworkSecurityGroup = old.Properties.NetworkSecurityGroup
			}
		}
		if err := upsertSubnet(&properties, address.ID(t.scope), subnetInput{Name: name, Properties: input}); err != nil {
			return nil, nil, InventoryResource{}, err
		}
	}
	next.References, err = normalizeNetworkReferences(t.scope, address.Group, properties.Subnets)
	if err != nil {
		return nil, nil, InventoryResource{}, err
	}
	next.Properties, _ = json.Marshal(properties)
	if item.Type == network.SubnetType {
		_, name, _ := strings.Cut(item.Name, "/")
		after = subnetProjection(properties.Subnets[properties.SubnetIndex(name)])
	} else {
		after = next.view(t.scope)
	}
	return before, after, next, nil
}

func subnetProjection(subnet network.Subnet) map[string]any {
	return map[string]any{"id": subnet.ID, "name": subnet.Name, "type": subnet.Type, "properties": subnet.Properties}
}
