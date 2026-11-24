package arm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

const securityGroupType = "Microsoft.Network/networkSecurityGroups"

type securityGroupPath struct {
	Name       string
	Collection string
	Rule       string
}

func parseSecurityGroupPath(raw string) (securityGroupPath, bool) {
	parts := strings.Split(raw, "/")
	var path securityGroupPath
	if len(parts) < 2 || len(parts) > 5 || !strings.EqualFold(strings.Join(parts[:2], "/"), securityGroupType) {
		return path, false
	}
	if len(parts) == 2 {
		return path, true
	}
	path.Name = parts[2]
	if !network.ValidName(path.Name) {
		return path, false
	}
	if len(parts) >= 4 {
		switch strings.ToLower(parts[3]) {
		case "securityrules":
			path.Collection = "securityRules"
		case "defaultsecurityrules":
			path.Collection = "defaultSecurityRules"
		default:
			return path, false
		}
	}
	if len(parts) == 5 {
		path.Rule = parts[4]
		return path, network.ValidName(path.Rule)
	}
	return path, true
}

func securityGroupAction(method string, path securityGroupPath) string {
	action := securityGroupType
	if path.Collection != "" {
		action += "/" + path.Collection
	}
	if method == http.MethodDelete {
		return action + "/delete"
	}
	return action + "/write"
}

func (s Server) securityGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, rawPath string) {
	path, ok := parseSecurityGroupPath(rawPath)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The network security group or rule identifier is invalid.")
		return
	}
	query, ok := readQuery(w, r, network.SecurityGroupAPIVersion, func(key, value string) bool {
		return key == "$skiptoken" && value != "" && path.Name == "" && r.Method == http.MethodGet
	})
	if !ok {
		return
	}
	readOnly := path.Name == "" || path.Collection != "" && path.Rule == "" || path.Collection == "defaultSecurityRules"
	if readOnly && r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if path.Name == "" {
		s.listNetworkResources(ctx, w, scope, reader, group, securityGroupType, query)
		return
	}
	address := ResourceAddress{Group: group, Path: securityGroupType + "/" + path.Name}
	switch r.Method {
	case http.MethodGet:
		s.readSecurityGroup(ctx, w, scope, reader, address, path)
	case http.MethodPut, http.MethodDelete:
		s.changeSecurityGroup(ctx, w, r, scope, actor, address, path)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) readSecurityGroup(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader string, address ResourceAddress, path securityGroupPath) {
	resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
	switch {
	case err != nil:
		inventoryError(w, err)
	case resource == nil:
		writeError(w, http.StatusNotFound, "NetworkSecurityGroupNotFound", "The network security group could not be found.")
	case path.Collection == "":
		writeJSON(w, http.StatusOK, resource.view(scope))
	default:
		var properties network.SecurityGroupProperties
		if err := json.Unmarshal(resource.Properties, &properties); err != nil {
			unavailable(w)
			return
		}
		rules := properties.SecurityRules
		if path.Collection == "defaultSecurityRules" {
			rules = properties.DefaultSecurityRules
		}
		if path.Rule == "" {
			writeJSON(w, http.StatusOK, map[string]any{"value": rules})
		} else if index := securityRuleIndex(rules, path.Rule); index >= 0 {
			writeJSON(w, http.StatusOK, rules[index])
		} else {
			writeError(w, http.StatusNotFound, "SecurityRuleNotFound", "The security rule could not be found.")
		}
	}
}

type securityGroupInput struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct{}          `json:"properties"`
}

type securityRuleInput struct {
	Name       string                         `json:"name"`
	Properties network.SecurityRuleProperties `json:"properties"`
}

var (
	errSecurityGroupMissing = errors.New("network security group not found")
	errSecurityRulePriority = errors.New("security rule priority is already in use")
	errSecurityRuleLimit    = errors.New("network security group rule limit exceeded")
)

func (s Server) changeSecurityGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor string, address ResourceAddress, path securityGroupPath) {
	var group securityGroupInput
	var rule securityRuleInput
	if r.Method == http.MethodPut {
		var input any = &group
		if path.Rule != "" {
			input = &rule
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The security group request contains an unsupported field or value.")
			return
		}
		if path.Rule != "" {
			if rule.Name != "" && !strings.EqualFold(rule.Name, path.Rule) {
				writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The specified security rule name differs from the resource ID.")
				return
			}
			if err := rule.Properties.Validate(); err != nil {
				writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error())
				return
			}
		} else if !strings.EqualFold(group.Location, s.Location) || !validTags(group.Tags) {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The requested security group location or tags are unsupported.")
			return
		}
	}
	deleting := r.Method == http.MethodDelete
	auditSuffix := ""
	if path.Rule != "" {
		auditSuffix = "/" + path.Collection + "/" + path.Rule
	}
	var updated *network.SecurityRule
	var createdRule bool
	resource, created, err := s.Networks.ChangeInventoryResource(ctx, scope, address, actor, securityGroupAction(r.Method, path), auditSuffix,
		func(current *InventoryResource, canonical ResourceAddress) (*InventoryResource, error) {
			if deleting && path.Rule == "" {
				return nil, nil
			}
			result := InventoryResource{Address: canonical, APIVersion: network.SecurityGroupAPIVersion, Location: s.Location, ProvisioningState: "Succeeded"}
			var properties network.SecurityGroupProperties
			if current == nil {
				if path.Rule != "" {
					return nil, errSecurityGroupMissing
				}
				properties = network.SecurityGroupProperties{SecurityRules: []network.SecurityRule{},
					DefaultSecurityRules: network.DefaultSecurityRules(canonical.ID(scope)), ProvisioningState: "Succeeded"}
			} else {
				if err := json.Unmarshal(current.Properties, &properties); err != nil {
					return nil, err
				}
				result.Tags = current.Tags
			}
			if path.Rule == "" {
				result.Tags = group.Tags
			} else {
				index := securityRuleIndex(properties.SecurityRules, path.Rule)
				createdRule = index < 0
				if deleting && index >= 0 {
					properties.SecurityRules = slices.Delete(properties.SecurityRules, index, index+1)
				}
				if !deleting {
					item, err := upsertSecurityRule(&properties, canonical.ID(scope), path.Rule, index, rule.Properties)
					if err != nil {
						return nil, err
					}
					updated = &item
				}
			}
			result.Properties, _ = json.Marshal(properties)
			return &result, nil
		})
	switch {
	case deleting && (errors.Is(err, ErrGroupMissing) || errors.Is(err, errSecurityGroupMissing)):
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, errSecurityGroupMissing):
		writeError(w, http.StatusNotFound, "NetworkSecurityGroupNotFound", "The network security group could not be found.")
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
	case errors.Is(err, ErrLinkedResourceInUse):
		writeError(w, http.StatusConflict, "InUseNetworkSecurityGroupCannotBeDeleted", "A subnet still references this network security group.")
	case errors.Is(err, errSecurityRulePriority):
		writeError(w, http.StatusBadRequest, "SecurityRuleConflict", err.Error())
	case errors.Is(err, errSecurityRuleLimit):
		writeError(w, http.StatusBadRequest, "SecurityRuleLimitExceeded", err.Error())
	case err != nil:
		inventoryError(w, err)
	case deleting:
		w.WriteHeader(http.StatusNoContent)
	case updated != nil:
		writeJSON(w, createdStatus(createdRule), updated)
	default:
		writeJSON(w, createdStatus(created), resource.view(scope))
	}
}

func securityRuleIndex(rules []network.SecurityRule, name string) int {
	return slices.IndexFunc(rules, func(rule network.SecurityRule) bool { return strings.EqualFold(rule.Name, name) })
}

func upsertSecurityRule(properties *network.SecurityGroupProperties, parentID, name string, index int, requested network.SecurityRuleProperties) (network.SecurityRule, error) {
	const maxRules = 128
	for position, rule := range properties.SecurityRules {
		if position != index && rule.Properties.Priority == requested.Priority && rule.Properties.Direction == requested.Direction {
			return network.SecurityRule{}, errSecurityRulePriority
		}
	}
	if index >= 0 {
		name = properties.SecurityRules[index].Name
	}
	rule := network.NewSecurityRule(parentID, name, "securityRules", requested)
	if index < 0 {
		if len(properties.SecurityRules) >= maxRules {
			return network.SecurityRule{}, errSecurityRuleLimit
		}
		properties.SecurityRules = append(properties.SecurityRules, rule)
	} else {
		properties.SecurityRules[index] = rule
	}
	return rule, nil
}
