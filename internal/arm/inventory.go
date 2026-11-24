package arm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const inventoryPageSize = 16

const MaxResourceReferences = 16

var (
	ErrLinkedResourceMissing = errors.New("a linked resource does not exist")
	ErrLinkedResourceInUse   = errors.New("another resource still references this resource")
	ErrPublicIPInUse         = errors.New("the public IP address is already attached to a resource")
	ErrPublicIPPoolDisabled  = errors.New("the region does not have a public IPv4 address pool")
	ErrPublicIPPoolExhausted = errors.New("the regional public IPv4 address pool is exhausted")

	resourceSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.()-]{0,127}$`)
	namespaceName   = regexp.MustCompile(`^[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$`)
	resourceVersion = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(-preview)?$`)
	inventoryTerm   = regexp.MustCompile(`^(resourceGroup|resourceType|name|location) eq '([^']+)'$`)
)

// ResourceAddress identifies a provider resource within a subscription's group.
// Path alternates resource types and names following the provider namespace.
type ResourceAddress struct {
	Group string
	Path  string
}

func (a ResourceAddress) Key() string { return strings.ToLower(a.Group + "/" + a.Path) }

func (a ResourceAddress) ID(scope SubscriptionScope) string {
	return groupID(scope, a.Group) + "/providers/" + a.Path
}

func (a ResourceAddress) parts() (name, kind string, ok bool) {
	pieces := strings.Split(a.Path, "/")
	if !validGroupName(a.Group) || len(pieces) < 3 || len(pieces) > 17 || len(pieces)%2 == 0 ||
		len(pieces[0]) > 128 || !namespaceName.MatchString(pieces[0]) {
		return "", "", false
	}
	types := []string{pieces[0]}
	for index := 1; index < len(pieces); index += 2 {
		if !resourceSegment.MatchString(pieces[index]) || !resourceSegment.MatchString(pieces[index+1]) {
			return "", "", false
		}
		types = append(types, pieces[index])
	}
	return pieces[len(pieces)-1], strings.Join(types, "/"), true
}

func (a ResourceAddress) Valid() bool {
	_, _, ok := a.parts()
	return ok
}

// InventoryResource contains the provider's public ARM projection. Provider
// credentials and private runtime state belong in their own storage records.
type InventoryResource struct {
	Address           ResourceAddress   `json:"address"`
	APIVersion        string            `json:"apiVersion"`
	Location          string            `json:"location"`
	Tags              map[string]string `json:"tags,omitempty"`
	SKU               ResourceSKU       `json:"sku,omitzero"`
	Properties        json.RawMessage   `json:"properties,omitempty"`
	ProvisioningState string            `json:"provisioningState,omitempty"`
	References        []ResourceAddress `json:"references,omitempty"`
	CreatedAt         time.Time         `json:"createdTime"`
	ChangedAt         time.Time         `json:"changedTime"`
}

type ResourceSKU struct {
	Name string `json:"name"`
	Tier string `json:"tier,omitempty"`
}

func (r InventoryResource) Valid() bool {
	if !r.Address.Valid() || !resourceVersion.MatchString(r.APIVersion) || r.Location == "" || !validTags(r.Tags) ||
		len(r.Properties) != 0 && (r.Properties[0] != '{' || !json.Valid(r.Properties)) || len(r.References) > MaxResourceReferences {
		return false
	}
	seen := make(map[string]bool)
	for _, ref := range r.References {
		key := ref.Key()
		if !ref.Valid() || !strings.EqualFold(ref.Group, r.Address.Group) || key == r.Address.Key() || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (r InventoryResource) view(scope SubscriptionScope) map[string]any {
	name, kind, _ := r.Address.parts()
	view := map[string]any{"id": r.Address.ID(scope), "name": name, "type": kind, "location": r.Location}
	if r.Tags != nil {
		view["tags"] = r.Tags
	}
	if r.SKU.Name != "" {
		view["sku"] = r.SKU
	}
	if len(r.Properties) != 0 {
		view["properties"] = r.Properties
	}
	return view
}

type InventoryQuery struct {
	Group      string
	GroupScope bool
	After      string
	Name       string
	Type       string
	Location   string
}

func (q InventoryQuery) Match(resource InventoryResource) bool {
	name, kind, _ := resource.Address.parts()
	return (q.Group == "" || strings.EqualFold(q.Group, resource.Address.Group)) &&
		(q.Name == "" || strings.EqualFold(q.Name, name)) && (q.Type == "" || strings.EqualFold(q.Type, kind)) &&
		(q.Location == "" || strings.EqualFold(q.Location, resource.Location))
}

type InventoryStore interface {
	GetInventoryResource(context.Context, SubscriptionScope, string, ResourceAddress) (*InventoryResource, error)
	ListInventoryResources(context.Context, SubscriptionScope, string, InventoryQuery, int) ([]InventoryResource, error)
}

func (s Server) showResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader string, address ResourceAddress) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if !address.Valid() {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The resource identifier is invalid.")
		return
	}
	version := r.URL.Query().Get("api-version")
	if !resourceVersion.MatchString(version) {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Specify a resource API version.")
		return
	}
	if _, ok := readQuery(w, r, version, nil); !ok {
		return
	}
	resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if resource == nil {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The resource could not be found.")
		return
	}
	if version != resource.APIVersion {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The API version is unsupported for this resource.")
		return
	}
	writeJSON(w, http.StatusOK, resource.view(scope))
}

func (s Server) listResources(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader, group string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	query, ok := readQuery(w, r, resourceAPIVersion, func(key, value string) bool {
		return key == "$filter" || value != "" && (key == "$skiptoken" || key == "$expand")
	})
	if !ok {
		return
	}
	search, ok := inventoryQuery(query, group)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The resource filter or continuation is unsupported.")
		return
	}
	fields, ok := inventoryExpansion(query.Get("$expand"))
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The resource expansion is unsupported.")
		return
	}
	resources, err := s.Inventory.ListInventoryResources(ctx, scope, reader, search, inventoryPageSize+1)
	if err != nil {
		inventoryError(w, err)
		return
	}
	count := min(len(resources), inventoryPageSize)
	items := make([]map[string]any, 0, count)
	for _, item := range resources[:count] {
		view := item.view(scope)
		if fields["createdTime"] {
			view["createdTime"] = item.CreatedAt
		}
		if fields["changedTime"] {
			view["changedTime"] = item.ChangedAt
		}
		if fields["provisioningState"] && item.ProvisioningState != "" {
			view["provisioningState"] = item.ProvisioningState
		}
		items = append(items, view)
	}
	response := map[string]any{"value": items}
	if len(resources) > count {
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(resources[count-1].Address.Key())))
		path := "/subscriptions/" + scope.SubscriptionID
		if group != "" {
			path += "/resourceGroups/" + url.PathEscape(group)
		}
		response["nextLink"] = s.Origin + path + "/resources?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

func inventoryExpansion(expand string) (map[string]bool, bool) {
	fields := make(map[string]bool)
	if expand == "" {
		return fields, true
	}
	for _, field := range strings.Split(expand, ",") {
		if fields[field] || (field != "createdTime" && field != "changedTime" && field != "provisioningState") {
			return nil, false
		}
		fields[field] = true
	}
	return fields, true
}

func inventoryQuery(params url.Values, group string) (InventoryQuery, bool) {
	result := InventoryQuery{Group: group, GroupScope: group != ""}
	if encoded := params.Get("$skiptoken"); encoded != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		name, path, _ := strings.Cut(string(decoded), "/")
		if err != nil || string(decoded) != strings.ToLower(string(decoded)) || !(ResourceAddress{Group: name, Path: path}).Valid() {
			return InventoryQuery{}, false
		}
		result.After = string(decoded)
	}
	filter := params.Get("$filter")
	if filter == "" {
		return result, true
	}
	seen := make(map[string]bool)
	for _, term := range strings.Split(filter, " and ") {
		match := inventoryTerm.FindStringSubmatch(term)
		if len(match) != 3 || seen[match[1]] || len(match[2]) > 512 {
			return InventoryQuery{}, false
		}
		seen[match[1]] = true
		switch match[1] {
		case "resourceGroup":
			if !validGroupName(match[2]) || group != "" && !strings.EqualFold(group, match[2]) {
				return InventoryQuery{}, false
			}
			result.Group = match[2]
		case "resourceType":
			result.Type = match[2]
		case "name":
			result.Name = match[2]
		case "location":
			result.Location = match[2]
		}
	}
	return result, true
}

func inventoryError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrRoleDenied) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
	} else if errors.Is(err, ErrGroupMissing) {
		writeError(w, http.StatusNotFound, "ResourceGroupNotFound", "The resource group could not be found.")
	} else {
		unavailable(w)
	}
}
