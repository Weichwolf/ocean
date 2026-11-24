package arm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const groupPageSize = 16

type SubscriptionScope struct {
	TenantID       string
	SubscriptionID string
}

type Group struct {
	Name            string            `json:"name"`
	Location        string            `json:"location"`
	Tags            map[string]string `json:"tags"`
	DeleteOperation string            `json:"deleteOperation,omitempty"`
}

type GroupStore interface {
	GetGroup(context.Context, SubscriptionScope, string) (*Group, error)
	ListGroups(context.Context, SubscriptionScope, string, int) ([]Group, error)
	PutGroup(context.Context, SubscriptionScope, Group, string) (Group, bool, error)
	DeleteGroup(context.Context, SubscriptionScope, string, string) (*Operation, error)
}

var ErrGroupLocation = errors.New("resource group location cannot change")
var ErrGroupDeleting = errors.New("resource group deletion is in progress")
var ErrGroupInUse = errors.New("the resource group still contains bound workload placements")

func (s Server) group(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, name, actor, reader string) {
	allowed := func(key, value string) bool {
		return key == "$skiptoken" && name == "" && r.Method == http.MethodGet && validGroupName(value) && value == strings.ToLower(value)
	}
	query, ok := readQuery(w, r, resourceAPIVersion, allowed)
	if !ok {
		return
	}
	if name == "" {
		if r.Method == http.MethodGet {
			s.listGroups(ctx, w, scope, reader, query.Get("$skiptoken"))
			return
		}
		methodNotAllowed(w, "GET")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		var group *Group
		var err error
		if reader != "" {
			group, err = s.Roles.GetGrantedGroup(ctx, scope, name, reader)
		} else {
			group, err = s.Groups.GetGroup(ctx, scope, name)
		}
		if err != nil {
			unavailable(w)
			return
		}
		if group == nil {
			if reader != "" {
				writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
				return
			}
			writeError(w, http.StatusNotFound, "ResourceGroupNotFound", "The resource group could not be found.")
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, group.view(scope))
	case http.MethodPut:
		s.putGroup(ctx, w, r, scope, name, actor)
	case http.MethodDelete:
		operation, err := s.Groups.DeleteGroup(ctx, scope, name, actor)
		if errors.Is(err, ErrGroupInUse) {
			writeError(w, http.StatusConflict, "ResourceGroupInUse", err.Error())
			return
		}
		if err != nil {
			unavailable(w)
			return
		}
		if operation == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.acceptOperation(w, scope, *operation)
	default:
		methodNotAllowed(w, "GET, HEAD, PUT, DELETE")
	}
}

func (s Server) listGroups(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader, after string) {
	var groups []Group
	var err error
	if reader != "" {
		groups, err = s.Roles.ListGrantedGroups(ctx, scope, reader, after, groupPageSize+1)
	} else {
		groups, err = s.Groups.ListGroups(ctx, scope, after, groupPageSize+1)
	}
	if err != nil {
		unavailable(w)
		return
	}
	count := min(len(groups), groupPageSize)
	result := make([]groupView, 0, count)
	for _, group := range groups[:count] {
		result = append(result, group.view(scope))
	}
	response := struct {
		Value    []groupView `json:"value"`
		NextLink string      `json:"nextLink,omitempty"`
	}{Value: result}
	if len(groups) > groupPageSize {
		query := url.Values{"api-version": {resourceAPIVersion}, "$skiptoken": {strings.ToLower(groups[groupPageSize-1].Name)}}
		response.NextLink = s.Origin + "/subscriptions/" + scope.SubscriptionID + "/resourcegroups?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s Server) putGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, name, actor string) {
	var input struct {
		Location string            `json:"location"`
		Tags     map[string]string `json:"tags"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !validTags(input.Tags) {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "Specify a location and optional string tags.")
		return
	}
	if !strings.EqualFold(input.Location, s.Location) {
		writeError(w, http.StatusBadRequest, "InvalidLocation", "The resource group location is unsupported.")
		return
	}
	if input.Tags == nil {
		input.Tags = map[string]string{}
	}
	group, created, err := s.Groups.PutGroup(ctx, scope, Group{Name: name, Location: s.Location, Tags: input.Tags}, actor)
	if errors.Is(err, ErrGroupLocation) {
		writeError(w, http.StatusConflict, "InvalidResourceGroupLocation", "The resource group location cannot change.")
		return
	}
	if errors.Is(err, ErrGroupDeleting) {
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, group.view(scope))
}

func validGroupName(name string) bool {
	if name == "" || strings.HasSuffix(name, ".") || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 90 {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("-_.()", r)
	})
}

func validTags(tags map[string]string) bool {
	if len(tags) > 50 {
		return false
	}
	keys := make(map[string]struct{}, len(tags))
	for name, value := range tags {
		key := strings.ToLower(name)
		if _, exists := keys[key]; exists || name == "" || utf8.RuneCountInString(name) > 512 || utf8.RuneCountInString(value) > 256 {
			return false
		}
		keys[key] = struct{}{}
	}
	return true
}

type groupView struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties map[string]string `json:"properties"`
}

func (g Group) ResourceID(scope SubscriptionScope) string {
	return groupID(scope, g.Name)
}

func (g Group) view(scope SubscriptionScope) groupView {
	state := "Succeeded"
	if g.DeleteOperation != "" {
		state = "Deleting"
	}
	return groupView{ID: g.ResourceID(scope), Type: "Microsoft.Resources/resourceGroups",
		Name: g.Name, Location: g.Location, Tags: g.Tags, Properties: map[string]string{"provisioningState": state}}
}
