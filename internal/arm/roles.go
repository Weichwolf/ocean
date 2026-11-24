package arm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const assignmentAPIVersion = "2022-04-01"
const definitionAPIVersion = "2022-05-01-preview"
const ReaderRoleID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

var (
	validUUID            = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	ErrGroupMissing      = errors.New("resource group not found")
	ErrAssignmentExists  = errors.New("role assignment already exists")
	ErrAssignmentChanged = errors.New("role assignment cannot change its principal or role")
	ErrRoleDenied        = errors.New("principal is not authorized for the role scope")
)

type RoleAssignment struct {
	ID            string    `json:"assignmentId"`
	Group         string    `json:"group"`
	PrincipalID   string    `json:"principalId"`
	PrincipalType string    `json:"principalType"`
	RoleID        string    `json:"roleId"`
	Description   string    `json:"description,omitempty"`
	CreatedBy     string    `json:"createdBy"`
	CreatedAt     time.Time `json:"createdOn"`
}

type AuditEvent struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Outcome string    `json:"outcome"`
}

type RoleStore interface {
	GroupGrant(context.Context, SubscriptionScope, string, string) (bool, error)
	GetGrantedGroup(context.Context, SubscriptionScope, string, string) (*Group, error)
	ListGrantedGroups(context.Context, SubscriptionScope, string, string, int) ([]Group, error)
	SubscriptionGrant(context.Context, SubscriptionScope, string) (bool, error)
	ListAssignments(context.Context, SubscriptionScope, string, string, string, int) ([]RoleAssignment, error)
	GetAssignment(context.Context, SubscriptionScope, string, string, string) (*RoleAssignment, error)
	PutAssignment(context.Context, SubscriptionScope, RoleAssignment) (RoleAssignment, bool, error)
	DeleteAssignment(context.Context, SubscriptionScope, string, string, string) (*RoleAssignment, error)
	RecordAudit(context.Context, SubscriptionScope, AuditEvent) error
}

func (a RoleAssignment) ResourceID(scope SubscriptionScope) string {
	return groupID(scope, a.Group) + "/providers/Microsoft.Authorization/roleAssignments/" + a.ID
}

func (a RoleAssignment) view(scope SubscriptionScope) map[string]any {
	return map[string]any{"id": a.ResourceID(scope), "name": a.ID, "type": "Microsoft.Authorization/roleAssignments",
		"properties": map[string]any{"scope": groupID(scope, a.Group), "principalId": a.PrincipalID, "principalType": a.PrincipalType,
			"roleDefinitionId": roleDefinitionID(scope), "description": a.Description, "createdOn": a.CreatedAt, "createdBy": a.CreatedBy}}
}

func groupID(scope SubscriptionScope, group string) string {
	return "/subscriptions/" + scope.SubscriptionID + "/resourceGroups/" + group
}

func roleDefinitionID(scope SubscriptionScope) string {
	return "/subscriptions/" + scope.SubscriptionID + "/providers/Microsoft.Authorization/roleDefinitions/" + ReaderRoleID
}

func (s Server) roleDefinitions(w http.ResponseWriter, r *http.Request, scope SubscriptionScope, id string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	filter := func(key, value string) bool {
		return id == "" && key == "$filter" && len(value) > len("roleName eq ''") &&
			strings.HasPrefix(value, "roleName eq '") && strings.HasSuffix(value, "'") && strings.Count(value, "'") == 2
	}
	query, ok := readQuery(w, r, definitionAPIVersion, filter)
	if !ok {
		return
	}
	definition := map[string]any{"id": roleDefinitionID(scope), "name": ReaderRoleID, "type": "Microsoft.Authorization/roleDefinitions",
		"properties": map[string]any{"roleName": "Reader", "type": "BuiltInRole", "description": "Read control plane resources.",
			"assignableScopes": []string{"/subscriptions/" + scope.SubscriptionID},
			"permissions":      []map[string][]string{{"actions": {"*/read"}, "notActions": {}, "dataActions": {}, "notDataActions": {}}}}}
	if id != "" {
		if !strings.EqualFold(id, ReaderRoleID) {
			writeError(w, http.StatusNotFound, "RoleDefinitionDoesNotExist", "The role definition was not found.")
			return
		}
		writeJSON(w, http.StatusOK, definition)
		return
	}
	result := []map[string]any{}
	if value := query.Get("$filter"); value == "" || strings.EqualFold(value, "roleName eq 'Reader'") {
		result = append(result, definition)
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": result})
}

func (s Server) roleAssignments(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, id string) {
	allowed := func(key, value string) bool {
		return id == "" && r.Method == http.MethodGet && ((key == "$filter" && value == "atScope()") ||
			(key == "$skiptoken" && validUUID.MatchString(value) && value == strings.ToLower(value)))
	}
	query, ok := readQuery(w, r, assignmentAPIVersion, allowed)
	if !ok {
		return
	}
	if group == "" {
		writeError(w, http.StatusBadRequest, "InvalidScope", "Role assignments require an existing resource group scope.")
		return
	}
	if id == "" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		s.listAssignments(ctx, w, scope, reader, group, query)
		return
	}
	id = strings.ToLower(id)
	switch r.Method {
	case http.MethodGet:
		assignment, err := s.Roles.GetAssignment(ctx, scope, reader, group, id)
		if err != nil {
			roleReadError(w, err)
			return
		}
		if assignment == nil {
			writeError(w, http.StatusNotFound, "RoleAssignmentDoesNotExist", "The role assignment was not found.")
			return
		}
		writeJSON(w, http.StatusOK, assignment.view(scope))
	case http.MethodPut:
		s.putAssignment(ctx, w, r, scope, actor, group, id)
	case http.MethodDelete:
		assignment, err := s.Roles.DeleteAssignment(ctx, scope, group, id, actor)
		if err != nil {
			unavailable(w)
			return
		}
		if assignment == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, assignment.view(scope))
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) listAssignments(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader, group string, query url.Values) {
	assignments, err := s.Roles.ListAssignments(ctx, scope, reader, group, query.Get("$skiptoken"), groupPageSize+1)
	if err != nil {
		roleReadError(w, err)
		return
	}
	count := min(len(assignments), groupPageSize)
	values := make([]map[string]any, 0, count)
	for _, assignment := range assignments[:count] {
		values = append(values, assignment.view(scope))
	}
	result := map[string]any{"value": values}
	if len(assignments) > groupPageSize {
		query.Set("$skiptoken", assignments[count-1].ID)
		result["nextLink"] = s.Origin + groupID(scope, url.PathEscape(group)) + "/providers/Microsoft.Authorization/roleAssignments?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, result)
}

func roleReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrRoleDenied) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
		return
	}
	unavailable(w)
}

func (s Server) putAssignment(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, group, id string) {
	var input struct {
		Properties struct {
			PrincipalID   string `json:"principalId"`
			PrincipalType string `json:"principalType"`
			Role          string `json:"roleDefinitionId"`
			Description   string `json:"description"`
		} `json:"properties"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	fields := &input.Properties
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !validUUID.MatchString(fields.PrincipalID) ||
		(fields.PrincipalType != "User" && fields.PrincipalType != "ServicePrincipal") || utf8.RuneCountInString(fields.Description) > 1024 ||
		(!strings.EqualFold(fields.Role, roleDefinitionID(scope)) && !strings.EqualFold(fields.Role, "/providers/Microsoft.Authorization/roleDefinitions/"+ReaderRoleID)) {
		writeError(w, http.StatusBadRequest, "InvalidRoleAssignmentRequest", "Specify a tenant user or service principal and the Reader role.")
		return
	}
	subject := strings.ToLower(fields.PrincipalID)
	exists, err := s.PrincipalExists(ctx, scope.TenantID, subject, fields.PrincipalType)
	if err != nil {
		unavailable(w)
		return
	}
	if !exists {
		writeError(w, http.StatusBadRequest, "PrincipalNotFound", "The assignee was not found in the tenant directory.")
		return
	}
	assignment := RoleAssignment{ID: id, Group: group, PrincipalID: subject, PrincipalType: fields.PrincipalType,
		RoleID: ReaderRoleID, Description: fields.Description, CreatedBy: actor, CreatedAt: time.Now().UTC()}
	assignment, created, err := s.Roles.PutAssignment(ctx, scope, assignment)
	switch {
	case errors.Is(err, ErrGroupMissing):
		writeError(w, http.StatusNotFound, "ResourceGroupNotFound", "The resource group could not be found.")
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
	case errors.Is(err, ErrAssignmentExists):
		writeError(w, http.StatusConflict, "RoleAssignmentExists", "The principal already has the role at this scope.")
	case errors.Is(err, ErrAssignmentChanged):
		writeError(w, http.StatusBadRequest, "RoleAssignmentUpdateNotPermitted", "The assignment cannot change its principal or role.")
	case err != nil:
		unavailable(w)
	case created:
		writeJSON(w, http.StatusCreated, assignment.view(scope))
	default:
		writeJSON(w, http.StatusOK, assignment.view(scope))
	}
}
