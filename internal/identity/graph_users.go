package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	graphDisplayName = "oceanDisplayName"
	graphMailAlias   = "oceanMailNickname"
	graphPageSize    = 100
)

type graphUserInput struct {
	UPN         *string        `json:"userPrincipalName,omitempty"`
	DisplayName *string        `json:"displayName,omitempty"`
	Alias       *string        `json:"mailNickname,omitempty"`
	Enabled     *bool          `json:"accountEnabled,omitempty"`
	Password    *graphPassword `json:"passwordProfile,omitempty"`
}

type graphPassword struct {
	Value     string `json:"password"`
	Temporary bool   `json:"forceChangePasswordNextSignIn"`
}

type directoryUser struct {
	ID         string              `json:"id"`
	Name       string              `json:"username"`
	Email      string              `json:"email,omitempty"`
	FirstName  string              `json:"firstName,omitempty"`
	LastName   string              `json:"lastName,omitempty"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

type graphUserView struct {
	ID          string `json:"id"`
	UPN         string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"mailNickname"`
	Enabled     bool   `json:"accountEnabled"`
	Mail        string `json:"mail,omitempty"`
}

func (c *Compatibility) graphTenant(ctx context.Context, w http.ResponseWriter, req *http.Request) *TenantReservation {
	raw, issuer, tenant := c.bearerRealm(req)
	if tenant == "" {
		graphError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid Graph access token is required.")
		return nil
	}
	record, err := c.onboarding.store.LookupTenant(ctx, tenant)
	if err != nil || (record != nil && !record.Valid(tenant)) {
		graphUnavailable(w)
		return nil
	}
	if record == nil {
		graphError(w, http.StatusForbidden, "Authorization_RequestDenied", "The tenant is outside the directory scope.")
		return nil
	}
	token, err := c.verifyAccessToken(ctx, raw, issuer, c.cloud.MicrosoftGraph)
	var claims struct {
		Type string `json:"typ"`
	}
	if err != nil || token.Claims(&claims) != nil || claims.Type != "Bearer" {
		graphError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid Graph access token is required.")
		return nil
	}
	subscription, err := c.subscriptions.lookup(ctx, tenant)
	if err != nil {
		graphUnavailable(w)
		return nil
	}
	if subscription == nil || !subscription.Valid(tenant) || subscription.SubscriptionID != record.SubscriptionID ||
		token.Subject != record.Administrator {
		graphError(w, http.StatusForbidden, "Authorization_RequestDenied", "The operation requires the tenant administrator.")
		return nil
	}
	return record
}

func (c *Compatibility) graphUser(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.MicrosoftGraph, "https://")) {
		http.NotFound(w, req)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 25*time.Second)
	defer cancel()
	tenant := c.graphTenant(ctx, w, req)
	if tenant == nil {
		return
	}
	if c.managedGraph(ctx, w, req, *tenant, false) {
		return
	}
	k := c.onboarding.admin
	name := req.PathValue("user")
	if (req.Method == http.MethodGet || req.Method == http.MethodHead) && name == "" {
		k.listGraphUsers(ctx, w, req, c.cloud.MicrosoftGraph, tenant.TenantID)
		return
	}
	if req.URL.RawQuery != "" {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Unsupported directory query parameter.")
		return
	}
	if req.Method == http.MethodPost {
		input, err := readGraphUser(req, w, true)
		if err != nil {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", err.Error())
			return
		}
		k.createGraphUser(ctx, w, tenant.TenantID, input)
		return
	}
	user, err := k.directoryUser(ctx, tenant.TenantID, name)
	if err != nil {
		graphUnavailable(w)
		return
	}
	if user == nil {
		graphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The user was not found.")
		return
	}
	path := "/users/" + user.ID
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		writeJSON(w, http.StatusOK, user.graphView())
	case http.MethodDelete:
		if user.ID == tenant.Administrator {
			graphError(w, http.StatusForbidden, "Authorization_RequestDenied", "The initial administrator cannot be deleted.")
			return
		}
		status, err := k.directoryRequest(ctx, tenant.TenantID, http.MethodDelete, path, nil, nil)
		graphUserMutation(w, status, err)
	case http.MethodPatch:
		input, err := readGraphUser(req, w, false)
		if err != nil {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", err.Error())
			return
		}
		if user.ID == tenant.Administrator && input.Enabled != nil && !*input.Enabled {
			graphError(w, http.StatusForbidden, "Authorization_RequestDenied", "The initial administrator cannot be disabled.")
			return
		}
		if (input.DisplayName != nil || input.Alias != nil) && k.ensureGraphUserProfile(ctx, tenant.TenantID) != nil {
			graphUnavailable(w)
			return
		}
		provider := input.providerView(user.Attributes)
		if _, hasAttributes := provider["attributes"]; hasAttributes {
			// Keycloak applies a complete attribute profile on this PUT.
			provider["username"], provider["email"] = user.Name, user.Email
			provider["firstName"], provider["lastName"] = user.FirstName, user.LastName
		}
		status, err := k.directoryRequest(ctx, tenant.TenantID, http.MethodPut, path, provider, nil)
		graphUserMutation(w, status, err)
	}
}

var graphAlias = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func readGraphUser(req *http.Request, w http.ResponseWriter, create bool) (graphUserInput, error) {
	var input graphUserInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return input, errors.New("submit one supported Graph user object")
	}
	if create && (input.UPN == nil || input.DisplayName == nil || input.Alias == nil || input.Password == nil || input.Enabled == nil) {
		return input, errors.New("user creation requires the principal name, display name, alias, status, and password")
	}
	if !create && (input.UPN != nil || (input.DisplayName == nil && input.Alias == nil && input.Password == nil && input.Enabled == nil)) {
		return input, errors.New("provide an editable user property")
	}
	if input.UPN != nil {
		*input.UPN = strings.ToLower(*input.UPN)
		if !validGraphUPN(*input.UPN) {
			return input, errors.New("invalid user principal name")
		}
	}
	if input.DisplayName != nil && (strings.TrimSpace(*input.DisplayName) == "" || len(*input.DisplayName) > 120 ||
		strings.ContainsFunc(*input.DisplayName, unicode.IsControl)) {
		return input, errors.New("invalid display name")
	}
	if input.Alias != nil && !graphAlias.MatchString(*input.Alias) {
		return input, errors.New("invalid mail nickname")
	}
	if input.Password != nil && (len(input.Password.Value) < 12 || len(input.Password.Value) > 256 ||
		strings.ContainsFunc(input.Password.Value, unicode.IsControl)) {
		return input, errors.New("configure a 12–256 byte password")
	}
	return input, nil
}

func validGraphUPN(s string) bool {
	address, err := mail.ParseAddress(s)
	return len(s) <= 128 && err == nil && address.Address == s
}

func (input graphUserInput) providerView(attributes map[string][]string) map[string]any {
	body := map[string]any{}
	if input.UPN != nil {
		body["username"], body["email"] = *input.UPN, *input.UPN
		body["firstName"], body["lastName"] = "Ocean", "User"
	}
	if input.Enabled != nil {
		body["enabled"] = *input.Enabled
	}
	if input.DisplayName != nil || input.Alias != nil {
		if attributes == nil {
			attributes = make(map[string][]string)
		}
		if input.DisplayName != nil {
			attributes[graphDisplayName] = []string{*input.DisplayName}
		}
		if input.Alias != nil {
			attributes[graphMailAlias] = []string{*input.Alias}
		}
		body["attributes"] = attributes
	}
	if input.Password != nil {
		body["credentials"] = []map[string]any{{
			"type": "password", "value": input.Password.Value, "temporary": input.Password.Temporary,
		}}
	}
	return body
}

func (u directoryUser) graphView() graphUserView {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if stored := u.Attributes[graphDisplayName]; len(stored) == 1 {
		name = stored[0]
	}
	alias, _, _ := strings.Cut(u.Name, "@")
	if stored := u.Attributes[graphMailAlias]; len(stored) == 1 {
		alias = stored[0]
	}
	return graphUserView{ID: u.ID, UPN: u.Name, DisplayName: name, Alias: alias, Enabled: u.Enabled, Mail: u.Email}
}

func (k keycloakAdmin) createGraphUser(ctx context.Context, w http.ResponseWriter, tenant string, input graphUserInput) {
	if err := k.ensureGraphUserProfile(ctx, tenant); err != nil {
		graphUnavailable(w)
		return
	}
	if err := k.ensureDeviceLoginRole(ctx, tenant); err != nil {
		graphUnavailable(w)
		return
	}
	status, err := k.directoryRequest(ctx, tenant, http.MethodPost, "/users", input.providerView(nil), nil)
	if err != nil || status != http.StatusCreated {
		graphUserMutation(w, status, err)
		return
	}
	user, err := k.directoryUser(ctx, tenant, *input.UPN)
	if err != nil || user == nil || user.graphView().DisplayName != *input.DisplayName || user.graphView().Alias != *input.Alias {
		graphUnavailable(w)
		return
	}
	writeJSON(w, http.StatusCreated, user.graphView())
}

func (k keycloakAdmin) directoryUser(ctx context.Context, tenant, name string) (*directoryUser, error) {
	name = strings.ToLower(name)
	if tenantID.MatchString(name) {
		var user directoryUser
		status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/users/"+name, nil, &user)
		if err == nil && status == http.StatusNotFound {
			return nil, nil
		}
		if err != nil || status != http.StatusOK || user.ID != name {
			return nil, errors.New("unable to confirm the directory user")
		}
		return &user, nil
	}
	if !validGraphUPN(name) {
		return nil, nil
	}
	query := url.Values{"username": {name}, "exact": {"true"}, "max": {"2"}}
	var users []directoryUser
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/users?"+query.Encode(), nil, &users)
	if err != nil || status != http.StatusOK {
		return nil, errors.New("unable to read the directory user")
	}
	if len(users) == 0 {
		return nil, nil
	}
	if len(users) != 1 || !strings.EqualFold(users[0].Name, name) || !tenantID.MatchString(users[0].ID) {
		return nil, errors.New("the directory could not resolve one user")
	}
	return &users[0], nil
}

func (k keycloakAdmin) ensureGraphUserProfile(ctx context.Context, tenant string) error {
	var profile map[string]json.RawMessage
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/users/profile", nil, &profile)
	if err != nil || status != http.StatusOK {
		return errors.New("unable to get the Keycloak user profile")
	}
	var attributes []map[string]json.RawMessage
	if json.Unmarshal(profile["attributes"], &attributes) != nil {
		return errors.New("invalid Keycloak user profile")
	}
	existing := make(map[string]bool)
	for _, attribute := range attributes {
		existing[jsonString(attribute["name"])] = true
	}
	changed := false
	for _, name := range []string{graphDisplayName, graphMailAlias} {
		if existing[name] {
			continue
		}
		label, _ := json.Marshal(name)
		attributes = append(attributes, map[string]json.RawMessage{
			"name": label, "permissions": json.RawMessage(`{"view":["admin"],"edit":["admin"]}`),
		})
		changed = true
	}
	if !changed {
		return nil
	}
	profile["attributes"], _ = json.Marshal(attributes)
	status, err = k.directoryRequest(ctx, tenant, http.MethodPut, "/users/profile", profile, nil)
	if err != nil || status != http.StatusOK {
		return errors.New("unable to configure the Keycloak Graph user attributes")
	}
	return nil
}

func (k keycloakAdmin) ensureDeviceLoginRole(ctx context.Context, tenant string) error {
	type realmRole struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var realm struct {
		DefaultRole realmRole `json:"defaultRole"`
	}
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "", nil, &realm)
	if err != nil || status != http.StatusOK || !tenantID.MatchString(realm.DefaultRole.ID) {
		return errors.New("unable to get the Keycloak default role")
	}
	composites := "/roles-by-id/" + realm.DefaultRole.ID + "/composites/realm"
	var roles []realmRole
	status, err = k.directoryRequest(ctx, tenant, http.MethodGet, composites, nil, &roles)
	if err != nil || status != http.StatusOK {
		return errors.New("unable to read default Keycloak realm roles")
	}
	for _, role := range roles {
		if role.Name == "offline_access" {
			return nil
		}
	}
	var offline realmRole
	status, err = k.directoryRequest(ctx, tenant, http.MethodGet, "/roles/offline_access", nil, &offline)
	if err != nil || status != http.StatusOK || offline.Name != "offline_access" || !tenantID.MatchString(offline.ID) {
		return errors.New("the Keycloak offline login role is absent")
	}
	path := strings.TrimSuffix(composites, "/realm")
	status, err = k.directoryRequest(ctx, tenant, http.MethodPost, path, []realmRole{offline}, nil)
	if err != nil || status != http.StatusNoContent {
		return errors.New("unable to enable the default device login role")
	}
	return nil
}

var graphUPNFilter = regexp.MustCompile(`^userPrincipalName eq '([^']+)'$`)
var graphNameFilter = regexp.MustCompile(`^startswith\(displayName,'([^']+)'\)$`)

func (k keycloakAdmin) listGraphUsers(ctx context.Context, w http.ResponseWriter, req *http.Request, origin, tenant string) {
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid directory query.")
		return
	}
	for name, values := range query {
		if len(values) != 1 || (name != "$filter" && name != "$skip") {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", "Unsupported directory query parameter.")
			return
		}
	}
	offset := 0
	if query.Has("$skip") {
		offset, err = strconv.Atoi(query.Get("$skip"))
		if err != nil || offset < 0 || offset > 1000000 {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid directory page.")
			return
		}
	}
	if match := graphUPNFilter.FindStringSubmatch(query.Get("$filter")); match != nil && offset == 0 {
		user, err := k.directoryUser(ctx, tenant, match[1])
		if err != nil {
			graphUnavailable(w)
			return
		}
		values := []graphUserView{}
		if user != nil {
			values = append(values, user.graphView())
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": values})
		return
	}
	display := graphNameFilter.FindStringSubmatch(query.Get("$filter"))
	if query.Has("$filter") && display == nil {
		graphError(w, http.StatusBadRequest, "Request_UnsupportedQuery", "The directory filter is unsupported.")
		return
	}
	providerQuery := url.Values{"first": {strconv.Itoa(offset)}, "max": {strconv.Itoa(graphPageSize)}}
	var users []directoryUser
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/users?"+providerQuery.Encode(), nil, &users)
	if err != nil || status != http.StatusOK {
		graphUnavailable(w)
		return
	}
	values := make([]graphUserView, 0, len(users))
	for _, user := range users {
		view := user.graphView()
		if display == nil || strings.HasPrefix(strings.ToLower(view.DisplayName), strings.ToLower(display[1])) {
			values = append(values, view)
		}
	}
	result := map[string]any{"value": values}
	if len(users) == graphPageSize {
		query.Set("$skip", strconv.Itoa(offset+graphPageSize))
		result["@odata.nextLink"] = origin + "/v1.0/users?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, result)
}

func graphUserMutation(w http.ResponseWriter, status int, err error) {
	if err == nil {
		switch status {
		case http.StatusNoContent:
			w.WriteHeader(status)
			return
		case http.StatusConflict:
			graphError(w, http.StatusConflict, "Request_Conflict", "The user already exists.")
			return
		case http.StatusBadRequest:
			graphError(w, http.StatusBadRequest, "Request_BadRequest", "Keycloak rejected the user properties.")
			return
		case http.StatusNotFound:
			graphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The user was not found.")
			return
		}
	}
	graphUnavailable(w)
}

func graphUnavailable(w http.ResponseWriter) {
	graphError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The tenant directory is unavailable.")
}

func graphError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
