package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

type keycloakWebScope struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	Attributes map[string]string `json:"attributes"`
}

type keycloakWebRole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Container   string `json:"containerId"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"clientRole"`
}

// publishDirectoryWebApplication reconciles a single immutable group policy.
// It attaches the admission execution before enabling the native client.
func (k keycloakAdmin) publishDirectoryWebApplication(ctx context.Context, tenant TenantReservation, directory ManagedDirectory,
	app Application, groupIDs []string) (string, error) {
	if !directory.Valid(tenant) || directory.ProvisionedAt.IsZero() || !app.Valid(tenant.TenantID) ||
		len(app.WebRedirectURIs) == 0 || app.PrincipalID != "" || len(app.Credentials) != 0 {
		return "", errors.New("an established directory and dedicated web registration are required")
	}
	filter, err := directoryObjectGUIDFilter(groupIDs)
	if err != nil {
		return "", err
	}
	id := tenant.TenantID
	realmID, err := k.federationRealm(ctx, tenant)
	if err != nil {
		return "", err
	}
	baseDN := "DC=" + strings.ReplaceAll(directory.Spec.DNSName, ".", ",DC=")
	var provider keycloakComponent
	status, err := k.directoryRequest(ctx, id, http.MethodGet, "/components/"+directory.ID, nil, &provider)
	if err != nil || status != http.StatusOK || provider.ID != directory.ID || provider.ParentID != realmID ||
		provider.Name != "Ocean Samba AD "+directory.ID || provider.ProviderType != keycloakUserStorageType || provider.ProviderID != "ldap" ||
		!slices.Equal(provider.Config["enabled"], []string{"true"}) || !slices.Equal(provider.Config["cachePolicy"], []string{"NO_CACHE"}) ||
		!slices.Equal(provider.Config["usersDn"], []string{"OU=Ocean Workforce Users," + baseDN}) {
		return "", errors.New("unable to confirm the managed directory federation for the web application")
	}
	if err := k.checkDirectoryAccountMapper(ctx, id, directory.ID); err != nil {
		return "", err
	}
	profile, err := k.ensureWebBrowserProfile(ctx, tenant)
	if err != nil {
		return "", err
	}
	rootName := "ocean-web-grant-" + app.ID
	rootID, err := k.ensureDirectoryGroupRoot(ctx, id, rootName)
	if err != nil {
		return "", err
	}
	groupMapper := keycloakComponent{ID: directoryMapperID(app.ID, "web-allowed-groups"), Name: "Ocean web grants " + app.ID,
		ParentID: directory.ID, ProviderType: keycloakLDAPMapperType, ProviderID: "group-ldap-mapper",
		Config: directoryGroupMapperConfig(baseDN, rootName, filter)}
	if err := k.ensureDirectoryComponent(ctx, id, groupMapper); err != nil {
		return "", err
	}
	role, err := k.ensureWebGrantRole(ctx, id, realmID, rootID, app)
	if err != nil {
		return "", err
	}
	scope := keycloakWebScope{ID: directoryMapperID(app.ID, "web-policy-scope"), Name: "ocean-web-policy-" + app.ID, Protocol: "openid-connect",
		Attributes: map[string]string{"include.in.token.scope": "false", "oceanApplicationId": app.ID}}
	if err := confirmKeycloakObject(ctx, k, id, "/client-scopes", scope.ID, scope, func(actual keycloakWebScope) bool {
		return actual.ID == scope.ID && actual.Name == scope.Name && actual.Protocol == scope.Protocol &&
			actual.Attributes["include.in.token.scope"] == "false" && actual.Attributes["oceanApplicationId"] == app.ID
	}); err != nil {
		return "", err
	}
	if err := k.ensureApplicationAdmission(ctx, app, profile.Admission, scope.Name, role.Name); err != nil {
		return "", err
	}
	return k.reconcileWebClient(ctx, app, profile.BrowserID, scope)
}

func directoryObjectGUIDFilter(groupIDs []string) (string, error) {
	ids := slices.Clone(groupIDs)
	slices.Sort(ids)
	if !validWebGroupIDs(ids) {
		return "", errors.New("specify between one and 32 unique managed directory group object GUIDs")
	}
	var filter strings.Builder
	filter.WriteString("(|")
	for _, id := range ids {
		value, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil {
			return "", err
		}
		// AD stores the first three fields of objectGUID in little-endian order.
		slices.Reverse(value[:4])
		slices.Reverse(value[4:6])
		slices.Reverse(value[6:8])
		filter.WriteString("(objectGUID=")
		for _, octet := range value {
			filter.WriteString(fmt.Sprintf("\\%02x", octet))
		}
		filter.WriteByte(')')
	}
	filter.WriteByte(')')
	return filter.String(), nil
}

func (k keycloakAdmin) ensureWebGrantRole(ctx context.Context, tenant, realm, group string, app Application) (keycloakWebRole, error) {
	name := "ocean-web-admit-" + app.ID
	description := "Ocean LDAP grant for application " + app.ID
	path := "/roles/" + name
	var role keycloakWebRole
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &role)
	if err == nil && status == http.StatusNotFound {
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, "/roles", map[string]string{"name": name, "description": description}, nil)
		status, err = k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &role)
	}
	if err != nil || status != http.StatusOK || !tenantID.MatchString(role.ID) || role.Container != realm ||
		role.Name != name || role.Description != description || role.Composite || role.ClientRole {
		return role, errors.New("unable to confirm the application admission role")
	}
	path = "/groups/" + group + "/role-mappings/realm"
	var bindings []keycloakWebRole
	status, err = k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &bindings)
	if err == nil && status == http.StatusOK && len(bindings) == 0 {
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, path, []keycloakWebRole{role}, nil)
		status, err = k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &bindings)
	}
	if err != nil || status != http.StatusOK || len(bindings) != 1 || bindings[0].ID != role.ID {
		return role, errors.New("unable to confirm the managed directory admission role binding")
	}
	return role, nil
}

func (k keycloakAdmin) ensureApplicationAdmission(ctx context.Context, app Application, admission keycloakBrowserFlow, scope, role string) error {
	tenant := app.TenantID
	candidate := webFlow(tenant, "candidate-"+app.ID, false)
	authorized := webFlow(tenant, "authorized-"+app.ID, false)
	for _, flow := range []keycloakBrowserFlow{candidate, authorized} {
		if err := k.ensureBrowserFlow(ctx, tenant, flow); err != nil {
			return err
		}
	}
	executions := []keycloakBrowserExecution{
		authorized.execution("conditional-client-scope", "REQUIRED", 10),
		authorized.execution("conditional-user-role", "REQUIRED", 20),
		authorized.execution("allow-access-authenticator", "REQUIRED", 30),
	}
	conditions := []map[string]string{{"client_scope": scope, "negate": "false"}, {"condUserRole": role, "negate": "false"}}
	for index, execution := range executions {
		alias := ""
		if index < len(conditions) {
			config := keycloakBrowserConfig{ID: directoryMapperID(execution.ID, "config"), Alias: "ocean-web-policy-" + execution.ID,
				Config: conditions[index]}
			if err := k.ensureBrowserConfig(ctx, tenant, config); err != nil {
				return err
			}
			execution.Config, alias = config.ID, config.Alias
			executions[index] = execution
		}
		if err := k.ensureBrowserExecution(ctx, tenant, execution, alias); err != nil {
			return err
		}
	}
	if err := k.checkBrowserExecutions(ctx, tenant, authorized, executions); err != nil {
		return err
	}
	gate := candidate.subflow(authorized, "CONDITIONAL", 10)
	if err := k.ensureBrowserExecution(ctx, tenant, gate, ""); err != nil {
		return err
	}
	if err := k.checkBrowserExecutions(ctx, tenant, candidate, []keycloakBrowserExecution{gate}); err != nil {
		return err
	}
	return k.ensureBrowserExecution(ctx, tenant, admission.subflow(candidate, "ALTERNATIVE", 10), "")
}
