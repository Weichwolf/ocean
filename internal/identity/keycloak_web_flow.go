package identity

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
)

const keycloakAuthenticationPath = "/authentication"

type keycloakBrowserFlow struct {
	ID          string `json:"id"`
	Alias       string `json:"alias"`
	Description string `json:"description"`
	Provider    string `json:"providerId"`
	TopLevel    bool   `json:"topLevel"`
	BuiltIn     bool   `json:"builtIn"`
}

type keycloakBrowserExecution struct {
	ID          string `json:"id"`
	Parent      string `json:"parentFlow"`
	Subflow     string `json:"flowId,omitempty"`
	IsSubflow   bool   `json:"authenticatorFlow"`
	Provider    string `json:"authenticator,omitempty"`
	Requirement string `json:"requirement"`
	Priority    int    `json:"priority"`
	Config      string `json:"authenticatorConfig,omitempty"`
}

type keycloakBrowserConfig struct {
	ID     string            `json:"id"`
	Alias  string            `json:"alias"`
	Config map[string]string `json:"config"`
}

type webBrowserProfile struct {
	BrowserID string
	Admission keycloakBrowserFlow
}

func webFlow(tenant, name string, topLevel bool) keycloakBrowserFlow {
	alias := "ocean-web-v1-" + name
	return keycloakBrowserFlow{ID: directoryMapperID(tenant, alias), Alias: alias, Provider: "basic-flow", TopLevel: topLevel,
		Description: "Ocean web browser profile v1 for " + tenant}
}

func (f keycloakBrowserFlow) execution(provider, requirement string, priority int) keycloakBrowserExecution {
	return keycloakBrowserExecution{ID: directoryMapperID(f.ID, "execution-"+provider), Parent: f.ID,
		Provider: provider, Requirement: requirement, Priority: priority}
}

func (f keycloakBrowserFlow) subflow(child keycloakBrowserFlow, requirement string, priority int) keycloakBrowserExecution {
	return keycloakBrowserExecution{ID: directoryMapperID(f.ID, "subflow-"+child.ID), Parent: f.ID, Subflow: child.ID,
		IsSubflow: true, Requirement: requirement, Priority: priority}
}

// ensureWebBrowserProfile installs a browser flow shared by the tenant's web
// clients. The realm's default browser binding stays intact. Admission runs
// after identity, including on the path that reuses an assured cookie.
func (k keycloakAdmin) ensureWebBrowserProfile(ctx context.Context, tenant TenantReservation) (webBrowserProfile, error) {
	var profile webBrowserProfile
	if !tenant.Valid(tenant.TenantID) {
		return profile, fmt.Errorf("invalid tenant reservation for the web browser profile")
	}
	if _, err := k.federationRealm(ctx, tenant); err != nil {
		return profile, err
	}
	id := tenant.TenantID
	browser := webFlow(id, "browser", true)
	identity := webFlow(id, "identity", false)
	interactive := webFlow(id, "interactive", false)
	assured := webFlow(id, "assurance", false)
	methods := webFlow(id, "methods", false)
	password := webFlow(id, "password-otp", false)
	admission := webFlow(id, "admission", false)
	for _, flow := range []keycloakBrowserFlow{browser, identity, interactive, assured, methods, password, admission} {
		if err := k.ensureBrowserFlow(ctx, id, flow); err != nil {
			return profile, err
		}
	}
	level := assured.execution("conditional-level-of-authentication", "REQUIRED", 10)
	config := keycloakBrowserConfig{ID: directoryMapperID(level.ID, "loa-2"), Alias: "ocean-web-v1-assurance",
		Config: map[string]string{"loa-condition-level": "2", "loa-max-age": "3600"}}
	if err := k.ensureBrowserConfig(ctx, id, config); err != nil {
		return profile, err
	}
	level.Config = config.ID
	// Construct the subflows before attaching them to the root. The final
	// admission alternative remains after every managed application branch.
	deny := admission.execution("deny-access-authenticator", "ALTERNATIVE", 10000)
	if err := k.ensureBrowserExecution(ctx, id, deny, ""); err != nil {
		return profile, err
	}
	for _, step := range []struct {
		flow       keycloakBrowserFlow
		executions []keycloakBrowserExecution
	}{
		{password, []keycloakBrowserExecution{password.execution("auth-username-password-form", "REQUIRED", 10), password.execution("auth-otp-form", "REQUIRED", 20)}},
		{methods, []keycloakBrowserExecution{methods.execution("auth-spnego", "ALTERNATIVE", 10), methods.subflow(password, "ALTERNATIVE", 20)}},
		{assured, []keycloakBrowserExecution{level, assured.subflow(methods, "REQUIRED", 20)}},
		{interactive, []keycloakBrowserExecution{interactive.subflow(assured, "CONDITIONAL", 10)}},
		{identity, []keycloakBrowserExecution{identity.execution("auth-cookie", "ALTERNATIVE", 10), identity.subflow(interactive, "ALTERNATIVE", 20)}},
		{browser, []keycloakBrowserExecution{browser.subflow(identity, "REQUIRED", 10), browser.subflow(admission, "REQUIRED", 20)}},
	} {
		for _, execution := range step.executions {
			configAlias := ""
			if execution.Config != "" {
				configAlias = config.Alias
			}
			if err := k.ensureBrowserExecution(ctx, id, execution, configAlias); err != nil {
				return profile, err
			}
		}
		if err := k.checkBrowserExecutions(ctx, id, step.flow, step.executions); err != nil {
			return profile, err
		}
	}
	return webBrowserProfile{BrowserID: browser.ID, Admission: admission}, nil
}

func (k keycloakAdmin) ensureBrowserFlow(ctx context.Context, tenant string, wanted keycloakBrowserFlow) error {
	return confirmKeycloakObject(ctx, k, tenant, keycloakAuthenticationPath+"/flows", wanted.ID, wanted, func(actual keycloakBrowserFlow) bool {
		return wanted == actual
	})
}

func (k keycloakAdmin) ensureBrowserConfig(ctx context.Context, tenant string, wanted keycloakBrowserConfig) error {
	return confirmKeycloakObject(ctx, k, tenant, keycloakAuthenticationPath+"/config", wanted.ID, wanted, func(actual keycloakBrowserConfig) bool {
		return actual.ID == wanted.ID && actual.Alias == wanted.Alias && maps.Equal(actual.Config, wanted.Config)
	})
}

func (k keycloakAdmin) ensureBrowserExecution(ctx context.Context, tenant string, wanted keycloakBrowserExecution, configAlias string) error {
	request := wanted
	// Keycloak accepts the configuration alias on create and returns its UUID.
	request.Config = configAlias
	return confirmKeycloakObject(ctx, k, tenant, keycloakAuthenticationPath+"/executions", wanted.ID, request, func(actual keycloakBrowserExecution) bool {
		return wanted == actual
	})
}

func confirmKeycloakObject[T any](ctx context.Context, k keycloakAdmin, tenant, collection, id string,
	input T, matches func(T) bool) error {
	var actual T
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, collection+"/"+id, nil, &actual)
	if err == nil && status == http.StatusNotFound {
		// Using deterministic IDs also covers concurrent writers or a committed
		// create whose response was lost.
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, collection, input, nil)
		status, err = k.directoryRequest(ctx, tenant, http.MethodGet, collection+"/"+id, nil, &actual)
	}
	if err != nil || status != http.StatusOK || !matches(actual) {
		return fmt.Errorf("unable to confirm the Keycloak object %s/%s", collection, id)
	}
	return nil
}

func (k keycloakAdmin) checkBrowserExecutions(ctx context.Context, tenant string, flow keycloakBrowserFlow, expected []keycloakBrowserExecution) error {
	var executions []struct {
		ID    string `json:"id"`
		Level int    `json:"level"`
	}
	path := keycloakAuthenticationPath + "/flows/" + url.PathEscape(flow.Alias) + "/executions"
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &executions)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("unable to read executions for Keycloak flow %q", flow.Alias)
	}
	var direct []string
	for _, execution := range executions {
		if execution.Level == 0 {
			direct = append(direct, execution.ID)
		}
	}
	if !slices.EqualFunc(direct, expected, func(id string, execution keycloakBrowserExecution) bool { return id == execution.ID }) {
		return fmt.Errorf("unexpected execution order or membership in Keycloak flow %q", flow.Alias)
	}
	return nil
}
