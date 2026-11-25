package identity

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
)

type keycloakWebClient struct {
	providerClient
	Name                 string            `json:"name"`
	Protocol             string            `json:"protocol"`
	Public               bool              `json:"publicClient"`
	StandardFlow         bool              `json:"standardFlowEnabled"`
	ImplicitFlow         bool              `json:"implicitFlowEnabled"`
	DirectGrants         bool              `json:"directAccessGrantsEnabled"`
	FullScope            bool              `json:"fullScopeAllowed"`
	RedirectURIs         []string          `json:"redirectUris"`
	WebOrigins           []string          `json:"webOrigins"`
	BrowserBindings      map[string]string `json:"authenticationFlowBindingOverrides"`
	DefaultClientScopes  []string          `json:"defaultClientScopes"`
	OptionalClientScopes []string          `json:"optionalClientScopes"`
	Mappers              []keycloakMapper  `json:"protocolMappers"`
}

const keycloakWebClientProfile = "ocean-web-v1"

func (k keycloakAdmin) reconcileWebClient(ctx context.Context, app Application, browserFlowID string, scope keycloakWebScope) (string, error) {
	if !app.Valid(app.TenantID) || len(app.WebRedirectURIs) == 0 || app.PrincipalID != "" ||
		len(app.Credentials) != 0 || !tenantID.MatchString(browserFlowID) {
		return "", errors.New("a dedicated web application and browser flow are required")
	}
	wanted := keycloakWebClient{
		providerClient: providerClient{ClientID: app.ClientID, Attributes: map[string]string{
			"oceanApplicationId":                        app.ID,
			"oceanClientProfile":                        keycloakWebClientProfile,
			"pkce.code.challenge.method":                "S256",
			"oauth2.device.authorization.grant.enabled": "false",
			"oidc.ciba.grant.enabled":                   "false",
			"standard.token.exchange.enabled":           "false",
			"use.refresh.tokens":                        "false",
			"access.token.lifespan":                     "120",
			"acr.loa.map":                               `{"ocean-web":2}`,
			"minimum.acr.value":                         "ocean-web",
		}},
		Name: app.DisplayName, Protocol: "openid-connect", Public: true, StandardFlow: true,
		RedirectURIs: app.WebRedirectURIs, WebOrigins: []string{}, BrowserBindings: map[string]string{"browser": browserFlowID},
		DefaultClientScopes: []string{"basic"}, OptionalClientScopes: []string{},
		Mappers: []keycloakMapper{
			mapper("ocean-web-assurance", "acr", map[string]string{
				"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "false",
			}),
			mapper("ocean-web-audience", "audience", map[string]string{
				"included.custom.audience": app.ClientID, "id.token.claim": "false", "access.token.claim": "true",
				"userinfo.token.claim": "false",
			}),
		},
	}
	query := url.Values{"clientId": {app.ClientID}, "search": {"false"}, "max": {"2"}}
	lookup := func() ([]keycloakWebClient, error) {
		var clients []keycloakWebClient
		status, err := k.directoryRequest(ctx, app.TenantID, http.MethodGet, "/clients?"+query.Encode(), nil, &clients)
		if err != nil || status != http.StatusOK {
			return nil, errors.New("unable to look up the web application client")
		}
		return clients, nil
	}
	clients, err := lookup()
	if err != nil {
		return "", err
	}
	if len(clients) == 0 {
		// A timeout can leave a committed client. Confirm its exact security
		// settings before returning an ID to the policy reconciler.
		status, createErr := k.directoryRequest(ctx, app.TenantID, http.MethodPost, "/clients", wanted, nil)
		clients, err = lookup()
		if err != nil {
			return "", err
		}
		if len(clients) == 0 && (createErr != nil || status != http.StatusCreated) {
			return "", fmt.Errorf("unable to create the web application client, Keycloak status %d", status)
		}
	}
	if len(clients) != 1 {
		return "", errors.New("unable to confirm the prepared web application client")
	}
	client := clients[0]
	if scope.Name == "" {
		if !client.matchesWebClient(wanted) {
			return "", errors.New("unable to confirm the prepared web application client")
		}
		return client.ID, nil
	}
	if !tenantID.MatchString(scope.ID) || scope.Name != "ocean-web-policy-"+app.ID {
		return "", errors.New("invalid web application policy scope")
	}
	wanted.ID = client.ID
	withScope := wanted
	withScope.DefaultClientScopes = []string{"basic", scope.Name}
	active := withScope
	active.Enabled = true
	if client.matchesWebClient(active) {
		return client.ID, nil
	}
	path := "/clients/" + client.ID
	if client.matchesWebClient(wanted) {
		_, _ = k.directoryRequest(ctx, app.TenantID, http.MethodPut, path+"/default-client-scopes/"+scope.ID, nil, nil)
		clients, err = lookup()
		if err != nil || len(clients) != 1 {
			return "", errors.New("unable to confirm the web application policy scope binding")
		}
		client = clients[0]
	}
	if client.matchesWebClient(active) {
		return client.ID, nil
	}
	if !client.matchesWebClient(withScope) {
		return "", errors.New("unable to confirm the disabled web application with its policy scope")
	}
	_, _ = k.directoryRequest(ctx, app.TenantID, http.MethodPut, path, active, nil)
	clients, err = lookup()
	if err != nil || len(clients) != 1 || !clients[0].matchesWebClient(active) {
		return "", errors.New("unable to confirm the enabled web application with its policy scope")
	}
	return client.ID, nil
}

func (client keycloakWebClient) matchesWebClient(wanted keycloakWebClient) bool {
	if !tenantID.MatchString(client.ID) || client.ClientID != wanted.ClientID || client.Protocol != wanted.Protocol ||
		(wanted.ID != "" && client.ID != wanted.ID) || client.Enabled != wanted.Enabled ||
		!client.Public || !client.StandardFlow || client.ImplicitFlow || client.DirectGrants ||
		client.FullScope || client.Service || len(client.WebOrigins) != 0 || !slices.Equal(client.RedirectURIs, wanted.RedirectURIs) ||
		len(client.BrowserBindings) != 1 || client.BrowserBindings["browser"] != wanted.BrowserBindings["browser"] ||
		!slices.Equal(slices.Sorted(slices.Values(client.DefaultClientScopes)), wanted.DefaultClientScopes) || len(client.OptionalClientScopes) != 0 ||
		len(client.Mappers) != len(wanted.Mappers) {
		return false
	}
	for key, value := range wanted.Attributes {
		if client.Attributes[key] != value {
			return false
		}
	}
	for _, expected := range wanted.Mappers {
		if !slices.ContainsFunc(client.Mappers, func(actual keycloakMapper) bool {
			return actual.Name == expected.Name && actual.Kind == expected.Kind && actual.Protocol == expected.Protocol &&
				maps.Equal(actual.Config, expected.Config)
		}) {
			return false
		}
	}
	return true
}
