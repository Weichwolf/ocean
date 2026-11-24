package identity

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Compatibility) graphPrincipal(w http.ResponseWriter, req *http.Request) {
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
	store := c.onboarding.store
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		id := req.PathValue("principal")
		if id == "" {
			c.listGraphApplications(ctx, w, req, tenant.TenantID, true)
			return
		}
		app := findGraphApplication(ctx, w, req, store, tenant.TenantID, "principalId", id)
		if app != nil {
			writeJSON(w, http.StatusOK, app.principalView())
		}
		return
	}
	var input struct {
		Client  string `json:"appId"`
		Enabled *bool  `json:"accountEnabled"`
	}
	if req.URL.RawQuery != "" || !decodeGraphBody(w, req, &input) || !tenantID.MatchString(input.Client) ||
		(input.Enabled != nil && !*input.Enabled) {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Specify the app ID for an enabled service principal.")
		return
	}
	app, err := lookupGraphApplication(ctx, store, tenant.TenantID, "appId", input.Client)
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	if app.PrincipalID != "" {
		writeJSON(w, http.StatusOK, app.principalView())
		return
	}
	subject, err := c.onboarding.admin.ensureServicePrincipal(ctx, *app, c.cloud, c.onboarding.providerClientSecret(tenant.TenantID, app.ClientID))
	if err != nil {
		graphUnavailable(w)
		return
	}
	published, err := updateGraphApplication(ctx, store, tenant.TenantID, app.ID, func(current *Application) error {
		if current.PrincipalID != "" && current.PrincipalID != subject {
			return errors.New("the service principal identity changed concurrently")
		}
		current.PrincipalID = subject
		return nil
	})
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, published.principalView())
}

type providerClient struct {
	ID         string            `json:"id"`
	ClientID   string            `json:"clientId"`
	Enabled    bool              `json:"enabled"`
	Service    bool              `json:"serviceAccountsEnabled"`
	Attributes map[string]string `json:"attributes"`
}

func (k keycloakAdmin) ensureServicePrincipal(ctx context.Context, app Application, cloud CloudEndpoints, secret string) (string, error) {
	tenant := app.TenantID
	query := url.Values{"clientId": {app.ClientID}, "search": {"false"}, "max": {"2"}}
	lookup := func() ([]providerClient, error) {
		var clients []providerClient
		status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/clients?"+query.Encode(), nil, &clients)
		if err != nil || status != http.StatusOK {
			return nil, errors.New("unable to look up the service account client")
		}
		return clients, nil
	}
	clients, err := lookup()
	if err != nil {
		return "", err
	}
	if len(clients) == 0 {
		payload := map[string]any{
			"clientId": app.ClientID, "name": app.DisplayName, "protocol": "openid-connect",
			"enabled": true, "publicClient": false, "fullScopeAllowed": false,
			"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
			"clientAuthenticatorType": "client-secret", "secret": secret,
			"attributes":           map[string]string{"oceanApplicationId": app.ID},
			"defaultClientScopes":  []string{"basic"},
			"optionalClientScopes": []string{cloud.ResourceManager + "/.default", cloud.MicrosoftGraph + "/.default"},
		}
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, "/clients", payload, nil)
		clients, err = lookup()
		if err != nil {
			return "", err
		}
	}
	if len(clients) != 1 || clients[0].ClientID != app.ClientID || !tenantID.MatchString(clients[0].ID) ||
		!clients[0].Enabled || !clients[0].Service || clients[0].Attributes["oceanApplicationId"] != app.ID {
		return "", errors.New("unable to confirm the service account client")
	}
	var account struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/clients/"+clients[0].ID+"/service-account-user", nil, &account)
	if err != nil || status != http.StatusOK || !tenantID.MatchString(account.ID) || !account.Enabled {
		return "", errors.New("unable to confirm the service principal identity")
	}
	return account.ID, nil
}
