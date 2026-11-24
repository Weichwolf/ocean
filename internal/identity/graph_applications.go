package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

type applicationInput struct {
	DisplayName string            `json:"displayName"`
	Audience    string            `json:"signInAudience"`
	Identifiers []string          `json:"identifierUris"`
	Keys        []json.RawMessage `json:"keyCredentials"`
}

type passwordMetadata struct {
	ID          string    `json:"keyId"`
	DisplayName string    `json:"displayName"`
	Start       time.Time `json:"startDateTime"`
	End         time.Time `json:"endDateTime"`
}

func (c *Compatibility) graphApplication(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.MicrosoftGraph, "https://")) {
		http.NotFound(w, req)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	tenant := c.graphTenant(ctx, w, req)
	if tenant == nil {
		return
	}
	store := c.onboarding.store
	id := req.PathValue("application")
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		if id == "" {
			c.listGraphApplications(ctx, w, req, tenant.TenantID, false)
			return
		}
		app := findGraphApplication(ctx, w, req, store, tenant.TenantID, "id", id)
		if app != nil {
			writeJSON(w, http.StatusOK, app.graphView())
		}
		return
	}
	var input applicationInput
	if req.URL.RawQuery != "" || !decodeGraphBody(w, req, &input) || !validGraphDisplayName(input.DisplayName) ||
		(input.Audience != "" && input.Audience != "AzureADMyOrg") || len(input.Identifiers) != 0 || len(input.Keys) != 0 {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Configure the display name of a single-tenant application.")
		return
	}
	if req.Method == http.MethodPost {
		app := Application{TenantID: tenant.TenantID, ID: newUUID(), ClientID: newUUID(), DisplayName: input.DisplayName}
		if saved, err := store.SaveApplication(ctx, app, 0); err != nil || !saved {
			graphUnavailable(w)
			return
		}
		writeJSON(w, http.StatusCreated, app.graphView())
		return
	}
	_, err := updateGraphApplication(ctx, store, tenant.TenantID, id, func(app *Application) error {
		app.DisplayName = input.DisplayName
		return nil
	})
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeGraphBody(w http.ResponseWriter, req *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 16<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(new(any)) == io.EOF
}

func validGraphDisplayName(name string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 120 && !strings.ContainsFunc(name, unicode.IsControl)
}

func (app Application) graphView() map[string]any {
	passwords := make([]passwordMetadata, 0, len(app.Credentials))
	for _, cred := range app.Credentials {
		passwords = append(passwords, cred.metadata())
	}
	return map[string]any{"id": app.ID, "appId": app.ClientID, "displayName": app.DisplayName, "signInAudience": "AzureADMyOrg",
		"identifierUris": []string{}, "passwordCredentials": passwords, "keyCredentials": []any{}}
}

func (cred ClientCredential) metadata() passwordMetadata {
	return passwordMetadata{cred.ID, cred.DisplayName, cred.Start, cred.End}
}

func (app Application) principalView() map[string]any {
	return map[string]any{"id": app.PrincipalID, "appId": app.ClientID, "displayName": app.DisplayName,
		"accountEnabled": true, "servicePrincipalType": "Application", "appOwnerOrganizationId": app.TenantID,
		"servicePrincipalNames": []string{app.ClientID}}
}

var graphClientFilter = regexp.MustCompile(`^appId eq '([0-9a-f-]+)'$`)
var graphPrincipalName = regexp.MustCompile(`^servicePrincipalNames/any\(c:c eq '([0-9a-f-]+)'\)$`)
var graphExactName = regexp.MustCompile(`^displayName eq '([^']+)'$`)

func (c *Compatibility) listGraphApplications(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant string, principals bool) {
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid directory query.")
		return
	}
	for key, values := range query {
		if len(values) != 1 || (key != "$filter" && key != "$skiptoken") {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", "Unsupported directory query parameter.")
			return
		}
	}
	after := query.Get("$skiptoken")
	if query.Has("$skiptoken") && !tenantID.MatchString(after) {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid application page.")
		return
	}
	store := c.onboarding.store
	response := make([]map[string]any, 0)
	filter := query.Get("$filter")
	match := graphClientFilter.FindStringSubmatch(filter)
	if match == nil && principals {
		match = graphPrincipalName.FindStringSubmatch(filter)
	}
	if match != nil && after == "" && tenantID.MatchString(match[1]) {
		app, _, err := store.FindApplication(ctx, tenant, "appId", match[1])
		if err != nil {
			graphUnavailable(w)
			return
		}
		if app != nil && (!principals || app.PrincipalID != "") {
			response = append(response, graphObjectView(*app, principals))
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": response})
		return
	}
	prefix := graphNameFilter.FindStringSubmatch(filter)
	exact := graphExactName.FindStringSubmatch(filter)
	if query.Has("$filter") && prefix == nil && exact == nil {
		graphError(w, http.StatusBadRequest, "Request_UnsupportedQuery", "The directory filter is unsupported.")
		return
	}
	apps, err := store.ListApplications(ctx, tenant, after, graphPageSize)
	if err != nil {
		graphUnavailable(w)
		return
	}
	for _, app := range apps {
		if (principals && app.PrincipalID == "") ||
			(prefix != nil && !strings.HasPrefix(strings.ToLower(app.DisplayName), strings.ToLower(prefix[1]))) ||
			(exact != nil && !strings.EqualFold(app.DisplayName, exact[1])) {
			continue
		}
		response = append(response, graphObjectView(app, principals))
	}
	result := map[string]any{"value": response}
	if len(apps) == graphPageSize {
		query.Set("$skiptoken", apps[len(apps)-1].ID)
		result["@odata.nextLink"] = c.cloud.MicrosoftGraph + req.URL.Path + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, result)
}

func graphObjectView(app Application, principals bool) map[string]any {
	if principals {
		return app.principalView()
	}
	return app.graphView()
}

func findGraphApplication(ctx context.Context, w http.ResponseWriter, req *http.Request, store ApplicationStore,
	tenant, field, id string) *Application {
	if req.URL.RawQuery != "" {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Unsupported directory query parameter.")
		return nil
	}
	app, err := lookupGraphApplication(ctx, store, tenant, field, id)
	if err != nil {
		writeApplicationError(w, err)
		return nil
	}
	return app
}

func lookupGraphApplication(ctx context.Context, store ApplicationStore, tenant, field, id string) (*Application, error) {
	if !tenantID.MatchString(id) {
		return nil, errDirectoryNotFound
	}
	app, _, err := store.FindApplication(ctx, tenant, field, id)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errDirectoryNotFound
	}
	return app, nil
}

var (
	errDirectoryNotFound = errors.New("directory object not found")
	errCredentialLimit   = errors.New("application credential limit reached")
)

func updateGraphApplication(ctx context.Context, store ApplicationStore, tenant, id string, update func(*Application) error) (*Application, error) {
	if !tenantID.MatchString(id) {
		return nil, errDirectoryNotFound
	}
	for range 10 {
		app, revision, err := store.FindApplication(ctx, tenant, "id", id)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, errDirectoryNotFound
		}
		if err := update(app); err != nil {
			return nil, err
		}
		saved, err := store.SaveApplication(ctx, *app, revision)
		if err != nil || saved {
			return app, err
		}
	}
	return nil, errors.New("application changed concurrently")
}

func writeApplicationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errDirectoryNotFound):
		graphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The directory object was not found.")
	case errors.Is(err, errCredentialLimit):
		graphError(w, http.StatusConflict, "Request_Conflict", "The application already has 64 credentials.")
	default:
		graphUnavailable(w)
	}
}

func (c *Compatibility) graphAppCredential(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.MicrosoftGraph, "https://")) {
		http.NotFound(w, req)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	tenant := c.graphTenant(ctx, w, req)
	if tenant == nil {
		return
	}
	if req.URL.RawQuery != "" {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Unsupported directory query parameter.")
		return
	}
	id := req.PathValue("application")
	store := c.onboarding.store
	if strings.HasSuffix(req.URL.Path, "/removePassword") {
		var input struct {
			ID string `json:"keyId"`
		}
		if !decodeGraphBody(w, req, &input) || !tenantID.MatchString(input.ID) {
			graphError(w, http.StatusBadRequest, "Request_BadRequest", "Specify the credential ID.")
			return
		}
		_, err := updateGraphApplication(ctx, store, tenant.TenantID, id, func(app *Application) error {
			app.Credentials = slices.DeleteFunc(app.Credentials, func(cred ClientCredential) bool { return cred.ID == input.ID })
			return nil
		})
		if err != nil {
			writeApplicationError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input struct {
		Password struct {
			DisplayName string    `json:"displayName"`
			Start       time.Time `json:"startDateTime"`
			End         time.Time `json:"endDateTime"`
		} `json:"passwordCredential"`
	}
	if !decodeGraphBody(w, req, &input) {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Configure one password credential.")
		return
	}
	requested := input.Password
	if requested.DisplayName != "" && !validGraphDisplayName(requested.DisplayName) {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Invalid credential display name.")
		return
	}
	now := time.Now().UTC()
	if requested.Start.IsZero() {
		requested.Start = now
	}
	if requested.End.IsZero() {
		requested.End = requested.Start.AddDate(1, 0, 0)
	}
	if !requested.End.After(now) || !requested.End.After(requested.Start) || requested.End.After(requested.Start.AddDate(2, 0, 0)) {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", "Choose a credential expiration within two years.")
		return
	}
	secret := newClientSecret()
	credential := ClientCredential{ID: newUUID(), DisplayName: requested.DisplayName, Start: requested.Start.UTC(), End: requested.End.UTC()}
	_, err := updateGraphApplication(ctx, store, tenant.TenantID, id, func(app *Application) error {
		if len(app.Credentials) >= 64 {
			return errCredentialLimit
		}
		credential.Verifier = c.onboarding.credentialVerifier(tenant.TenantID, app.ClientID, secret)
		app.Credentials = append(app.Credentials, credential)
		return nil
	})
	if err != nil {
		writeApplicationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		passwordMetadata
		Secret string `json:"secretText"`
	}{credential.metadata(), secret})
}
