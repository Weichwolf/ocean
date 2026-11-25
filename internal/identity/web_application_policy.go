package identity

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

// WebDirectoryConfig locates the pre-authorized LDAPS connectors and reader
// credential for a specific managed directory in the regional process config.
type WebDirectoryConfig struct {
	DirectoryID      string    `json:"directoryId"`
	DomainSID        string    `json:"domainSid"`
	Connectors       [2]string `json:"connectors"`
	ReaderSecretFile string    `json:"readerSecretFile"`
}

func (d WebDirectoryConfig) valid() bool {
	health := enrollment.DirectoryHealth{Ready: true, DomainSID: d.DomainSID}
	return tenantID.MatchString(d.DirectoryID) && health.Valid() && d.Connectors[0] != d.Connectors[1] &&
		validLDAPSConnector(d.Connectors[0]) && validLDAPSConnector(d.Connectors[1]) && d.ReaderSecretFile != ""
}

type webApplicationPolicy struct {
	DirectoryID string   `json:"directoryId"`
	GroupIDs    []string `json:"groupIds"`
	NativeID    string   `json:"nativeId,omitempty"`
}

func (p webApplicationPolicy) valid() bool {
	return tenantID.MatchString(p.DirectoryID) && validWebGroupIDs(p.GroupIDs) &&
		(p.NativeID == "" || tenantID.MatchString(p.NativeID))
}

func validWebGroupIDs(ids []string) bool {
	if len(ids) == 0 || len(ids) > 32 {
		return false
	}
	for index, id := range ids {
		if !tenantID.MatchString(id) || (index > 0 && ids[index-1] >= id) {
			return false
		}
	}
	return true
}

var errWebPolicyConflict = errors.New("the web application already has a different directory group policy")

func (c *Compatibility) manageWebApplication(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation) {
	w.Header().Set("Cache-Control", "no-store")
	app, err := lookupGraphApplication(ctx, c.onboarding.store, tenant.TenantID, "id", req.PathValue("application"))
	if errors.Is(err, errDirectoryNotFound) || (app != nil && len(app.WebRedirectURIs) == 0) {
		armError(w, http.StatusNotFound, "ResourceNotFound", "The tenant web application was not found.")
		return
	}
	if err != nil {
		directoryError(w, err)
		return
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		if app.WebPolicy == nil {
			armError(w, http.StatusNotFound, "ResourceNotFound", "The web application has no directory group policy.")
			return
		}
		c.writeWebApplicationPolicy(w, *app)
		return
	}
	var request struct {
		GroupIDs []string `json:"groupIds"`
	}
	if !decodeGraphBody(w, req, &request) {
		armError(w, http.StatusBadRequest, "InvalidRequest", "Submit a single web application group policy.")
		return
	}
	slices.Sort(request.GroupIDs)
	if !validWebGroupIDs(request.GroupIDs) {
		armError(w, http.StatusBadRequest, "InvalidGroupIds", "Specify one to 32 distinct managed directory group object IDs.")
		return
	}
	directory, err := c.directories.LookupManagedDirectory(ctx, tenant)
	if err != nil {
		directoryError(w, err)
		return
	}
	configuration := c.onboarding.config.WebDirectories[tenant.TenantID]
	if directory == nil || !directory.Valid(tenant) || directory.ProvisionedAt.IsZero() ||
		configuration.DirectoryID != directory.ID || configuration.DomainSID != directory.DomainSID {
		armError(w, http.StatusConflict, "WebDirectoryUnavailable", "The managed directory is not configured for web sign-in.")
		return
	}
	wanted := webApplicationPolicy{DirectoryID: directory.ID, GroupIDs: request.GroupIDs}
	if app.WebPolicy != nil && !app.WebPolicy.sameGrant(wanted) {
		webPolicyConflict(w)
		return
	}
	if app.WebPolicy == nil {
		if !c.checkWebApplicationGroups(ctx, w, tenant, request.GroupIDs) {
			return
		}
		app, err = updateGraphApplication(ctx, c.onboarding.store, tenant.TenantID, app.ID, func(current *Application) error {
			if current.WebPolicy == nil {
				current.WebPolicy = &wanted
			} else if !current.WebPolicy.sameGrant(wanted) {
				return errWebPolicyConflict
			}
			return nil
		})
		if errors.Is(err, errWebPolicyConflict) {
			webPolicyConflict(w)
			return
		}
		if err != nil {
			directoryError(w, err)
			return
		}
	}
	secret, err := readPrivateFile(configuration.ReaderSecretFile)
	if err != nil {
		webPolicyUnavailable(w)
		return
	}
	admin := c.onboarding.admin
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, *directory, configuration.Connectors, secret); err != nil {
		webPolicyUnavailable(w)
		return
	}
	providerID, err := admin.publishDirectoryWebApplication(ctx, tenant, *directory, *app, request.GroupIDs)
	if err != nil {
		webPolicyUnavailable(w)
		return
	}
	published, err := updateGraphApplication(ctx, c.onboarding.store, tenant.TenantID, app.ID, func(current *Application) error {
		if current.WebPolicy == nil || !current.WebPolicy.sameGrant(wanted) ||
			(current.WebPolicy.NativeID != "" && current.WebPolicy.NativeID != providerID) {
			return errWebPolicyConflict
		}
		current.WebPolicy.NativeID = providerID
		return nil
	})
	if err != nil {
		webPolicyUnavailable(w)
		return
	}
	c.writeWebApplicationPolicy(w, *published)
}

func (p webApplicationPolicy) sameGrant(other webApplicationPolicy) bool {
	return p.DirectoryID == other.DirectoryID && slices.Equal(p.GroupIDs, other.GroupIDs)
}

func (c *Compatibility) checkWebApplicationGroups(ctx context.Context, w http.ResponseWriter, tenant TenantReservation, groups []string) bool {
	store, enabled := c.directories.(managedGraphStore)
	if !enabled {
		webPolicyUnavailable(w)
		return false
	}
	for _, id := range groups {
		result, err := store.RunDirectoryGraph(ctx, tenant, enrollment.DirectoryGraphInput{Operation: enrollment.DirectoryGroupGet, Selector: id})
		if err != nil || (result.Status != http.StatusOK && result.Status != http.StatusNotFound) {
			webPolicyUnavailable(w)
			return false
		}
		if result.Status == http.StatusNotFound || result.Group == nil || result.Group.ID != id || !result.Group.Security {
			armError(w, http.StatusBadRequest, "InvalidDirectoryGroup", "Use security groups from this tenant's managed directory.")
			return false
		}
	}
	return true
}

func (c *Compatibility) writeWebApplicationPolicy(w http.ResponseWriter, app Application) {
	policy := app.WebPolicy
	state := "Pending"
	if policy.NativeID != "" {
		state = "Succeeded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": directoryPath(app.TenantID) + "/webApplications/" + app.ID, "appId": app.ClientID,
		"properties": map[string]any{"directoryId": policy.DirectoryID, "groupIds": policy.GroupIDs,
			"issuer": c.provider + "/realms/" + app.TenantID, "provisioningState": state},
	})
}

func webPolicyConflict(w http.ResponseWriter) {
	armError(w, http.StatusConflict, "WebApplicationPolicyConflict", "Replay the web application's original managed directory group policy.")
}

func webPolicyUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "2")
	armError(w, http.StatusServiceUnavailable, "WebApplicationPolicyUnavailable", "Retry the same web application group policy when the directory and identity provider are available.")
}
