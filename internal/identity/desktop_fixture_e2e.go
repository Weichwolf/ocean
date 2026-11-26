//go:build e2e

package identity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

// DesktopBrowserFixture prepares a disposable application through the same
// Keycloak administration paths used by the managed web application provider.
type DesktopBrowserFixture struct {
	ApplicationID string
	ClientID      string
	Callback      string
	GroupID       string
	User          string
	OTPSecret     string
}

func (c *Compatibility) PrepareDesktopBrowserFixture(ctx context.Context, tenant TenantReservation,
	directory ManagedDirectory, fixture DesktopBrowserFixture) error {
	if c.onboarding == nil {
		return errors.New("the desktop fixture requires tenant onboarding")
	}
	cfg := c.onboarding.config.WebDirectories[tenant.TenantID]
	if cfg.DesktopApplicationID != fixture.ApplicationID || cfg.DirectoryID != directory.ID {
		return errors.New("the desktop fixture is not pre-authorized")
	}
	admin := c.onboarding.admin
	input := onboardingRequest{DisplayName: "Disposable managed desktop",
		AdministratorUPN: "desktop-fixture-admin@example.test", AdministratorPassword: "Oc9-" + rand.Text() + rand.Text()}
	if err := admin.ensureRealm(ctx, tenant, tenantRealm(tenant, input,
		c.cloud, c.onboarding.derive("keycloak-token-exchange", tenant.TenantID))); err != nil {
		return err
	}
	bind, err := readPrivateFile(cfg.ReaderSecretFile)
	if err != nil {
		return err
	}
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, directory, cfg.Connectors, bind,
		cfg.kerberos(c.provider, directory.Spec.DNSName)); err != nil {
		return err
	}
	app := Application{TenantID: tenant.TenantID, ID: fixture.ApplicationID, ClientID: fixture.ClientID,
		DisplayName: "Disposable Ocean Desktop", WebRedirectURIs: []string{fixture.Callback}}
	groupIDs := []string{fixture.GroupID}
	native, err := admin.publishDirectoryWebApplication(ctx, tenant, directory, app, groupIDs, true)
	if err != nil {
		return err
	}
	app.WebPolicy = &webApplicationPolicy{DirectoryID: directory.ID, NativeID: native, GroupIDs: groupIDs}
	saved, err := c.onboarding.store.SaveApplication(ctx, app, 0)
	if err != nil || !saved {
		return errors.New("could not store the disposable desktop app")
	}
	query := url.Values{"username": {fixture.User}, "exact": {"true"}}.Encode()
	var users []directoryUser
	status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users?"+query, nil, &users)
	if err != nil || status != http.StatusOK || len(users) != 1 || users[0].FederationLink != directory.ID {
		return errors.New("could not locate the disposable Samba desktop user")
	}
	secretData, err := json.Marshal(map[string]string{"value": fixture.OTPSecret})
	if err != nil {
		return err
	}
	credential := map[string]any{"credentials": []map[string]string{{"type": "otp", "userLabel": "Disposable desktop probe",
		"secretData": string(secretData), "credentialData": `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1","counter":0,"secretEncoding":"BASE32"}`}}}
	status, err = admin.directoryRequest(ctx, tenant.TenantID, http.MethodPut, "/users/"+users[0].ID, credential, nil)
	if err != nil || status != http.StatusNoContent {
		return errors.New("could not enroll the disposable desktop user's OTP")
	}
	return nil
}

func (c *Compatibility) DeleteDesktopBrowserFixture(ctx context.Context, tenant TenantReservation) error {
	if c.onboarding == nil {
		return errors.New("the desktop fixture requires tenant onboarding")
	}
	admin := c.onboarding.admin
	var realm struct {
		Attributes map[string]string `json:"attributes"`
	}
	status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "", nil, &realm)
	if err == nil && status == http.StatusNotFound {
		return nil
	}
	if err != nil || status != http.StatusOK || realm.Attributes["oceanRegistration"] != tenant.SubscriptionID {
		return errors.New("could not confirm ownership of the disposable realm")
	}
	status, err = admin.directoryRequest(ctx, tenant.TenantID, http.MethodDelete, "", nil, nil)
	if err != nil || status != http.StatusNoContent {
		return errors.New("could not remove the disposable realm")
	}
	return nil
}
