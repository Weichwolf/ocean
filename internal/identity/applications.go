package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Application is the durable directory record for a tenant-owned application.
type Application struct {
	TenantID        string                `json:"tenantId"`
	ID              string                `json:"id"`
	ClientID        string                `json:"appId"`
	DisplayName     string                `json:"displayName"`
	PrincipalID     string                `json:"principalId,omitempty"`
	Credentials     []ClientCredential    `json:"credentials,omitempty"`
	WebRedirectURIs []string              `json:"webRedirectUris,omitempty"`
	WebPolicy       *webApplicationPolicy `json:"webPolicy,omitempty"`
}

// ClientCredential stores metadata and a keyed verifier rather than the secret.
type ClientCredential struct {
	ID          string    `json:"keyId"`
	DisplayName string    `json:"displayName"`
	Start       time.Time `json:"startDateTime"`
	End         time.Time `json:"endDateTime"`
	Verifier    string    `json:"verifier"`
}

// ApplicationStore provides linearizable lookup and conditional updates.
type ApplicationStore interface {
	FindApplication(context.Context, string, string, string) (*Application, int64, error)
	ListApplications(context.Context, string, string, int) ([]Application, error)
	SaveApplication(context.Context, Application, int64) (bool, error)
}

func (a Application) Valid(tenant string) bool {
	return a.TenantID == tenant && tenantID.MatchString(a.TenantID) && tenantID.MatchString(a.ID) &&
		tenantID.MatchString(a.ClientID) && (a.PrincipalID == "" || tenantID.MatchString(a.PrincipalID)) && a.DisplayName != "" &&
		validWebRedirectURIs(a.WebRedirectURIs) && (a.WebPolicy == nil || len(a.WebRedirectURIs) != 0 &&
		a.PrincipalID == "" && len(a.Credentials) == 0 && a.WebPolicy.valid())
}

func validWebRedirectURIs(uris []string) bool {
	seen := make(map[string]bool, len(uris))
	for _, uri := range uris {
		if seen[uri] || !validWebRedirectURI(uri) {
			return false
		}
		seen[uri] = true
	}
	return true
}

func validWebRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		strings.HasSuffix(parsed.Host, ":") || strings.ContainsAny(uri, "#\\*") || strings.ContainsFunc(uri, unicode.IsSpace) {
		return false
	}
	decoded, err := url.PathUnescape(uri)
	if err != nil || strings.ContainsAny(decoded, "\\*") || strings.ContainsFunc(decoded, unicode.IsControl) {
		return false
	}
	if value := parsed.Port(); value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		return err == nil && port > 0
	}
	return true
}

func (o *onboarding) credentialVerifier(tenant, client, secret string) string {
	return o.derive("directory-client-credential", tenant+"\x00"+client+"\x00"+secret)
}

func (o *onboarding) providerClientSecret(tenant, client string) string {
	return o.derive("keycloak-service-account", tenant+"\x00"+client)
}

func (o *onboarding) authenticateClient(ctx context.Context, tenant, client, secret string) (privateSecret, subject string, err error) {
	record, err := o.store.LookupTenant(ctx, tenant)
	if err != nil {
		return "", "", err
	}
	if record == nil {
		if tenant == o.config.OperatorTenant && client == o.config.OperatorClient {
			return "", "", nil
		}
		if o.legacyExchange != nil {
			if _, err := o.legacyExchange(tenant); err == nil {
				return "", "", nil
			}
		}
		return "", "", errClientCredential
	}
	if !record.Valid(tenant) {
		return "", "", errors.New("invalid registration")
	}
	app, _, err := o.store.FindApplication(ctx, tenant, "appId", client)
	if err != nil {
		return "", "", err
	}
	if app == nil || app.PrincipalID == "" {
		return "", "", errClientCredential
	}
	now := time.Now()
	verifier := []byte(o.credentialVerifier(tenant, client, secret))
	accepted := false
	for _, key := range app.Credentials {
		if hmac.Equal(verifier, []byte(key.Verifier)) && !now.Before(key.Start) && now.Before(key.End) {
			accepted = true
		}
	}
	if !accepted {
		return "", "", errClientCredential
	}
	return o.providerClientSecret(tenant, client), app.PrincipalID, nil
}

var errClientCredential = errors.New("client credential rejected")

func newClientSecret() string {
	var value [32]byte
	rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}
