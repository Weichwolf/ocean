package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// Application is the durable directory record for a tenant-owned application.
type Application struct {
	TenantID    string             `json:"tenantId"`
	ID          string             `json:"id"`
	ClientID    string             `json:"appId"`
	DisplayName string             `json:"displayName"`
	PrincipalID string             `json:"principalId,omitempty"`
	Credentials []ClientCredential `json:"credentials,omitempty"`
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
		tenantID.MatchString(a.ClientID) && (a.PrincipalID == "" || tenantID.MatchString(a.PrincipalID)) && a.DisplayName != ""
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
