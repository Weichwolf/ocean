package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
)

const onboardingVersion = "2026-11-01"

var ErrTenantConflict = errors.New("tenant registration conflicts with an existing allocation")

// OnboardingConfig identifies the operator and the private Keycloak admin API.
type OnboardingConfig struct {
	OperatorTenant  string   `json:"operatorTenant"`
	OperatorClient  string   `json:"operatorClient"`
	AdminEndpoints  []string `json:"adminEndpoints"`
	AdminClient     string   `json:"adminClient"`
	AdminSecretFile string   `json:"adminSecretFile"`
	RegionalKeyFile string   `json:"regionalKeyFile"`
}

// TenantReservation relates an idempotent request to its identities and subscription.
type TenantReservation struct {
	TenantID       string `json:"tenantId"`
	Administrator  string `json:"administratorId"`
	SubscriptionID string `json:"subscriptionId"`
	Fingerprint    string `json:"fingerprint"`
}

// Valid checks the realm, user, and subscription identity of a reservation.
func (r TenantReservation) Valid(tenant string) bool {
	return r.TenantID == tenant && tenantID.MatchString(r.TenantID) &&
		tenantID.MatchString(r.Administrator) && tenantID.MatchString(r.SubscriptionID) && r.Fingerprint != ""
}

// TenantStore provides the regional transactions used by onboarding.
type TenantStore interface {
	ReserveTenant(context.Context, TenantReservation) (TenantReservation, error)
	LookupTenant(context.Context, string) (*TenantReservation, error)
	PublishSubscription(context.Context, TenantReservation, Subscription) (bool, error)
}

type onboarding struct {
	config OnboardingConfig
	admin  keycloakAdmin
	key    []byte
	store  TenantStore
}

type onboardingRequest struct {
	DisplayName           string `json:"displayName"`
	AdministratorUPN      string `json:"administratorUserPrincipalName"`
	AdministratorPassword string `json:"administratorPassword"`
}

// EnableOnboarding binds the operator API and derives tenant credentials from
// the same regional key on every API replica.
func (c *Compatibility) EnableOnboarding(cfg OnboardingConfig, store TenantStore) error {
	if !tenantID.MatchString(cfg.OperatorTenant) || !tenantID.MatchString(cfg.OperatorClient) ||
		cfg.OperatorClient == cliClientID || c.subscriptions == nil || cfg.AdminClient == "" || len(cfg.AdminEndpoints) == 0 {
		return errors.New("onboarding requires operator IDs, cloud endpoints, and Keycloak administration settings")
	}
	for _, endpoint := range cfg.AdminEndpoints {
		if !httpsOrigin(endpoint) || endpoint == c.provider || endpoint == c.authority {
			return errors.New("Keycloak admin endpoints must be private HTTPS origins")
		}
	}
	secret, err := readPrivateFile(cfg.AdminSecretFile)
	if err != nil {
		return fmt.Errorf("read Keycloak admin credential: %w", err)
	}
	key, err := readPrivateFile(cfg.RegionalKeyFile)
	if err != nil {
		return fmt.Errorf("read regional identity key: %w", err)
	}
	if len(key) < 32 || len(secret) < 32 {
		return errors.New("onboarding credentials must contain at least 32 bytes")
	}
	adminClient := *c.client
	adminClient.Timeout = 20 * time.Second
	o := &onboarding{
		config: cfg, key: []byte(key), store: store,
		admin: keycloakAdmin{client: &adminClient, endpoints: cfg.AdminEndpoints, clientID: cfg.AdminClient, secret: secret},
	}
	fixtureSecret := c.exchangeSecret
	c.exchangeSecret = func(tenant string) (string, error) {
		if fixtureSecret != nil {
			secret, err := fixtureSecret(tenant)
			if !errors.Is(err, os.ErrNotExist) {
				return secret, err
			}
		}
		return o.derive("keycloak-token-exchange", tenant), nil
	}
	c.onboarding = o
	return nil
}

func readPrivateFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return "", errors.New("expected a private regular credential file")
	}
	content, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

func (o *onboarding) derive(purpose, value string) string {
	digest := hmac.New(sha256.New, o.key)
	digest.Write([]byte(purpose + "\x00" + value))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func newUUID() string {
	var bytes [16]byte
	rand.Read(bytes[:])
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:])
}

func (c *Compatibility) onboardTenant(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, req)
		return
	}
	o := c.onboarding
	tenant := req.PathValue("tenant")
	ctx, cancel := context.WithTimeout(req.Context(), 24*time.Second)
	defer cancel()
	raw, issuer, caller := c.bearerRealm(req)
	if caller == "" {
		invalidARMToken(w)
		return
	}
	if caller != o.config.OperatorTenant {
		armError(w, http.StatusForbidden, "AuthorizationFailed", "Tenant registration requires an ocean operator.")
		return
	}
	token, err := c.verifyAccessToken(ctx, raw, issuer, c.cloud.ResourceManager)
	var actor struct {
		Client string `json:"azp"`
		Type   string `json:"typ"`
	}
	if err != nil || token.Claims(&actor) != nil || actor.Type != "Bearer" {
		invalidARMToken(w)
		return
	}
	if actor.Client != o.config.OperatorClient {
		armError(w, http.StatusForbidden, "AuthorizationFailed", "Tenant registration requires an ocean operator.")
		return
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["api-version"]) != 1 || query.Get("api-version") != onboardingVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Tenant registration requires api-version="+onboardingVersion+".")
		return
	}
	if !tenantID.MatchString(tenant) || tenant == o.config.OperatorTenant {
		armError(w, http.StatusBadRequest, "InvalidTenant", "Use a customer tenant UUID.")
		return
	}
	input, err := readOnboardingRequest(http.MaxBytesReader(w, req.Body, 16<<10))
	if err != nil {
		armError(w, http.StatusBadRequest, "InvalidRequest", err.Error())
		return
	}
	fingerprint, _ := json.Marshal(input)
	reservation, err := o.store.ReserveTenant(ctx, TenantReservation{
		TenantID: tenant, Administrator: newUUID(), SubscriptionID: newUUID(),
		Fingerprint: o.derive("onboarding-request", tenant+"\x00"+string(fingerprint)),
	})
	if err != nil {
		tenantWriteError(w, err)
		return
	}
	existing, err := c.subscriptions.lookup(ctx, tenant)
	switch {
	case err != nil:
		tenantWriteError(w, err)
		return
	case existing != nil:
		if !existing.Valid(tenant) || existing.SubscriptionID != reservation.SubscriptionID {
			tenantWriteError(w, ErrTenantConflict)
			return
		}
		writeJSON(w, http.StatusOK, reservation.view())
		return
	}
	exchange, err := c.exchangeSecret(tenant)
	if err != nil {
		tenantWriteError(w, err)
		return
	}
	realm := tenantRealm(reservation, input, c.cloud, exchange)
	if err := o.admin.ensureRealm(ctx, reservation, realm); err != nil {
		tenantWriteError(w, err)
		return
	}
	subscription := Subscription{
		TenantID: tenant, SubscriptionID: reservation.SubscriptionID, DisplayName: input.DisplayName,
		Members: []string{reservation.Administrator},
	}
	created, err := o.store.PublishSubscription(ctx, reservation, subscription)
	if err != nil {
		tenantWriteError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	slog.Info("Tenant registration reconciled", "tenant", tenant, "operator", token.Subject,
		"subscription", reservation.SubscriptionID, "created", created)
	writeJSON(w, status, reservation.view())
}

func (r TenantReservation) view() map[string]string {
	return map[string]string{"tenantId": r.TenantID, "subscriptionId": r.SubscriptionID, "administratorId": r.Administrator}
}

func readOnboardingRequest(body io.Reader) (onboardingRequest, error) {
	var input onboardingRequest
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(new(any)) != io.EOF {
		return input, errors.New("Submit one JSON tenant configuration.")
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.AdministratorUPN = strings.ToLower(strings.TrimSpace(input.AdministratorUPN))
	address, err := mail.ParseAddress(input.AdministratorUPN)
	password := input.AdministratorPassword
	if err != nil || address.Address != input.AdministratorUPN || len(input.AdministratorUPN) > 128 ||
		input.DisplayName == "" || len(input.DisplayName) > 120 || strings.ContainsFunc(input.DisplayName, unicode.IsControl) ||
		len(password) < 12 || len(password) > 256 || strings.ContainsFunc(password, unicode.IsControl) {
		return input, errors.New("Configure a display name, an administrator email address, and a 12–256 byte password.")
	}
	return input, nil
}

func tenantWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTenantConflict) {
		armError(w, http.StatusConflict, "TenantAlreadyRegistered", "The tenant has another registration.")
		return
	}
	slog.Warn("Tenant registration pending", "operation", "reconcile")
	armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "Tenant registration is pending. Retry the same request.")
}
