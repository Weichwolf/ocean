package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type keycloakAdmin struct {
	client    *http.Client
	endpoints []string
	clientID  string
	secret    string
}

// directoryRequest selects an available admin endpoint. A mutation is
// attempted once so a lost response cannot cause another provider write.
func (k keycloakAdmin) directoryRequest(ctx context.Context, tenant, method, path string, input, output any) (int, error) {
	var payload []byte
	if input != nil {
		var err error
		payload, err = json.Marshal(input)
		if err != nil {
			return 0, err
		}
	}
	for _, origin := range k.endpoints {
		token, err := k.login(ctx, origin)
		if err != nil {
			continue
		}
		var body io.Reader
		media := ""
		if payload != nil {
			body = bytes.NewReader(payload)
			media = "application/json"
		}
		status, err := k.request(ctx, method, origin+"/admin/realms/"+tenant+path, token, media, body, output)
		if method != http.MethodGet || (err == nil && status < 500) {
			return status, err
		}
	}
	return 0, errors.New("Keycloak directory is unavailable")
}

func (k keycloakAdmin) ensureRealm(ctx context.Context, reservation TenantReservation, representation any) error {
	body, err := json.Marshal(representation)
	if err != nil {
		return err
	}
	for _, origin := range k.endpoints {
		token, err := k.login(ctx, origin)
		if err != nil {
			continue
		}
		if err := k.reconcileRealm(ctx, origin, token, reservation, body); err == nil || errors.Is(err, ErrTenantConflict) {
			return err
		}
	}
	return errors.New("no Keycloak replica confirmed the tenant realm")
}

func (k keycloakAdmin) reconcileRealm(ctx context.Context, origin, token string, reservation TenantReservation, body []byte) error {
	path := "/admin/realms/" + reservation.TenantID
	get := func() (bool, error) {
		var realm struct {
			Name       string            `json:"realm"`
			Attributes map[string]string `json:"attributes"`
		}
		status, err := k.request(ctx, http.MethodGet, origin+path, token, "", nil, &realm)
		if err != nil || (status != http.StatusOK && status != http.StatusNotFound) {
			return false, errors.New("unable to get tenant realm")
		}
		if status == http.StatusNotFound {
			return false, nil
		}
		if realm.Name != reservation.TenantID || realm.Attributes["oceanRegistration"] != reservation.SubscriptionID {
			return false, ErrTenantConflict
		}
		return true, nil
	}
	present, err := get()
	if err != nil {
		return err
	}
	if !present {
		// The outcome of a timed-out import is unknown. Verify the registration
		// marker before publishing or attempting an import on another replica.
		_, _ = k.request(ctx, http.MethodPost, origin+"/admin/realms", token, "application/json", bytes.NewReader(body), nil)
		present, err = get()
		if err != nil {
			return err
		}
		if !present {
			return errors.New("Keycloak has not committed the realm")
		}
	}
	var user struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	status, err := k.request(ctx, http.MethodGet, origin+path+"/users/"+reservation.Administrator, token, "", nil, &user)
	if err != nil || status != http.StatusOK || user.ID != reservation.Administrator || !user.Enabled {
		return errors.New("Keycloak has not confirmed the tenant administrator")
	}
	return nil
}

func (k keycloakAdmin) login(ctx context.Context, origin string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.clientID}, "client_secret": {k.secret}}
	var response struct {
		Token string `json:"access_token"`
	}
	status, err := k.request(ctx, http.MethodPost, origin+"/realms/master/protocol/openid-connect/token",
		"", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), &response)
	if err != nil || status != http.StatusOK || response.Token == "" {
		return "", errors.New("Keycloak admin authentication failed")
	}
	return response.Token, nil
}

func (k keycloakAdmin) request(ctx context.Context, method, endpoint, token, mediaType string, body io.Reader, output any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if mediaType != "" {
		req.Header.Set("Content-Type", mediaType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	reply, err := k.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer reply.Body.Close()
	if reply.StatusCode < 200 || reply.StatusCode >= 300 || output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(reply.Body, 64<<10))
		return reply.StatusCode, nil
	}
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(reply.Body, limit+1))
	if err != nil {
		return reply.StatusCode, err
	}
	if len(data) > limit {
		return reply.StatusCode, fmt.Errorf("Keycloak response exceeds %d bytes", limit)
	}
	return reply.StatusCode, json.Unmarshal(data, output)
}
