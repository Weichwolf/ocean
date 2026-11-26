package identity

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrExportDenied  = errors.New("the tenant administrator is required for this export")
	ErrExportExpired = errors.New("the export snapshot has expired")
)

type HostedExportCursor struct {
	ClusterID  uint64    `json:"clusterId"`
	Revision   int64     `json:"revision"`
	CapturedAt time.Time `json:"capturedAt"`
	Section    int       `json:"section"`
	After      string    `json:"after,omitempty"`
}

type HostedExportRecord struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}

type HostedExportPage struct {
	CapturedAt time.Time
	Records    []HostedExportRecord
	Next       *HostedExportCursor
}

type HostedExportStore interface {
	ReadHostedExport(context.Context, ARMPrincipal, HostedExportCursor) (HostedExportPage, error)
}

type hostedExportContinuation struct {
	Tenant       string             `json:"tenant"`
	Subscription string             `json:"subscription"`
	Actor        string             `json:"actor"`
	Cursor       HostedExportCursor `json:"cursor"`
}

const hostedExportLifetime = 10 * time.Minute

func (c *Compatibility) EnableHostedExport(store HostedExportStore) error {
	if c.onboarding == nil || c.subscriptions == nil || c.offboarding == nil || store == nil {
		return errors.New("hosted export requires tenant onboarding and the independent deletion ledger")
	}
	c.hostedExport = store
	return nil
}

func (c *Compatibility) tenantDataExport(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(req.Context(), 12*time.Second)
	defer cancel()
	principal, err := c.AuthenticateARM(ctx, req)
	if err != nil {
		if errors.Is(err, ErrInvalidARMToken) {
			invalidARMToken(w)
		} else {
			hostedExportError(w, err)
		}
		return
	}
	tenant := req.PathValue("tenant")
	if !tenantID.MatchString(tenant) || tenant != principal.Subscription.TenantID {
		hostedExportError(w, ErrExportDenied)
		return
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query["api-version"]) != 1 || query.Get("api-version") != hostedOperatorVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "Hosted export requires api-version="+hostedOperatorVersion+".")
		return
	}
	for key, values := range query {
		if len(values) != 1 || key != "api-version" && (key != "cursor" || values[0] == "") {
			armError(w, http.StatusBadRequest, "InvalidQueryParameter", "Use the returned export continuation URL.")
			return
		}
	}
	var cursor HostedExportCursor
	if token := query.Get("cursor"); token != "" {
		cursor, err = c.readExportCursor(principal, token)
		if err != nil {
			hostedExportError(w, err)
			return
		}
	}
	page, err := c.hostedExport.ReadHostedExport(ctx, principal, cursor)
	if err != nil {
		hostedExportError(w, err)
		return
	}
	view := struct {
		Format         string               `json:"format"`
		TenantID       string               `json:"tenantId"`
		SubscriptionID string               `json:"subscriptionId"`
		CapturedAt     time.Time            `json:"capturedAt"`
		Records        []HostedExportRecord `json:"records"`
		NextLink       string               `json:"nextLink,omitempty"`
	}{Format: "ocean-hosted-export-v1", TenantID: tenant, SubscriptionID: principal.Subscription.SubscriptionID,
		CapturedAt: page.CapturedAt, Records: page.Records}
	if page.Next != nil {
		token, err := c.exportCursor(principal, *page.Next)
		if err != nil {
			hostedExportError(w, err)
			return
		}
		query.Set("cursor", token)
		view.NextLink = c.cloud.ResourceManager + req.URL.Path + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, view)
}

func (c *Compatibility) exportCursor(principal ARMPrincipal, cursor HostedExportCursor) (string, error) {
	data, err := json.Marshal(hostedExportContinuation{Tenant: principal.Subscription.TenantID,
		Subscription: principal.Subscription.SubscriptionID, Actor: principal.Subject, Cursor: cursor})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + c.exportCursorMAC(payload), nil
}

func (c *Compatibility) exportCursorMAC(payload string) string {
	return c.onboarding.derive("hosted-export-cursor", c.cloud.ResourceManager+"\x00"+payload)
}

func (c *Compatibility) readExportCursor(principal ARMPrincipal, token string) (HostedExportCursor, error) {
	payload, mac, ok := strings.Cut(token, ".")
	if !ok || len(token) > 8192 || !hmac.Equal([]byte(mac), []byte(c.exportCursorMAC(payload))) {
		return HostedExportCursor{}, ErrExportDenied
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	var next hostedExportContinuation
	if err != nil || json.Unmarshal(data, &next) != nil || next.Tenant != principal.Subscription.TenantID ||
		next.Subscription != principal.Subscription.SubscriptionID || next.Actor != principal.Subject {
		return HostedExportCursor{}, ErrExportDenied
	}
	if next.Cursor.ClusterID == 0 || next.Cursor.Revision <= 0 || next.Cursor.CapturedAt.IsZero() || time.Since(next.Cursor.CapturedAt) >= hostedExportLifetime {
		return HostedExportCursor{}, ErrExportExpired
	}
	return next.Cursor, nil
}

func hostedExportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrExportDenied), errors.Is(err, ErrTenantSuspended):
		armError(w, http.StatusForbidden, "AuthorizationFailed", ErrExportDenied.Error())
	case errors.Is(err, ErrExportExpired):
		armError(w, http.StatusGone, "ExportSnapshotExpired", "Start a new export to get a current snapshot.")
	default:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The hosted export is temporarily unavailable.")
	}
}
