package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const directoryAPIVersion = "2026-11-01"

var (
	directoryLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	netBIOSLabel   = regexp.MustCompile(`^[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?$`)

	ErrDirectoryConflict = errors.New("the tenant already has a directory with a different configuration")
	ErrDirectorySubnet   = errors.New("the tenant directory subnet is invalid or unavailable")
	ErrDirectoryTenant   = errors.New("the tenant directory requires a published tenant registration")
)

// DirectorySpec is the immutable configuration for a tenant's AD domain.
type DirectorySpec struct {
	DNSName     string `json:"dnsName"`
	NetBIOSName string `json:"netbiosName"`
	SubnetID    string `json:"subnetId"`
}

func (s DirectorySpec) Canonical() (DirectorySpec, bool) {
	if strings.ContainsFunc(s.DNSName+s.NetBIOSName, func(character rune) bool { return character > 127 }) {
		return DirectorySpec{}, false
	}
	s.DNSName = strings.ToLower(s.DNSName)
	s.NetBIOSName = strings.ToUpper(s.NetBIOSName)
	s.SubnetID = strings.ToLower(s.SubnetID)
	if len(s.DNSName) > 253 || !netBIOSLabel.MatchString(s.NetBIOSName) || len(s.SubnetID) == 0 || len(s.SubnetID) > 2048 {
		return DirectorySpec{}, false
	}
	labels := strings.Split(s.DNSName, ".")
	if len(labels) < 2 {
		return DirectorySpec{}, false
	}
	for _, label := range labels {
		if !directoryLabel.MatchString(label) {
			return DirectorySpec{}, false
		}
	}
	return s, true
}

// ManagedDirectory is the durable provisioning request for a tenant.
type ManagedDirectory struct {
	TenantID       string                          `json:"tenantId"`
	SubscriptionID string                          `json:"subscriptionId"`
	ID             string                          `json:"directoryId"`
	Spec           DirectorySpec                   `json:"spec"`
	RequestedAt    time.Time                       `json:"requestedAt"`
	ProvisionedAt  time.Time                       `json:"provisionedAt,omitzero"`
	DomainSID      string                          `json:"domainSid,omitempty"`
	Controllers    [2]DirectoryControllerReadiness `json:"-"`
}

// DirectoryControllerReadiness is the tenant-facing view of an assigned controller.
type DirectoryControllerReadiness struct {
	DNSName     string     `json:"dnsName"`
	PrivateIPv4 netip.Addr `json:"privateIPv4"`
	Ready       bool       `json:"ready"`
	Writer      bool       `json:"writer"`
}

func (d ManagedDirectory) Valid(tenant TenantReservation) bool {
	spec, ok := d.Spec.Canonical()
	return tenant.Valid(d.TenantID) && d.SubscriptionID == tenant.SubscriptionID &&
		tenantID.MatchString(d.ID) && ok && d.Spec == spec && !d.RequestedAt.IsZero() &&
		(d.ProvisionedAt.IsZero() || d.DomainSID != "" && !d.ProvisionedAt.Before(d.RequestedAt))
}

// ManagedDirectoryStore reserves a tenant directory in the regional store.
type ManagedDirectoryStore interface {
	RequestManagedDirectory(context.Context, TenantReservation, DirectorySpec) (ManagedDirectory, error)
	LookupManagedDirectory(context.Context, TenantReservation) (*ManagedDirectory, error)
}

func (c *Compatibility) EnableManagedDirectories(store ManagedDirectoryStore) error {
	if c.onboarding == nil || c.subscriptions == nil || store == nil {
		return errors.New("managed directories require regional tenant onboarding")
	}
	c.directories = store
	return nil
}

func (c *Compatibility) managedDirectory(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.ResourceManager, "https://")) {
		http.NotFound(w, req)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()
	principal, err := c.AuthenticateARM(ctx, req)
	if err != nil {
		if errors.Is(err, ErrInvalidARMToken) {
			invalidARMToken(w)
		} else {
			directoryError(w, err)
		}
		return
	}
	tenant := req.PathValue("tenant")
	if tenant != principal.Subscription.TenantID {
		directoryError(w, ErrDirectoryTenant)
		return
	}
	record, err := c.onboarding.store.LookupTenant(ctx, tenant)
	if err != nil {
		directoryError(w, err)
		return
	}
	if record == nil || !record.Valid(tenant) || record.SubscriptionID != principal.Subscription.SubscriptionID ||
		record.Administrator != principal.Subject {
		directoryError(w, ErrDirectoryTenant)
		return
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["api-version"]) != 1 || query.Get("api-version") != directoryAPIVersion {
		armError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "The managed directory requires api-version="+directoryAPIVersion+".")
		return
	}
	if req.PathValue("authorization") != "" {
		c.manageDirectoryJoin(ctx, w, req, *record)
		return
	}
	if req.Method == http.MethodPost {
		c.replaceDirectoryController(ctx, w, req, *record, strings.HasSuffix(req.URL.Path, "/replacePrimary"))
		return
	}
	if req.Method != http.MethodPut {
		directory, err := c.directories.LookupManagedDirectory(ctx, *record)
		switch {
		case err != nil:
			directoryError(w, err)
		case directory == nil:
			armError(w, http.StatusNotFound, "ResourceNotFound", "The tenant has no managed directory.")
		default:
			writeDirectory(w, http.StatusOK, *directory)
		}
		return
	}
	spec, err := readDirectorySpec(http.MaxBytesReader(w, req.Body, 8<<10))
	if err != nil {
		armError(w, http.StatusBadRequest, "InvalidRequest", err.Error())
		return
	}
	directory, err := c.directories.RequestManagedDirectory(ctx, *record, spec)
	if err != nil {
		directoryError(w, err)
		return
	}
	w.Header().Set("Location", c.cloud.ResourceManager+directoryPath(tenant)+"?api-version="+directoryAPIVersion)
	w.Header().Set("Retry-After", "2")
	writeDirectory(w, http.StatusAccepted, directory)
}

func readDirectorySpec(body io.Reader) (DirectorySpec, error) {
	var input DirectorySpec
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return DirectorySpec{}, errors.New("Submit one supported directory configuration.")
	}
	spec, ok := input.Canonical()
	if !ok {
		return DirectorySpec{}, errors.New("Specify an AD DNS domain, its NetBIOS name and a private subnet ID.")
	}
	return spec, nil
}

func directoryPath(tenant string) string {
	return "/ocean/tenants/" + tenant + "/directory"
}

func writeDirectory(w http.ResponseWriter, status int, directory ManagedDirectory) {
	controllers := make([]DirectoryControllerReadiness, 0, len(directory.Controllers))
	available := 0
	for _, controller := range directory.Controllers {
		if controller.DNSName == "" {
			continue
		}
		controllers = append(controllers, controller)
		if controller.Ready {
			available++
		}
	}
	provisioning, availability := "Creating", "Pending"
	if !directory.ProvisionedAt.IsZero() {
		provisioning, availability = "Succeeded", "Unavailable"
		switch available {
		case 1:
			availability = "Degraded"
		case 2:
			availability = "Available"
		}
	}
	writeJSON(w, status, map[string]any{
		"id": directoryPath(directory.TenantID), "directoryId": directory.ID, "tenantId": directory.TenantID,
		"properties": directory.Spec, "requestedAt": directory.RequestedAt, "provisioningState": provisioning,
		"availability": availability, "controllers": controllers,
	})
}

func directoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrDirectoryConflict):
		armError(w, http.StatusConflict, "DirectoryConfigurationConflict", "The directory configuration differs from the original request.")
	case errors.Is(err, ErrDirectorySubnet):
		armError(w, http.StatusBadRequest, "InvalidDirectorySubnet", "Use an available private subnet in the tenant subscription.")
	case errors.Is(err, ErrDirectoryTenant):
		armError(w, http.StatusForbidden, "AuthorizationFailed", "The managed directory requires the administrator of this tenant.")
	default:
		armError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The managed directory store is unavailable.")
	}
}
