package storage

import (
	"regexp"
	"strings"
)

const (
	AccountType       = "Microsoft.Storage/storageAccounts"
	AccountAPIVersion = "2026-09-01"
	ShareType         = "Microsoft.Storage/storageAccounts/fileServices/shares"
	ShareAPIVersion   = "2024-01-01"
)

var (
	accountName = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	shareName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

func ValidAccount(name string) bool { return accountName.MatchString(name) }

func ValidShare(name string) bool {
	return shareName.MatchString(name) && !strings.Contains(name, "--")
}

type AccountRequest struct {
	Location   string            `json:"location"`
	Kind       string            `json:"kind"`
	Tags       map[string]string `json:"tags,omitempty"`
	SKU        AccountSKU        `json:"sku"`
	Properties AccountProperties `json:"properties"`
}

type AccountSKU struct {
	Name string `json:"name"`
}

type AccountProperties struct {
	HTTPSOnly         *bool              `json:"supportsHttpsTrafficOnly,omitempty"`
	BlobPublicAccess  *bool              `json:"allowBlobPublicAccess,omitempty"`
	SharedKeyAccess   *bool              `json:"allowSharedKeyAccess,omitempty"`
	PublicNetwork     string             `json:"publicNetworkAccess,omitempty"`
	MinimumTLSVersion string             `json:"minimumTlsVersion,omitempty"`
	Encryption        *AccountEncryption `json:"encryption,omitempty"`
}

type AccountEncryption struct {
	KeySource string        `json:"keySource"`
	Services  *AccountMedia `json:"services,omitempty"`
}

type AccountMedia struct {
	Blob *struct{} `json:"blob,omitempty"`
}

func (a AccountRequest) Valid(location string) bool {
	p := a.Properties
	return a.Location == location && a.Kind == "StorageV2" && a.SKU.Name == "Standard_LRS" &&
		(p.HTTPSOnly == nil || *p.HTTPSOnly) && (p.BlobPublicAccess == nil || !*p.BlobPublicAccess) &&
		(p.SharedKeyAccess == nil || *p.SharedKeyAccess) && (p.PublicNetwork == "" || p.PublicNetwork == "Disabled") &&
		(p.MinimumTLSVersion == "" || p.MinimumTLSVersion == "TLS1_2") && (p.Encryption == nil || p.Encryption.KeySource == "Microsoft.Storage")
}

type ShareRequest struct {
	Properties ShareProperties `json:"properties"`
}

type ShareProperties struct {
	QuotaGiB         int    `json:"shareQuota"`
	EnabledProtocols string `json:"enabledProtocols,omitempty"`
	AccessTier       string `json:"accessTier,omitempty"`
}

func (s ShareProperties) Valid() bool {
	return s.QuotaGiB >= 1 && s.QuotaGiB <= 16 && (s.EnabledProtocols == "" || s.EnabledProtocols == "SMB") &&
		(s.AccessTier == "" || s.AccessTier == "TransactionOptimized")
}
