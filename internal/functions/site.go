package functions

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	SiteKind         = "functionapp,linux,container"
	HostStorageImage = "mcr.microsoft.com/azure-storage/azurite@sha256:dae2a5f96553962901304b94e72ef87e299d0825e4b679673bcc527a25076fe4"
)

var (
	ErrInvalidSite = errors.New("the requested Linux Functions app configuration is unsupported")
	imagePath      = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$`)
	settingName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,95}$`)
	functionName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	keyValue       = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}={0,2}$`)
)

type Site struct {
	Location   string            `json:"location"`
	Kind       string            `json:"kind"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties SiteProperties    `json:"properties"`
}

type SiteProperties struct {
	Name                    string           `json:"name,omitempty"`
	Enabled                 *bool            `json:"enabled,omitempty"`
	ProvisioningState       string           `json:"provisioningState,omitempty"`
	ServerFarmID            string           `json:"serverFarmId"`
	Reserved                bool             `json:"reserved"`
	HTTPSOnly               bool             `json:"httpsOnly"`
	VNetContentShareEnabled bool             `json:"vnetContentShareEnabled"`
	VirtualNetworkSubnetID  string           `json:"virtualNetworkSubnetId,omitempty"`
	OutboundVNetRouting     *OutboundRouting `json:"outboundVnetRouting,omitempty"`
	HostNameSSLStates       []HostNameState  `json:"hostNameSslStates,omitempty"`
	Config                  SiteConfig       `json:"siteConfig"`
}

type HostNameState struct {
	Name     string `json:"name"`
	HostType string `json:"hostType"`
	SSLState string `json:"sslState"`
}

type OutboundRouting struct {
	ApplicationTraffic bool `json:"applicationTraffic"`
}

type SiteConfig struct {
	LinuxFxVersion        string    `json:"linuxFxVersion"`
	Use32BitWorkerProcess bool      `json:"use32BitWorkerProcess"`
	AlwaysOn              bool      `json:"alwaysOn"`
	AppSettings           []Setting `json:"appSettings,omitempty"`
}

type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Settings struct {
	Properties map[string]string `json:"properties"`
}

// Runtime contains configuration that may be given only to the assigned worker.
type Runtime struct {
	MasterKey     string            `json:"masterKey"`
	Account       string            `json:"account"`
	StorageKey    string            `json:"storageKey"`
	Configuration string            `json:"configuration"`
	Request       *AdminRequest     `json:"request,omitempty"`
	Package       *PackageReference `json:"package,omitempty"`
	EmptySlot     bool              `json:"emptySlot,omitempty"`
}

type AdminRequest struct {
	ID        string    `json:"id"`
	Function  string    `json:"function,omitempty"`
	Name      string    `json:"name,omitempty"`
	Value     string    `json:"value,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type AdminResult struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
}

func ValidNameSetting(name string) bool {
	if !settingName.MatchString(name) {
		return false
	}
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"AZUREWEBJOBS", "AZUREFUNCTIONS", "FUNCTION", "WEBSITE", "DOCKER_", "ASPNETCORE", "DOTNET_", "JAVA_", "MACHINEKEY_", "LD_", "OTEL_"} {
		if strings.HasPrefix(upper, prefix) {
			return false
		}
	}
	switch upper {
	case "HOME", "PATH", "SHELL", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "NODE_EXTRA_CA_CERTS",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "CLR_PROFILER", "COR_ENABLE_PROFILING", "SCM_DO_BUILD_DURING_DEPLOYMENT":
		return false
	default:
		return true
	}
}

func ValidSettings(settings map[string]string) bool {
	if len(settings) > 32 {
		return false
	}
	seen := make(map[string]bool, len(settings))
	for name, value := range settings {
		key := strings.ToUpper(name)
		if !ValidNameSetting(name) || seen[key] || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
		seen[key] = true
	}
	return true
}

func ValidImage(image, registry string) bool {
	host, path, ok := strings.Cut(image, "/")
	if !ok || len(image) > 384 || !imagePath.MatchString(path) || strings.Contains(path, "//") {
		return false
	}
	switch host {
	case "docker.io", "mcr.microsoft.com", "ghcr.io", "quay.io":
		return true
	default:
		return registry != "" && registry == host
	}
}

func ImageFromFX(value string) string {
	image, _ := strings.CutPrefix(value, "DOCKER|")
	return image
}

func (s Site) Settings() (map[string]string, bool) {
	settings := make(map[string]string, len(s.Properties.Config.AppSettings))
	for _, setting := range s.Properties.Config.AppSettings {
		if _, exists := settings[setting.Name]; exists {
			return nil, false
		}
		settings[setting.Name] = setting.Value
	}
	return settings, true
}

func ParseHostCredential(connection, suffix string) (account, key string, ok bool) {
	parts := make(map[string]string, 4)
	for _, item := range strings.Split(connection, ";") {
		name, value, found := strings.Cut(item, "=")
		if !found || parts[name] != "" || value == "" {
			return "", "", false
		}
		parts[name] = value
	}
	account, key = parts["AccountName"], parts["AccountKey"]
	decoded, err := base64.StdEncoding.DecodeString(key)
	clear(decoded)
	ok = err == nil && len(decoded) == 64 && len(parts) == 4 && suffix != "" &&
		parts["EndpointSuffix"] == suffix && parts["DefaultEndpointsProtocol"] == "https"
	return
}

func (r Runtime) StorageConnection() string {
	return "DefaultEndpointsProtocol=http;AccountName=" + r.Account + ";AccountKey=" + r.StorageKey +
		";BlobEndpoint=http://127.0.0.1:10000/" + r.Account +
		";QueueEndpoint=http://127.0.0.1:10001/" + r.Account +
		";TableEndpoint=http://127.0.0.1:10002/" + r.Account
}

func ValidKey(value string) bool { return keyValue.MatchString(value) }

func ValidFunctionName(name string) bool { return functionName.MatchString(name) }
