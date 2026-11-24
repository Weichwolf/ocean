package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// Config locates the public identity endpoints and configures provider trust.
type Config struct {
	Authority               string          `json:"authority"`
	Provider                string          `json:"provider"`
	ProviderCAFile          string          `json:"providerCAFile"`
	Cloud                   *CloudEndpoints `json:"cloud"`
	ExchangeSecretDirectory string          `json:"exchangeSecretDirectory"`
}

// OpenCompatibility configures the control plane's OAuth compatibility routes.
func (cfg Config) OpenCompatibility() (*Compatibility, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ProviderCAFile != "" {
		data, err := os.ReadFile(cfg.ProviderCAFile)
		if err != nil {
			return nil, fmt.Errorf("read identity provider CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("identity provider CA file contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	compatibility, err := NewCompatibility(cfg.Authority, cfg.Provider, transport)
	if err != nil {
		return nil, err
	}
	if cfg.Cloud != nil {
		if !httpsOrigin(cfg.Cloud.ResourceManager) || !httpsOrigin(cfg.Cloud.MicrosoftGraph) ||
			cfg.Cloud.ResourceManager == cfg.Cloud.MicrosoftGraph {
			return nil, errors.New("cloud resourceManager and microsoftGraph must be distinct HTTPS origins")
		}
		compatibility.cloud = *cfg.Cloud
	}
	if cfg.ExchangeSecretDirectory != "" {
		if cfg.Cloud == nil {
			return nil, errors.New("token exchange requires configured cloud endpoints")
		}
		info, err := os.Stat(cfg.ExchangeSecretDirectory)
		if err != nil {
			return nil, fmt.Errorf("open exchange secret directory: %w", err)
		}
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("exchange secret directory must be a private directory")
		}
		compatibility.exchangeSecret = func(tenant string) (string, error) {
			return readExchangeSecret(cfg.ExchangeSecretDirectory, tenant)
		}
	}
	return compatibility, nil
}
