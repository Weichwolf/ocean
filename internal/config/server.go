package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
)

// Server configures a service listener and its diagnostic output.
type Server struct {
	ListenAddress string     `json:"listenAddress"`
	LogLevel      slog.Level `json:"logLevel"`
	TLS           *TLS       `json:"tls"`
}

// TLS identifies the PEM files used to serve HTTPS.
type TLS struct {
	CertificateFile  string `json:"certificateFile"`
	KeyFile          string `json:"keyFile"`
	ClientCAFile     string `json:"clientCAFile"`
	OptionalClientCA bool   `json:"optionalClientCA"`
}

// LoadServer reads an optional JSON file over the supplied listener defaults.
func LoadServer(path, defaultAddress string) (Server, error) {
	settings, err := Load(path, Server{ListenAddress: defaultAddress})
	if err != nil {
		return Server{}, err
	}
	return settings, settings.Validate()
}

// Load reads one strict JSON object over the supplied defaults.
func Load[T any](path string, defaults T) (T, error) {
	if path == "" {
		return defaults, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return defaults, err
	}
	defer func() { _ = file.Close() }()

	settings := &defaults
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil {
		return defaults, fmt.Errorf("decode configuration: %w", err)
	}
	if settings == nil {
		return defaults, errors.New("configuration must be a JSON object")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return defaults, errors.New("configuration must contain one JSON object")
	}
	return *settings, nil
}

// Validate checks the listener settings before a service binds its socket.
func (settings Server) Validate() error {
	address, err := netip.ParseAddrPort(settings.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid listenAddress: %w", err)
	}
	if settings.TLS == nil && !address.Addr().Unmap().IsLoopback() {
		return errors.New("TLS is required for a non-loopback listener")
	}
	if settings.TLS != nil && (settings.TLS.CertificateFile == "" || settings.TLS.KeyFile == "") {
		return errors.New("TLS requires certificateFile and keyFile")
	}
	if settings.TLS != nil && settings.TLS.OptionalClientCA && settings.TLS.ClientCAFile == "" {
		return errors.New("optional TLS client certificates require clientCAFile")
	}
	return nil
}
