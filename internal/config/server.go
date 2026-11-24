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
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

// LoadServer reads an optional JSON file over the supplied listener defaults.
func LoadServer(path, defaultAddress string) (Server, error) {
	settings := &Server{ListenAddress: defaultAddress}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return Server{}, err
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&settings); err != nil {
			return Server{}, fmt.Errorf("decode configuration: %w", err)
		}
		if settings == nil {
			return Server{}, errors.New("configuration must be a JSON object")
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			return Server{}, errors.New("configuration must contain one JSON object")
		}
	}

	address, err := netip.ParseAddrPort(settings.ListenAddress)
	if err != nil {
		return Server{}, fmt.Errorf("invalid listenAddress: %w", err)
	}
	if settings.TLS == nil && !address.Addr().Unmap().IsLoopback() {
		return Server{}, errors.New("TLS is required for a non-loopback listener")
	}
	if settings.TLS != nil && (settings.TLS.CertificateFile == "" || settings.TLS.KeyFile == "") {
		return Server{}, errors.New("TLS requires certificateFile and keyFile")
	}
	return *settings, nil
}
