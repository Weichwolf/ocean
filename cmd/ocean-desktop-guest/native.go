package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
)

type guestTLS struct {
	Region          string `json:"region"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

func (settings guestTLS) client() (*http.Client, error) {
	origin, err := url.Parse(settings.Region)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.String() != settings.Region {
		return nil, errors.New("invalid desktop regional HTTPS endpoint")
	}
	ca, err := os.ReadFile(settings.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("the desktop region requires its trusted CA")
	}
	key, err := os.Lstat(settings.KeyFile)
	if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0077 != 0 {
		return nil, errors.New("the desktop identity key must be private")
	}
	owner, ok := key.Sys().(*syscall.Stat_t)
	if !ok || owner == nil || owner.Uid != 0 {
		return nil, errors.New("the desktop identity key must be owned by root")
	}
	identity, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.KeyFile)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func authorizeAccount(path, account string) bool {
	settings, err := loadGuestConfig(path)
	if err != nil {
		return false
	}
	if settings.Native == nil {
		return true // The authentication stack admits signed browser credentials only.
	}
	account = strings.ToLower(account)
	if !desktop.ValidNativeAccount(account) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := workforceUID(ctx, account); err != nil {
		return false
	}
	client, err := settings.Native.client()
	if err != nil {
		return false
	}
	defer client.CloseIdleConnections()
	body, err := json.Marshal(desktop.NativeAdmissionRequest{User: account})
	if err != nil {
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.Native.Region+desktop.NativeAdmissionPath, bytes.NewReader(body))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode == http.StatusNoContent && response.Header.Get("Cache-Control") == "no-store"
}
