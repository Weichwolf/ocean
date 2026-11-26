package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
)

const cacheDirectory = "/run/ocean-desktop-cifs"

type guestKerberos struct {
	Region          string `json:"region"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	Service         string `json:"service"`
}

var cifsService = regexp.MustCompile(`^cifs/[a-z0-9][a-z0-9.-]{0,252}@[A-Z0-9][A-Z0-9.-]{0,252}$`)

func installCIFSCache(settings guestKerberos, user string, ticket []byte) error {
	login, domain, ok := strings.Cut(user, "@")
	realm := strings.ToUpper(domain)
	if !ok || !cifsService.MatchString(settings.Service) || !strings.HasSuffix(settings.Service, "."+domain+"@"+realm) {
		return errors.New("invalid desktop CIFS principal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	uid, err := workforceUID(ctx, user)
	if err != nil {
		return err
	}
	cache, err := settings.fetch(ctx, user, ticket)
	if err != nil {
		return err
	}
	defer clear(cache)
	if err := os.Mkdir(cacheDirectory, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(cacheDirectory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0711 {
		return errors.New("invalid desktop CIFS cache directory")
	}
	staging, err := os.CreateTemp(cacheDirectory, ".cifs-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staging.Name()) }()
	_, err = staging.Write(cache)
	if err := errors.Join(err, staging.Close()); err != nil {
		return err
	}
	if err := desktop.VerifyCIFSCache(ctx, staging.Name(), login+"@"+realm, settings.Service, time.Now()); err != nil {
		return err
	}
	if err := os.Chown(staging.Name(), uid, -1); err != nil {
		return err
	}
	return os.Rename(staging.Name(), filepath.Join(cacheDirectory, strconv.Itoa(uid)))
}

func workforceUID(ctx context.Context, user string) (int, error) {
	command := exec.CommandContext(ctx, "/usr/bin/getent", "passwd", user)
	command.Env = []string{"LC_ALL=C"}
	body, err := command.Output()
	fields := strings.Split(strings.TrimSuffix(string(body), "\n"), ":")
	if err != nil || len(fields) != 7 || fields[0] != user {
		return 0, errors.New("unable to resolve the desktop workforce account")
	}
	uid, err := strconv.ParseUint(fields[2], 10, 31)
	if err != nil || uid < 1000 {
		return 0, errors.New("invalid desktop workforce identity")
	}
	return int(uid), nil
}

func (settings guestKerberos) fetch(ctx context.Context, user string, ticket []byte) ([]byte, error) {
	origin, err := url.Parse(settings.Region)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" || origin.String() != settings.Region {
		return nil, errors.New("invalid desktop Kerberos regional HTTPS endpoint")
	}
	ca, err := os.ReadFile(settings.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("the desktop Kerberos region requires its trusted CA")
	}
	key, err := os.Lstat(settings.KeyFile)
	if err != nil || !key.Mode().IsRegular() || key.Mode().Perm()&0077 != 0 {
		return nil, errors.New("the desktop Kerberos identity key must be private")
	}
	owner, ok := key.Sys().(*syscall.Stat_t)
	if !ok || owner == nil || owner.Uid != 0 {
		return nil, errors.New("the desktop Kerberos identity key must be owned by root")
	}
	identity, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.KeyFile)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := json.Marshal(desktop.KerberosRequest{User: user, Credential: ticket})
	if err != nil {
		return nil, err
	}
	defer clear(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.Region+desktop.KerberosPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.ContentLength > desktop.MaxCIFSCache ||
		response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, errors.New("the desktop Kerberos service denied the request")
	}
	cache, err := io.ReadAll(io.LimitReader(response.Body, desktop.MaxCIFSCache+1))
	if err != nil || len(cache) == 0 || len(cache) > desktop.MaxCIFSCache {
		clear(cache)
		return nil, errors.New("invalid desktop Kerberos service response")
	}
	return cache, nil
}
