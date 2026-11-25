package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/service"
)

type joinConfig struct {
	Origin               string `json:"origin"`
	HostID               string `json:"hostId"`
	Interface            string `json:"managementInterface"`
	CAFile               string `json:"caFile"`
	TokenFile            string `json:"tokenFile"`
	StateDirectory       string `json:"stateDirectory"`
	TelemetryBufferBytes int    `json:"telemetryBufferBytes,omitempty"`
}

type settings struct {
	config.Server
	Enrollment *joinConfig `json:"enrollment"`
}

// Load configures the node listener and its optional enrollment.
func Load(path string) (config.Server, service.Hooks, error) {
	settings, err := config.Load(path, settings{Server: config.Server{ListenAddress: "127.0.0.1:8081"}})
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	if err := settings.Server.Validate(); err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	hooks := service.Hooks{Startup: CheckRuntime}
	if settings.Enrollment != nil {
		client, err := newJoinClient(*settings.Enrollment)
		if err != nil {
			return config.Server{}, service.Hooks{}, err
		}
		hooks.Startup = client.start
		hooks.Readiness = client.ready
		hooks.Reconcile = func(ctx context.Context, logger *slog.Logger) {
			go client.reportCapacity(ctx, logger)
			go client.runTelemetry(ctx, logger)
			client.reconcileContainers(ctx, logger)
		}
	}
	return settings.Server, hooks, nil
}

type joinClient struct {
	config            joinConfig
	trust             *x509.CertPool
	client            *http.Client
	lastAdvertisement atomic.Pointer[time.Time]
	telemetryTargets  atomic.Pointer[[]telemetryTarget]
}

func loadEnrolledClient(path string) (*joinClient, error) {
	cfg, err := config.Load(path, settings{})
	if err != nil {
		return nil, err
	}
	if cfg.Enrollment == nil {
		return nil, errors.New("this host service requires enrollment")
	}
	client, err := newJoinClient(*cfg.Enrollment)
	if err != nil {
		return nil, err
	}
	key, err := readIdentityKey(filepath.Join(cfg.Enrollment.StateDirectory, "identity.key"))
	if err != nil {
		return nil, err
	}
	cert, err := privateData(filepath.Join(cfg.Enrollment.StateDirectory, "identity.crt"))
	if err != nil {
		return nil, err
	}
	if err := client.useIdentity(cert, key); err != nil {
		return nil, err
	}
	return client, nil
}

func newJoinClient(cfg joinConfig) (*joinClient, error) {
	if cfg.TelemetryBufferBytes != 0 && (cfg.TelemetryBufferBytes < 4096 || cfg.TelemetryBufferBytes > 4<<20) {
		return nil, errors.New("telemetry buffer must be between 4 KiB and 4 MiB")
	}
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" ||
		cfg.HostID == "" || url.PathEscape(cfg.HostID) != cfg.HostID || strings.ContainsAny(cfg.HostID, "/%") ||
		cfg.Interface == "" || !filepath.IsAbs(cfg.StateDirectory) || !filepath.IsAbs(cfg.TokenFile) {
		return nil, errors.New("invalid node enrollment configuration")
	}
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM(ca) {
		return nil, errors.New("node enrollment requires a management CA")
	}
	return &joinClient{config: cfg, trust: trust}, nil
}

func (j *joinClient) start(ctx context.Context) error {
	if err := CheckRuntime(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(j.config.StateDirectory, 0700); err != nil {
		return err
	}
	key, err := readOrCreateKey(filepath.Join(j.config.StateDirectory, "identity.key"))
	if err != nil {
		return err
	}
	path := filepath.Join(j.config.StateDirectory, "identity.crt")
	cert, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cert, err = j.enroll(ctx, key)
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if err := j.useIdentity(cert, key); err != nil {
		return err
	}
	if err := j.confirm(ctx); err != nil {
		return err
	}
	if err := publishFile(path, cert); err != nil {
		return err
	}
	return j.heartbeat(ctx)
}

func (j *joinClient) useIdentity(cert []byte, key ed25519.PrivateKey) error {
	leaf, err := x509.ParseCertificate(cert)
	if err != nil || leaf.PublicKeyAlgorithm != x509.Ed25519 {
		return errors.New("the host identity certificate is invalid")
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !public.Equal(key.Public()) {
		return errors.New("the certificate does not match the local host key")
	}
	j.client = j.httpClient([]tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key, Leaf: leaf}})
	return nil
}

func (j *joinClient) httpClient(certificates []tls.Certificate) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: j.trust, Certificates: certificates, MinVersion: tls.VersionTLS12,
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (j *joinClient) url() string { return j.config.Origin + "/ocean/hosts/" + j.config.HostID }

func (j *joinClient) enroll(ctx context.Context, key ed25519.PrivateKey) ([]byte, error) {
	token, err := privateData(j.config.TokenFile)
	if err != nil {
		return nil, err
	}
	report, err := probeHost(j.config.Interface)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(enrollment.Request{CSR: csr, Report: report})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/enrollment", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	client := j.httpClient(nil)
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("host enrollment returned HTTP %d", response.StatusCode)
	}
	var registered enrollment.Registration
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&registered); err != nil ||
		registered.HostID != j.config.HostID || len(registered.Certificate) == 0 {
		return nil, errors.New("invalid host registration response")
	}
	return registered.Certificate, nil
}

func (j *joinClient) confirm(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url(), nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("host identity check returned HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 16<<10))
	return err
}

func privateData(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, errors.New("enrollment secrets must be small, private files")
	}
	return io.ReadAll(io.LimitReader(file, 4096))
}

func readOrCreateKey(path string) (ed25519.PrivateKey, error) {
	key, err := readIdentityKey(path)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := publishFile(path, data); err != nil {
			return nil, err
		}
		return readIdentityKey(path)
	}
	return key, err
}

func readIdentityKey(path string) (ed25519.PrivateKey, error) {
	data, err := privateData(path)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(data)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("invalid local host key")
	}
	return key, nil
}

// publishFile makes a complete identity file visible without replacing a file
// written by a concurrent agent start.
func publishFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".identity-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func probeHost(name string) (enrollment.Report, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return enrollment.Report{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return enrollment.Report{}, err
	}
	report := enrollment.Report{MAC: iface.HardwareAddr.String(), CPU: runtime.NumCPU(), RootlessPodman: true}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
			report.Address = prefix.Addr().String()
			break
		}
	}
	if report.Address == "" {
		return enrollment.Report{}, errors.New("the management interface has no IPv4 address")
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return enrollment.Report{}, err
	}
	for _, line := range strings.Split(string(osRelease), "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "ID":
			report.OS = strings.Trim(value, `"'`)
		case "VERSION_ID":
			report.OSVersion = strings.Trim(value, `"'`)
		}
	}
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return enrollment.Report{}, err
	}
	for _, line := range strings.Split(string(meminfo), "\n") {
		if fields := strings.Fields(line); len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			memory, err := strconv.Atoi(fields[1])
			if err != nil {
				return enrollment.Report{}, err
			}
			report.MemoryMiB = memory / 1024
			break
		}
	}
	if device, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
		report.KVM = true
		_ = device.Close()
	}
	return report, nil
}
