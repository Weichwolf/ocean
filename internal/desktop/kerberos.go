package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	CIFSLifetime = 5 * time.Minute
	MaxCIFSCache = 64 << 10
	KerberosPath = "/ocean/desktops/kerberos"
)

type KerberosRequest struct {
	User       string `json:"user"`
	Credential []byte `json:"credential"`
}

// CIFSBroker acquires a service-only cache using a directory-managed,
// constrained delegation account.
type CIFSBroker struct {
	Principal  string
	KeytabFile string
	ConfigFile string
	DNSDomain  string
	Service    string
}

func (b CIFSBroker) Acquire(ctx context.Context, upn string) ([]byte, error) {
	user, domain, ok := strings.Cut(upn, "@")
	if !ok || domain != b.DNSDomain || !workforceUPN.MatchString(upn) {
		return nil, ErrLaunchDenied
	}
	dir, err := os.MkdirTemp("", "ocean-desktop-kerberos-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	client := user + "@" + strings.ToUpper(domain)
	brokerCache := "FILE:" + filepath.Join(dir, "broker")
	serviceFile := filepath.Join(dir, "cifs")
	serviceCache := "FILE:" + serviceFile
	run := func(binary string, args ...string) error {
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = []string{"LC_ALL=C", "TZ=UTC", "KRB5_CONFIG=" + b.ConfigFile}
		return command.Run()
	}
	if err := run("/usr/bin/kinit", "-f", "-l", "300s", "-k", "-t", b.KeytabFile, "-c", brokerCache, b.Principal); err != nil {
		return nil, errors.New("obtain the broker Kerberos credential")
	}
	if err := run("/usr/bin/kvno", "-q", "-c", brokerCache, "--no-store", "--out-cache", serviceCache, "-I", client, "-P", b.Service); err != nil {
		return nil, errors.New("obtain the delegated CIFS service ticket")
	}
	metadata, err := os.Stat(serviceFile)
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() < 1 || metadata.Size() > MaxCIFSCache {
		return nil, errors.New("invalid Kerberos service cache")
	}
	cache, err := os.ReadFile(serviceFile)
	if err != nil {
		return nil, err
	}
	if err := VerifyCIFSCache(ctx, serviceFile, client, b.Service, time.Now()); err != nil {
		clear(cache)
		return nil, err
	}
	return cache, nil
}

// VerifyCIFSCache checks the default principal, unique service and lifetime
// with the local Kerberos implementation before exposing the cache.
func VerifyCIFSCache(ctx context.Context, path, client, service string, now time.Time) error {
	command := exec.CommandContext(ctx, "/usr/bin/klist", "-c", "FILE:"+path)
	command.Env = []string{"LC_ALL=C", "TZ=UTC"}
	out, err := command.Output()
	if err != nil || len(out) > 8192 {
		return errors.New("unable to inspect the CIFS service cache")
	}
	if err := validateCIFSList(out, client, service, now); err != nil {
		return fmt.Errorf("validate the Kerberos service cache: %w", err)
	}
	return nil
}

func validateCIFSList(out []byte, client, service string, now time.Time) error {
	principal := false
	tickets := 0
	for line := range bytes.Lines(out) {
		text := strings.TrimSpace(string(line))
		if found, ok := strings.CutPrefix(text, "Default principal: "); ok {
			if principal || found != client {
				return errors.New("unexpected default principal")
			}
			principal = true
			continue
		}
		if text == "" || text[0] < '0' || text[0] > '9' {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 5 || fields[4] != service {
			return errors.New("unexpected service principal")
		}
		format := "01/02/06 15:04:05"
		issued, startErr := time.Parse(format, fields[0]+" "+fields[1])
		expiry, endErr := time.Parse(format, fields[2]+" "+fields[3])
		if startErr != nil || endErr != nil || !issued.Before(expiry) || issued.After(now.Add(5*time.Second)) ||
			!now.Before(expiry) || expiry.Sub(issued) > CIFSLifetime {
			return errors.New("unexpected service ticket lifetime")
		}
		tickets++
	}
	if !principal || tickets != 1 {
		return errors.New("one personal CIFS ticket is required")
	}
	return nil
}
