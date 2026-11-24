package network

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// HTTPSIngress describes one public HTTPS listener and its private HTTP backend.
type HTTPSIngress struct {
	PublicIPv4      netip.Addr     `json:"publicIPv4"`
	Hostname        string         `json:"hostname"`
	CertificateFile string         `json:"certificateFile"`
	Backend         netip.AddrPort `json:"backend"`
	BackendSubnet   netip.Prefix   `json:"backendSubnet"`
}

var (
	certificatePath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)
	hostLabel       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func (ingress HTTPSIngress) validate() error {
	if !ingress.PublicIPv4.Is4() || !ingress.PublicIPv4.IsGlobalUnicast() ||
		ingress.BackendSubnet.Contains(ingress.PublicIPv4) || ingress.Backend.Port() == 0 ||
		!ingress.Backend.Addr().IsPrivate() || !IsUsableSubnetAddress(ingress.BackendSubnet, ingress.Backend.Addr()) {
		return errors.New("HTTPS ingress requires a public IPv4 listener and a usable private subnet backend")
	}
	if !validIngressHostname(ingress.Hostname) {
		return errors.New("HTTPS ingress requires a canonical DNS hostname")
	}
	if !certificatePath.MatchString(ingress.CertificateFile) || filepath.Clean(ingress.CertificateFile) != ingress.CertificateFile {
		return errors.New("the certificate bundle needs a canonical absolute path")
	}
	// Refuse files that could be substituted for a private, bounded bundle.
	file, err := os.OpenFile(ingress.CertificateFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 ||
		info.Mode().Perm()&0077 != 0 || info.Size() > maximumIngressBundle {
		return errors.New("the TLS bundle must be a small root-owned private file")
	}
	bundle, err := io.ReadAll(io.LimitReader(file, maximumIngressBundle+1))
	if err != nil {
		return err
	}
	if len(bundle) > maximumIngressBundle {
		return errors.New("the TLS bundle exceeds its size limit")
	}
	leaf, err := ingressCertificateLeaf(bundle)
	if err != nil {
		return err
	}
	if leaf.VerifyHostname(ingress.Hostname) != nil {
		return errors.New("the ingress certificate must be valid for the configured hostname")
	}
	return nil
}

func validIngressHostname(hostname string) bool {
	labels := strings.Split(hostname, ".")
	if len(hostname) > 253 || len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// HAProxy renders the narrow public listener contract for a dedicated ingress
// process. A separate route supervisor owns the listener's virtual address.
func (ingress HTTPSIngress) HAProxy() (string, error) {
	if err := ingress.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`global
  nbthread 1
  user haproxy
  group haproxy
defaults
  mode http
  timeout connect 2s
  timeout client 30s
  timeout server 30s
  timeout http-request 5s
  timeout http-keep-alive 5s
frontend ingress
  bind %[1]s:443 transparent ssl crt %[2]s ssl-min-ver TLSv1.2 strict-sni alpn h2,http/1.1
  acl valid_sni ssl_fc_sni -i %[3]s
  acl valid_host hdr(host) -i %[3]s %[3]s:443
  acl single_host hdr_cnt(host) eq 1
  http-request deny deny_status 421 unless valid_sni valid_host single_host
  http-request deny if { method CONNECT }
  http-request del-header Forwarded
  http-request del-header X-Real-IP
  http-request del-header X-Forwarded-Server
  http-request set-header X-Forwarded-For %%[src]
  http-request set-header X-Forwarded-Proto https
  http-request set-header X-Forwarded-Host %[3]s
  http-request set-header X-Forwarded-Port 443
  default_backend workload
backend workload
  server workload %[4]s check inter 500ms fall 2 rise 1
`, ingress.PublicIPv4, ingress.CertificateFile, ingress.Hostname, ingress.Backend), nil
}
