package network

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type GeoHTTPSOrigin struct {
	Address netip.AddrPort `json:"address"`
	CAFile  string         `json:"caFile"`
}

var healthPath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]{0,127}$`)

// GeoHTTPS renders one independently addressed HTTPS edge for approved origins.
// Origins must serve the public hostname over TLS and report local readiness.
func GeoHTTPS(listen netip.AddrPort, hostname, certificate, readiness string, origins []GeoHTTPSOrigin) (string, error) {
	if !listen.Addr().Is4() || !listen.Addr().IsGlobalUnicast() || listen.Port() == 0 ||
		!validIngressHostname(hostname) || !healthPath.MatchString(readiness) || len(origins) < 2 || len(origins) > 16 {
		return "", errors.New("geo HTTPS requires one IPv4 listener, a canonical hostname, a health path, and two to sixteen origins")
	}
	var servers strings.Builder
	seen := make(map[netip.Addr]bool, len(origins))
	for index, origin := range origins {
		addr := origin.Address.Addr()
		if !addr.Is4() || !addr.IsPrivate() || addr == listen.Addr() || seen[addr] || origin.Address.Port() == 0 || !validIngressFilePath(origin.CAFile) {
			return "", errors.New("geo HTTPS origins require distinct private IPv4 endpoints and canonical CA file paths")
		}
		seen[addr] = true
		fmt.Fprintf(&servers, "  server origin%d %s ssl ssl-min-ver TLSv1.2 verify required ca-file %s verifyhost %s sni str(%s) check check-sni %s inter 500ms fall 2 rise 2\n",
			index+1, origin.Address, origin.CAFile, hostname, hostname, hostname)
	}
	if err := validateIngressCertificate(certificate, hostname, uint32(os.Geteuid())); err != nil {
		return "", err
	}
	return fmt.Sprintf(`global
  maxconn 1024
defaults
  mode http
  timeout connect 500ms
  timeout check 500ms
  timeout client 30s
  timeout server 30s
  timeout http-request 5s
  timeout http-keep-alive 5s
%sbackend workload
  balance roundrobin
  http-reuse never
  option redispatch 1
  retry-on conn-failure
  retries 2
  option httpchk
  http-check send meth GET uri %s ver HTTP/1.1 hdr Host %s
  http-check expect status 200
%s`, httpsFrontend(listen, certificate, hostname, ""), readiness, hostname, servers.String()), nil
}
