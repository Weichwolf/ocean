package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const endpoint = "/ocean/federation/v1/pairings/"

type Service struct {
	cfg     Config
	policy  string
	client  *clientv3.Client
	region  string
	root    string
	remotes map[string]*http.Client
}

type advertisement struct {
	Farm   string         `json:"farm"`
	PairID string         `json:"pairId"`
	Path   string         `json:"path"`
	Routes []netip.Prefix `json:"routes"`
}

func Open(cfg Config, client *clientv3.Client) (*Service, error) {
	cfg, err := validate(cfg)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLS.CertificateFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load federation identity: %w", err)
	}
	if !farmCertificate(certificate.Leaf, cfg.Policy.Farm) || certificate.Leaf.VerifyHostname(cfg.Policy.DNSName) != nil {
		return nil, errors.New("the local TLS certificate must identify the configured farm and DNS name")
	}
	ca, err := os.ReadFile(cfg.TLS.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read the federation CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("the federation CA file contains no certificates")
	}
	policy, err := json.Marshal(cfg.Policy)
	if err != nil {
		return nil, err
	}
	region := "/ocean/v1/regions/" + cfg.Policy.Farm
	resolvers := discoveryResolvers(cfg.DNSServers)
	s := &Service{cfg: cfg, policy: string(policy), client: client, region: region, root: region + "/federation",
		remotes: make(map[string]*http.Client, len(cfg.Policy.Peers))}
	for farm, peer := range cfg.Policy.Peers {
		s.remotes[farm] = &http.Client{Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext:       makePathDialer(peer.DNSName, peer.Paths[cfg.Path], cfg.Policy.LocalPath[cfg.Path].Addr(), resolvers),
				DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: peer.DNSName,
					Certificates: []tls.Certificate{certificate},
					VerifyConnection: func(state tls.ConnectionState) error {
						if !verifiedFarm(state, farm) {
							return errors.New("peer certificate does not identify the approved farm")
						}
						return nil
					}},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return s, nil
}

func farmCertificate(cert *x509.Certificate, farm string) bool {
	return cert != nil && len(cert.URIs) == 1 && cert.URIs[0].String() == "spiffe://ocean/farms/"+farm
}

func verifiedFarm(state tls.ConnectionState, farm string) bool {
	return len(state.VerifiedChains) != 0 && len(state.PeerCertificates) != 0 && farmCertificate(state.PeerCertificates[0], farm)
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+endpoint+"{farm}", s.receive)
	return mux
}

func (s *Service) receive(w http.ResponseWriter, r *http.Request) {
	farm := r.PathValue("farm")
	peer, approved := s.cfg.Policy.Peers[farm]
	source, sourceErr := netip.ParseAddrPort(r.RemoteAddr)
	if !approved || sourceErr != nil || source.Addr().Unmap() != peer.Paths[s.cfg.Path].Addr() ||
		r.TLS == nil || !verifiedFarm(*r.TLS, farm) {
		http.Error(w, "farm or transport path is not approved", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}
	offer, err := config.Decode(http.MaxBytesReader(w, r.Body, 8192), advertisement{})
	if err != nil {
		http.Error(w, "invalid pairing offer", http.StatusBadRequest)
		return
	}
	if !s.approvedOffer(farm, offer) {
		http.Error(w, "pairing offer does not match the approved routes", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := s.remember(ctx, farm); err != nil {
		http.Error(w, "local federation state is unavailable", http.StatusServiceUnavailable)
		return
	}
	body, _ := json.Marshal(s.offerFor(farm))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Service) offerFor(farm string) advertisement {
	return advertisement{Farm: s.cfg.Policy.Farm, PairID: pairingID(farm, s.cfg.Policy.Farm), Path: s.cfg.Path, Routes: s.cfg.Policy.Exports}
}

func (s *Service) approvedOffer(farm string, offer advertisement) bool {
	routes, err := canonicalRoutes(offer.Routes, nil)
	return err == nil && offer.Farm == farm && offer.Path == s.cfg.Path &&
		offer.PairID == pairingID(farm, s.cfg.Policy.Farm) && slices.Equal(routes, s.cfg.Policy.Peers[farm].Imports)
}

func (s *Service) Reconcile(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		var peers sync.WaitGroup
		for farm, peer := range s.cfg.Policy.Peers {
			peers.Go(func() {
				if err := s.exchange(ctx, farm, peer); err != nil && ctx.Err() == nil {
					logger.Debug("federation path is waiting for an approved exchange", "peer", farm, "path", s.cfg.Path, "error", err)
				}
			})
		}
		peers.Wait()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) exchange(parent context.Context, farm string, peer Peer) error {
	ctx, cancel := context.WithTimeout(parent, 7*time.Second)
	defer cancel()
	port := strconv.Itoa(int(peer.Paths[s.cfg.Path].Port()))
	url := "https://" + net.JoinHostPort(peer.DNSName, port) + endpoint + s.cfg.Policy.Farm
	body, _ := json.Marshal(s.offerFor(farm))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.remotes[farm].Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned HTTP %d", res.StatusCode)
	}
	reply, err := config.Decode(http.MaxBytesReader(nil, res.Body, 8192), advertisement{})
	if err != nil || !s.approvedOffer(farm, reply) {
		return errors.New("peer reply conflicts with the approved pairing")
	}
	revision, err := s.remember(ctx, farm)
	if err != nil {
		return err
	}
	return s.markPathLive(ctx, farm, revision)
}

func discoveryResolvers(servers []netip.AddrPort) []*net.Resolver {
	if len(servers) == 0 {
		return []*net.Resolver{net.DefaultResolver}
	}
	resolvers := make([]*net.Resolver, 0, len(servers))
	for _, server := range servers {
		resolvers = append(resolvers, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.String())
		}})
	}
	return resolvers
}

func makePathDialer(host string, endpoint netip.AddrPort, local netip.Addr, resolvers []*net.Resolver) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, destination string) (net.Conn, error) {
		if destination != net.JoinHostPort(host, strconv.Itoa(int(endpoint.Port()))) {
			return nil, errors.New("unexpected federation connection destination")
		}
		for _, resolver := range resolvers {
			probe, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
			addresses, err := resolver.LookupNetIP(probe, "ip4", host+".")
			cancel()
			if err == nil && slices.Contains(addresses, endpoint.Addr()) {
				dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}
				return dialer.DialContext(ctx, "tcp4", endpoint.String())
			}
		}
		return nil, errors.New("DNS did not return the approved address for this federation path")
	}
}
