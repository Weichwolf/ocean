package desktopgateway

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/nodeagent"
	"github.com/Weichwolf/ocean/internal/service"
)

type settings struct {
	config.Server
	PublicOrigin          string            `json:"publicOrigin"`
	HostConfigFile        string            `json:"hostConfigFile"`
	Identity              identitySettings  `json:"identity"`
	GuacamoleScriptFile   string            `json:"guacamoleScriptFile"`
	GuacamoleScriptSHA256 string            `json:"guacamoleScriptSha256"`
	Desktops              map[string]target `json:"desktops"`
	MaximumConcurrent     int               `json:"maximumConcurrent"`
}

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// Load configures a TLS desktop gateway for one dedicated workforce application.
func Load(path string) (config.Server, service.Hooks, error) {
	cfg, err := config.Load(path, settings{MaximumConcurrent: 32})
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	if err := cfg.Server.Validate(); err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	origin, err := parseHTTPS(cfg.PublicOrigin)
	if err != nil || origin.Path != "" || cfg.TLS == nil || cfg.TLS.ClientCAFile != "" {
		return config.Server{}, service.Hooks{}, errors.New("desktop gateway requires a public HTTPS origin and a TLS listener")
	}
	if cfg.MaximumConcurrent < 1 || cfg.MaximumConcurrent > 256 || len(cfg.Desktops) < 1 || len(cfg.Desktops) > 256 {
		return config.Server{}, service.Hooks{}, errors.New("desktop gateway requires 1 to 256 configured desktop routes and a bounded session capacity")
	}
	for slug, desktop := range cfg.Desktops {
		if !slugPattern.MatchString(slug) || !desktop.valid() {
			return config.Server{}, service.Hooks{}, fmt.Errorf("invalid configured desktop route %q", slug)
		}
	}
	regionOrigin, regionHTTP, err := nodeagent.OpenHostAccess(cfg.HostConfigFile)
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	script, err := loadScript(cfg.GuacamoleScriptFile, cfg.GuacamoleScriptSHA256)
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	auth, err := newBrowserIdentity(cfg.Identity, cfg.PublicOrigin)
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	peer := sessionPeer{region: regionClient{origin: regionOrigin, http: regionHTTP}, origin: cfg.PublicOrigin, slots: make(chan struct{}, cfg.MaximumConcurrent)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/guacamole.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(script)
	})
	mux.HandleFunc("GET /assets/desktop.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, viewerJS)
	})
	mux.HandleFunc("GET /oauth/callback", auth.callback)
	mux.HandleFunc("GET /d/{desktop}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("desktop")
		if _, ok := cfg.Desktops[slug]; !ok {
			http.NotFound(w, r)
			return
		}
		if auth.session(r, slug) == nil {
			auth.start(w, r, slug)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, viewerHTML)
	})
	mux.HandleFunc("GET /d/{desktop}/tunnel", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("desktop")
		desktop, ok := cfg.Desktops[slug]
		if !ok {
			http.NotFound(w, r)
			return
		}
		session := auth.session(r, slug)
		if session == nil {
			http.Error(w, "A current desktop sign-in is required.", http.StatusUnauthorized)
			return
		}
		peer.open(w, r, desktop, session.access)
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; script-src 'self'; "+
			"style-src 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' wss://"+origin.Host)
		if !strings.EqualFold(r.Host, origin.Host) {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return cfg.Server, service.Hooks{Startup: auth.startup, Handler: handler}, nil
}

func (t target) valid() bool {
	parts := strings.Split(t.DesktopID, "/")
	if len(parts) != 9 || !enrollment.ValidDirectoryJoinID(parts[2]) {
		return false
	}
	scope := arm.SubscriptionScope{SubscriptionID: parts[2]}
	_, desktopOK := arm.NetworkResourceAddress(scope, t.DesktopID, arm.DesktopType)
	_, _, subnetOK := arm.SubnetParent(scope, t.SubnetID)
	addr, addrErr := netip.ParseAddrPort(t.Guacd)
	fingerprint, hashErr := hex.DecodeString(strings.ReplaceAll(t.Fingerprint, ":", ""))
	return desktopOK && subnetOK && addrErr == nil && addr.Addr().IsLoopback() && addr.Port() != 0 &&
		hashErr == nil && len(fingerprint) == sha256.Size
}

func parseHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.User != nil || u.String() != raw {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

func loadScript(path, fingerprint string) ([]byte, error) {
	digest, err := hex.DecodeString(fingerprint)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("a Guacamole JavaScript SHA-256 digest is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	const limit = 2 << 20
	script, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(script) == 0 || len(script) > limit {
		return nil, errors.New("invalid Guacamole JavaScript bundle")
	}
	actual := sha256.Sum256(script)
	if !bytes.Equal(actual[:], digest) {
		return nil, errors.New("Guacamole JavaScript digest does not match")
	}
	return script, nil
}

func identityHTTP(caFile string) (*http.Client, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("desktop identity requires the issuer CA")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
