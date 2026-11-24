package enrollment

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
)

type Config struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	InventoryFile   string `json:"inventoryFile"`
}

type Store interface {
	Enrollment(context.Context, string) (*Approval, *Host, int64, error)
	RedeemEnrollment(context.Context, Host, int64) (bool, error)
	PublishHostCapacity(context.Context, string, []byte, Report) error
	HostAssignments(context.Context, string, []byte, string) (AssignmentPage, error)
}

var (
	ErrHostDenied      = errors.New("host identity denied")
	ErrHostUnqualified = errors.New("host qualification failed")
)

type Authority struct {
	issuer *x509.Certificate
	signer crypto.Signer
	store  Store
}

func Open(settings Config, store Store) (*Authority, []Approval, error) {
	pair, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.KeyFile)
	if err != nil {
		return nil, nil, err
	}
	issuer := pair.Leaf
	signer, ok := pair.PrivateKey.(crypto.Signer)
	now := time.Now()
	if !ok || issuer == nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
		return nil, nil, errors.New("host enrollment requires a valid certificate-signing CA")
	}
	var inventory struct {
		Hosts []Approval `json:"hosts"`
	}
	inventory, err = config.Load(settings.InventoryFile, inventory)
	if err != nil {
		return nil, nil, err
	}
	identifiers := make(map[string]bool)
	for _, approved := range inventory.Hosts {
		if !approved.Valid() || approved.ExpiresAt.After(now.Add(24*time.Hour)) ||
			identifiers[approved.HostID] || identifiers[approved.MAC] || identifiers[approved.Address] || identifiers[approved.TokenSHA256] {
			return nil, nil, errors.New("invalid or duplicate host inventory record")
		}
		for _, key := range []string{approved.HostID, approved.MAC, approved.Address, approved.TokenSHA256} {
			identifiers[key] = true
		}
	}
	return &Authority{issuer: issuer, signer: signer, store: store}, inventory.Hosts, nil
}

func (a *Authority) Handler(fallback http.Handler) http.Handler {
	if fallback == nil {
		fallback = http.NotFoundHandler()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ocean/hosts/{host}/enrollment", a.enroll)
	mux.HandleFunc("POST /ocean/hosts/{host}/heartbeat", a.heartbeat)
	mux.HandleFunc("GET /ocean/hosts/{host}/placements", a.placements)
	mux.HandleFunc("GET /ocean/hosts/{host}/https-assignments", func(w http.ResponseWriter, r *http.Request) {
		a.gatewayAssignments(w, r, false)
	})
	mux.HandleFunc("POST /ocean/hosts/{host}/https-assignments/{slot}/status", func(w http.ResponseWriter, r *http.Request) {
		a.reportGatewayStatus(w, r, false)
	})
	mux.HandleFunc("GET /ocean/hosts/{host}/wireguard-assignments", func(w http.ResponseWriter, r *http.Request) {
		a.gatewayAssignments(w, r, true)
	})
	mux.HandleFunc("POST /ocean/hosts/{host}/wireguard-assignments/{slot}/status", func(w http.ResponseWriter, r *http.Request) {
		a.reportGatewayStatus(w, r, true)
	})
	mux.HandleFunc("GET /ocean/hosts/{host}", a.getHost)
	mux.Handle("/", fallback)
	return mux
}

func (a *Authority) enroll(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host")
	if r.TLS == nil || !hostName.MatchString(hostID) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	credentials := r.Header.Values("Authorization")
	if len(credentials) != 1 {
		reject(w, http.StatusUnauthorized, "InvalidEnrollmentCredential")
		return
	}
	scheme, token, ok := strings.Cut(credentials[0], " ")
	entropy, err := base64.RawURLEncoding.DecodeString(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || err != nil || len(entropy) != 32 {
		reject(w, http.StatusUnauthorized, "InvalidEnrollmentCredential")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	approved, current, revision, err := a.store.Enrollment(ctx, hostID)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
		return
	}
	digest := sha256.Sum256([]byte(token))
	if !accepts(approved, digest) || current == nil && !time.Now().Before(approved.ExpiresAt) {
		reject(w, http.StatusUnauthorized, "InvalidEnrollmentCredential")
		return
	}
	var request Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		reject(w, http.StatusBadRequest, "InvalidEnrollmentRequest")
		return
	}
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil || csr.CheckSignature() != nil || csr.PublicKeyAlgorithm != x509.Ed25519 {
		reject(w, http.StatusBadRequest, "InvalidHostKeyProof")
		return
	}
	keyHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	keyID := hex.EncodeToString(keyHash[:])
	if current != nil {
		returnExisting(w, *current, keyID)
		return
	}
	if _, qualified := approved.Available(request.Report); !qualified {
		reject(w, http.StatusUnprocessableEntity, "HostQualificationFailed")
		return
	}
	now := time.Now().UTC()
	cert, err := a.issue(hostID, csr.PublicKey.(ed25519.PublicKey), now)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
		return
	}
	host := Host{HostID: hostID, Cell: approved.Cell, Pool: approved.Pool, Profile: approved.Profile, Roles: approved.Roles,
		Report: request.Report, Certificate: cert, KeySHA256: keyID, JoinedAt: now}
	created, err := a.store.RedeemEnrollment(ctx, host, revision)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
		return
	}
	if created {
		respond(w, http.StatusCreated, host.Registration())
		return
	}
	approved, current, _, err = a.store.Enrollment(ctx, hostID)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
		return
	}
	if current == nil || !accepts(approved, digest) {
		reject(w, http.StatusConflict, "EnrollmentChanged")
		return
	}
	returnExisting(w, *current, keyID)
}

func (a *Authority) heartbeat(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host")
	if !hostName.MatchString(hostID) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	var report Report
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		reject(w, http.StatusBadRequest, "InvalidHostReport")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	switch err := a.store.PublishHostCapacity(ctx, hostID, peer.Raw, report); {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrHostUnqualified):
		reject(w, http.StatusUnprocessableEntity, "HostQualificationFailed")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func verifiedHostCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func (a *Authority) placements(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host")
	if !hostName.MatchString(hostID) {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	cursor := query["continuation"]
	if err != nil || len(query) != 0 && (len(query) != 1 || len(cursor) != 1 || !validAssignmentCursor(cursor[0])) {
		reject(w, http.StatusBadRequest, "InvalidPlacementQuery")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	result, err := a.store.HostAssignments(ctx, hostID, peer.Raw, query.Get("continuation"))
	if errors.Is(err, ErrHostDenied) {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "PlacementUnavailable")
		return
	}
	respond(w, http.StatusOK, result)
}

func validAssignmentCursor(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 3 && hostName.MatchString(parts[0]) && hostName.MatchString(parts[1]) && hostName.MatchString(parts[2])
}

func accepts(approval *Approval, digest [sha256.Size]byte) bool {
	if approval == nil {
		return false
	}
	expected, err := hex.DecodeString(approval.TokenSHA256)
	return err == nil && subtle.ConstantTimeCompare(digest[:], expected) == 1
}

func returnExisting(w http.ResponseWriter, host Host, keyID string) {
	if host.RevokedAt != nil || host.KeySHA256 != keyID {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	respond(w, http.StatusOK, host.Registration())
}

func (a *Authority) getHost(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("host")
	if !hostName.MatchString(hostID) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	_, host, _, err := a.store.Enrollment(ctx, hostID)
	if err != nil {
		reject(w, http.StatusServiceUnavailable, "EnrollmentUnavailable")
		return
	}
	if host == nil || host.RevokedAt != nil || !bytes.Equal(host.Certificate, peer.Raw) {
		reject(w, http.StatusForbidden, "HostIdentityDenied")
		return
	}
	respond(w, http.StatusOK, host.Registration())
}

func (a *Authority) issue(host string, key ed25519.PublicKey, now time.Time) ([]byte, error) {
	identity := &url.URL{Scheme: "urn", Opaque: "ocean:host:" + host}
	end := now.Add(24 * time.Hour)
	if a.issuer.NotAfter.Before(end) {
		end = a.issuer.NotAfter
	}
	template := &x509.Certificate{Subject: pkix.Name{CommonName: host}, URIs: []*url.URL{identity},
		NotBefore: now.Add(-time.Minute), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	return x509.CreateCertificate(rand.Reader, template, a.issuer, key, a.signer)
}

func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func reject(w http.ResponseWriter, status int, code string) {
	respond(w, status, map[string]string{"error": code})
}
