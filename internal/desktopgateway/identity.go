package desktopgateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	callbackPath   = "/oauth/callback"
	signInCookie   = "__Host-ocean-desktop-oauth"
	sessionCookie  = "__Host-ocean-desktop-session"
	signInLifetime = 3 * time.Minute
	sessionLife    = 8 * time.Hour
	maxBrowserAuth = 512
)

type identitySettings struct {
	Issuer   string `json:"issuer"`
	CAFile   string `json:"caFile"`
	ClientID string `json:"clientId"`
}

type browserIdentity struct {
	client   *http.Client
	issuer   string
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	mu       sync.Mutex
	pending  map[string]signIn
	sessions map[string]*browserSession
}

type signIn struct {
	desktop, state, nonce, verifier string
	expires                         time.Time
}

type browserSession struct {
	desktop string
	expires time.Time
	user    *browserIdentity
	lock    chan struct{}
	token   *oauth2.Token
}

func newBrowserIdentity(cfg identitySettings, origin string) (*browserIdentity, error) {
	if _, err := parseHTTPS(cfg.Issuer); err != nil || !enrollment.ValidDirectoryJoinID(cfg.ClientID) {
		return nil, errors.New("desktop identity requires the dedicated OIDC issuer and application client ID")
	}
	client, err := identityHTTP(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	return &browserIdentity{client: client, issuer: cfg.Issuer,
		oauth:   oauth2.Config{ClientID: cfg.ClientID, RedirectURL: origin + callbackPath, Scopes: []string{oidc.ScopeOpenID}},
		pending: make(map[string]signIn), sessions: make(map[string]*browserSession)}, nil
}

func (b *browserIdentity) startup(ctx context.Context) error {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, b.client), b.issuer)
	if err != nil {
		return errors.New("desktop OIDC discovery failed")
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		if _, err := parseHTTPS(raw); err != nil {
			return errors.New("desktop OIDC endpoints must use HTTPS")
		}
	}
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	b.oauth.Endpoint = endpoint
	b.verifier = provider.VerifierContext(oidc.ClientContext(context.Background(), b.client), &oidc.Config{ClientID: b.oauth.ClientID})
	return nil
}

func desktopCookie(name, value string, age time.Duration) *http.Cookie {
	seconds := int(age.Seconds())
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: seconds,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func (b *browserIdentity) start(w http.ResponseWriter, r *http.Request, desktop string) {
	now := time.Now()
	id := rand.Text()
	flow := signIn{desktop: desktop, state: rand.Text(), nonce: rand.Text(), verifier: oauth2.GenerateVerifier(), expires: now.Add(signInLifetime)}
	b.mu.Lock()
	for key, candidate := range b.pending {
		if !now.Before(candidate.expires) {
			delete(b.pending, key)
		}
	}
	atLimit := len(b.pending) >= maxBrowserAuth
	if !atLimit {
		b.pending[id] = flow
	}
	b.mu.Unlock()
	if atLimit {
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, desktopCookie(signInCookie, id, signInLifetime))
	http.Redirect(w, r, b.oauth.AuthCodeURL(flow.state, oauth2.S256ChallengeOption(flow.verifier),
		oauth2.SetAuthURLParam("nonce", flow.nonce), oauth2.SetAuthURLParam("acr_values", "ocean-web")), http.StatusSeeOther)
}

func (b *browserIdentity) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(signInCookie)
	query := r.URL.Query()
	if err != nil || len(query["state"]) != 1 || len(query["code"]) != 1 || query.Get("code") == "" ||
		len(query.Get("code")) > 4096 || query.Has("error") || query.Has("iss") && query.Get("iss") != b.issuer {
		http.Error(w, "Desktop sign-in was denied.", http.StatusUnauthorized)
		return
	}
	b.mu.Lock()
	flow, ok := b.pending[cookie.Value]
	if ok {
		delete(b.pending, cookie.Value)
	}
	b.mu.Unlock()
	http.SetCookie(w, desktopCookie(signInCookie, "", -time.Second))
	if !ok || !time.Now().Before(flow.expires) || subtle.ConstantTimeCompare([]byte(flow.state), []byte(query.Get("state"))) != 1 {
		http.Error(w, "Desktop sign-in was denied.", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	token, err := b.oauth.Exchange(oidc.ClientContext(ctx, b.client), query.Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil || !token.Valid() || token.RefreshToken == "" || token.Expiry.IsZero() || token.TokenType != "Bearer" {
		http.Error(w, "Desktop sign-in was denied.", http.StatusUnauthorized)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Desktop sign-in was denied.", http.StatusUnauthorized)
		return
	}
	id, err := b.verifier.Verify(ctx, raw)
	var claims struct {
		Assurance string `json:"acr"`
	}
	if err != nil || len(id.Audience) != 1 || !enrollment.ValidDirectoryJoinID(id.Subject) || id.Claims(&claims) != nil || claims.Assurance != "ocean-web" ||
		subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(flow.nonce)) != 1 {
		http.Error(w, "Desktop sign-in was denied.", http.StatusUnauthorized)
		return
	}
	sessionID := rand.Text()
	now := time.Now()
	b.mu.Lock()
	for key, candidate := range b.sessions {
		if !now.Before(candidate.expires) {
			delete(b.sessions, key)
		}
	}
	atLimit := len(b.sessions) >= maxBrowserAuth
	if !atLimit {
		b.sessions[sessionID] = &browserSession{desktop: flow.desktop, expires: now.Add(sessionLife),
			user: b, lock: make(chan struct{}, 1), token: token}
	}
	b.mu.Unlock()
	if atLimit {
		http.Error(w, "Sign-in is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, desktopCookie(sessionCookie, sessionID, sessionLife))
	http.Redirect(w, r, "/d/"+flow.desktop, http.StatusSeeOther)
}

func (b *browserIdentity) session(r *http.Request, desktop string) *browserSession {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	b.mu.Lock()
	session := b.sessions[cookie.Value]
	b.mu.Unlock()
	if session == nil || session.desktop != desktop || !time.Now().Before(session.expires) {
		return nil
	}
	return session
}

func (s *browserSession) access(ctx context.Context) (string, error) {
	if !time.Now().Before(s.expires) {
		return "", errDesktopAccess
	}
	select {
	case s.lock <- struct{}{}:
		defer func() { <-s.lock }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if s.token.Expiry.After(time.Now().Add(20 * time.Second)) {
		return s.token.AccessToken, nil
	}
	refresh := s.user.oauth.TokenSource(oidc.ClientContext(ctx, s.user.client), &oauth2.Token{RefreshToken: s.token.RefreshToken})
	token, err := refresh.Token()
	if err != nil || !token.Valid() || token.Expiry.IsZero() || token.TokenType != "Bearer" {
		return "", errDesktopAccess
	}
	s.token = token
	return token.AccessToken, nil
}
