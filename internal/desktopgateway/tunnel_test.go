package desktopgateway

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/coder/websocket"
)

func TestDesktopTunnelClosesAfterRevocation(t *testing.T) {
	const machine = "84b678b0-0a39-47d3-a355-ff4d84de4a83"
	const assignment = "49ed3571-cafa-493d-9001-7fb492b8be44"
	const generation = "310dee94-5876-489a-a5a9-4e25515f30e6"
	const upn = "desktop@ad.ocean.test"
	const fingerprint = "12:34"
	const subnet = "tenant-subnet"
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var deny atomic.Bool
	region := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer gateway-test-session" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if deny.Load() && strings.HasSuffix(r.URL.Path, "/renew") {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		now := time.Now()
		result := arm.DesktopSession{DesktopAdmission: arm.DesktopAdmission{MachineID: machine, AssignmentID: assignment, ExpiresAt: now.Add(12 * time.Second)},
			PrivateIP: netip.MustParseAddr("10.20.30.40"), User: upn, Generation: generation, NetworkInterface: "private-interface", SubnetID: subnet}
		if strings.HasSuffix(r.URL.Path, "/renew") {
			_ = json.NewEncoder(w).Encode(result)
			return
		}
		ticket, err := desktop.IssueLaunch(signer, machine, upn, now, result.ExpiresAt)
		if err != nil {
			t.Error(err)
			http.Error(w, "could not issue credential", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(arm.DesktopLaunch{DesktopSession: result, Credential: ticket})
	}))
	defer region.Close()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	guacdDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			guacdDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		guacdDone <- serveFixtureGuacd(conn, upn, fingerprint)
	}()
	var peer sessionPeer
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer.open(w, r, target{DesktopID: "/desktop-a", SubnetID: subnet, Fingerprint: fingerprint, Guacd: listener.Addr().String()},
			func(context.Context) (string, error) { return "gateway-test-session", nil })
	}))
	peer = sessionPeer{region: regionClient{origin: region.URL, http: region.Client()},
		origin: "https://" + gateway.Listener.Addr().String(), slots: make(chan struct{}, 2)}
	gateway.StartTLS()
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 16*time.Second)
	defer cancel()
	dial := func(origin string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(ctx, gateway.URL, &websocket.DialOptions{HTTPClient: gateway.Client(),
			HTTPHeader: http.Header{"Origin": {origin}}, Subprotocols: []string{"guacamole"}})
	}
	denied, response, err := dial("https://foreign.test")
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if denied != nil {
		_ = denied.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
		t.Fatal("foreign WebSocket origin reached the desktop")
	}

	browser, upgraded, err := dial(peer.origin)
	if upgraded != nil && upgraded.Body != nil {
		defer func() { _ = upgraded.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = browser.CloseNow() }()
	_, bootstrap, err := browser.Read(ctx)
	if err != nil || !strings.HasPrefix(string(bootstrap), "0.,") {
		t.Fatal("missing Guacamole WebSocket bootstrap")
	}
	_, display, err := browser.Read(ctx)
	if err != nil || string(display) != encodeInstruction("sync", "100", "1") {
		t.Fatalf("missing display update: %v", err)
	}
	if err := browser.Write(ctx, websocket.MessageText, []byte(encodeInstruction("key", "65", "1"))); err != nil {
		t.Fatal(err)
	}
	if err := browser.Write(ctx, websocket.MessageText, []byte(encodeInstruction("", "ping", "1"))); err != nil {
		t.Fatal(err)
	}
	_, pong, err := browser.Read(ctx)
	if err != nil || string(pong) != encodeInstruction("", "ping", "1") {
		t.Fatal("the gateway did not handle the Guacamole tunnel ping")
	}
	started := time.Now()
	deny.Store(true)
	_, _, err = browser.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation || time.Since(started) > 8*time.Second {
		t.Fatalf("the browser tunnel did not close on revocation: %v", err)
	}
	select {
	case err := <-guacdDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("the gateway did not close the backend socket")
	}
}

func serveFixtureGuacd(conn net.Conn, upn, fingerprint string) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	selectRDP, err := readInstruction(reader)
	if err != nil || !slices.Equal(selectRDP, []string{"select", "rdp"}) {
		return errors.New("gateway failed to select RDP")
	}
	args := []string{"args", "VERSION_1_5_0", "hostname", "port", "username", "password", "security", "cert-fingerprints", "disable-copy", "disable-paste"}
	if err := writeInstruction(conn, args...); err != nil {
		return err
	}
	for range 5 {
		if _, err := readInstruction(reader); err != nil {
			return err
		}
	}
	fields, err := readInstruction(reader)
	if err != nil || len(fields) != len(args) || !desktop.IsLaunchPassword([]byte(fields[5])) ||
		!slices.Equal(fields[:5], []string{"connect", "VERSION_1_5_0", "10.20.30.40", "3389", upn}) ||
		!slices.Equal(fields[6:], []string{"tls", "sha256:" + fingerprint, "true", "true"}) {
		return errors.New("gateway did not set the expected private TLS RDP parameters")
	}
	if err := writeInstruction(conn, "ready", "test-id"); err != nil {
		return err
	}
	if err := writeInstruction(conn, "sync", "100", "1"); err != nil {
		return err
	}
	fields, err = readInstruction(reader)
	if err != nil || !slices.Equal(fields, []string{"key", "65", "1"}) {
		return errors.New("gateway did not deliver browser keyboard input")
	}
	if _, err := reader.ReadByte(); err == nil {
		return errors.New("gateway did not close the connection")
	}
	return nil
}
