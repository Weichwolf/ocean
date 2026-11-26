package desktopgateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/coder/websocket"
)

const (
	accessCheckInterval = 5 * time.Second
	tunnelWriteTimeout  = 5 * time.Second
)

type target struct {
	DesktopID   string `json:"desktopId"`
	SubnetID    string `json:"subnetId"`
	Fingerprint string `json:"fingerprint"`
	Guacd       string `json:"guacd"`
}

type accessToken func(context.Context) (string, error)

type sessionPeer struct {
	region regionClient
	origin string
	slots  chan struct{}
}

func (p sessionPeer) open(w http.ResponseWriter, r *http.Request, desktop target, token accessToken) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Origin") != p.origin ||
		!slices.Contains(strings.FieldsFunc(strings.Join(r.Header.Values("Sec-WebSocket-Protocol"), ","), protocolSeparator), "guacamole") {
		http.Error(w, "A same-origin Guacamole WebSocket is required.", http.StatusBadRequest)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Desktop gateway capacity is temporarily exhausted.", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	setup, finishSetup := context.WithTimeout(ctx, 12*time.Second)
	defer finishSetup()
	bearer, err := token(setup)
	if err != nil {
		http.Error(w, "A current desktop sign-in is required.", http.StatusUnauthorized)
		return
	}
	launch, err := p.region.request(setup, desktop.DesktopID, "launch", bearer)
	if errors.Is(err, errDesktopAccess) {
		http.Error(w, "Desktop access denied.", http.StatusForbidden)
		return
	}
	if err != nil || launch.SubnetID != desktop.SubnetID {
		http.Error(w, "The desktop is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	conn, err := (&net.Dialer{}).DialContext(setup, "tcp", desktop.Guacd)
	if err != nil {
		http.Error(w, "The desktop is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := setup.Deadline()
	if limit := launch.ExpiresAt.Add(-250 * time.Millisecond); limit.Before(deadline) {
		deadline = limit
	}
	if err := conn.SetDeadline(deadline); err != nil {
		http.Error(w, "The desktop is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	guacd, err := openGuacamole(conn, launch, desktop.Fingerprint)
	launch.Credential = ""
	if err != nil || !time.Now().Before(launch.ExpiresAt) || conn.SetDeadline(time.Time{}) != nil {
		http.Error(w, "The desktop is temporarily unavailable.", http.StatusServiceUnavailable)
		return
	}
	browser, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return
	}
	defer func() { _ = browser.CloseNow() }()
	browser.SetReadLimit(64 << 10)
	if err := writeBrowser(ctx, browser, "", rand.Text()); err != nil {
		return
	}
	done := make(chan error, 3)
	go func() { done <- browserToGuacamole(ctx, browser, conn) }()
	go func() { done <- guacamoleToBrowser(ctx, guacd, browser) }()
	go func() { done <- p.renew(ctx, desktop.DesktopID, token, launch.DesktopSession) }()
	err = <-done
	_ = conn.Close()
	if errors.Is(err, errDesktopAccess) {
		_ = browser.Close(websocket.StatusPolicyViolation, "")
		return
	}
	_ = browser.Close(websocket.StatusNormalClosure, "")
}

func protocolSeparator(char rune) bool { return char == ',' || char == ' ' || char == '\t' }

func (p sessionPeer) renew(ctx context.Context, id string, token accessToken, active arm.DesktopSession) error {
	for {
		now := time.Now()
		wait := min(accessCheckInterval, active.ExpiresAt.Sub(now)/2)
		if wait <= 0 {
			return errDesktopAccess
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		check, cancel := context.WithDeadline(ctx, active.ExpiresAt)
		bearer, err := token(check)
		var next arm.DesktopLaunch
		if err == nil {
			next, err = p.region.request(check, id, "renew", bearer)
		}
		cancel()
		if err != nil || !time.Now().Before(active.ExpiresAt) {
			return errDesktopAccess
		}
		expires := next.ExpiresAt
		next.ExpiresAt = active.ExpiresAt
		if next.DesktopSession != active {
			return errDesktopAccess
		}
		active.ExpiresAt = expires
	}
}

func writeBrowser(ctx context.Context, browser *websocket.Conn, fields ...string) error {
	write, cancel := context.WithTimeout(ctx, tunnelWriteTimeout)
	defer cancel()
	return browser.Write(write, websocket.MessageText, []byte(encodeInstruction(fields...)))
}

func guacamoleToBrowser(ctx context.Context, guacd *bufio.Reader, browser *websocket.Conn) error {
	for {
		instruction, err := readInstruction(guacd)
		if err != nil {
			return err
		}
		if instruction[0] == "" || instruction[0] == "ready" || instruction[0] == "require" {
			return errors.New("unexpected Guacamole instruction")
		}
		if err := writeBrowser(ctx, browser, instruction...); err != nil {
			return err
		}
	}
}

func browserToGuacamole(ctx context.Context, browser *websocket.Conn, guacd net.Conn) error {
	for {
		message, data, err := browser.Read(ctx)
		if err != nil {
			return err
		}
		if message != websocket.MessageText {
			return errDesktopAccess
		}
		in := bufio.NewReader(bytes.NewReader(data))
		for {
			if _, err := in.Peek(1); errors.Is(err, io.EOF) {
				break
			}
			fields, err := readInstruction(in)
			if err != nil {
				return err
			}
			switch fields[0] {
			case "":
				if len(fields) != 3 || fields[1] != "ping" || len(fields[2]) > 20 {
					return errDesktopAccess
				}
				if err := writeBrowser(ctx, browser, fields...); err != nil {
					return err
				}
			case "size":
				if !validBrowserSize(fields) {
					return errDesktopAccess
				}
				fallthrough
			case "key", "mouse", "touch", "sync", "ack", "nop":
				if err := guacd.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout)); err != nil {
					return err
				}
				if err := writeInstruction(guacd, fields...); err != nil {
					return err
				}
			case "disconnect":
				return nil
			default:
				return errDesktopAccess
			}
		}
	}
}

func validBrowserSize(fields []string) bool {
	if len(fields) != 3 && len(fields) != 4 {
		return false
	}
	limits := [...]uint64{3840, 2160, 300}
	for i, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 16)
		if err != nil || value == 0 || value > limits[i] {
			return false
		}
	}
	return true
}
