package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Weichwolf/ocean/internal/config"
)

func TestHealthHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := healthHandler(ctx, nil)

	assertStatus := func(method, path string, want int) {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != want {
			t.Errorf("%s %s returned %d, want %d", method, path, response.Code, want)
		}
	}

	assertStatus(http.MethodGet, "/livez", http.StatusNoContent)
	assertStatus(http.MethodGet, "/readyz", http.StatusNoContent)
	assertStatus(http.MethodPost, "/readyz", http.StatusMethodNotAllowed)
	assertStatus(http.MethodGet, "/subscriptions", http.StatusNotFound)
	cancel()
	assertStatus(http.MethodGet, "/readyz", http.StatusServiceUnavailable)
}

func TestServeFailsStartupCheck(t *testing.T) {
	startupError := errors.New("dependency unavailable")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	err := serve(context.Background(), config.Server{ListenAddress: "127.0.0.1:0"}, Hooks{Startup: func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("startup check has no deadline")
		}
		return startupError
	}}, logger)
	if !errors.Is(err, startupError) {
		t.Fatalf("serve error = %v, want %v", err, startupError)
	}
}

func TestReadinessTracksDependencyWithoutChangingLiveness(t *testing.T) {
	available := false
	handler := healthHandler(context.Background(), func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("readiness probe has no deadline")
		}
		if !available {
			return errors.New("quorum unavailable")
		}
		return nil
	})
	for _, test := range []struct {
		path      string
		available bool
		want      int
	}{
		{"/livez", false, http.StatusNoContent},
		{"/readyz", false, http.StatusServiceUnavailable},
		{"/readyz", true, http.StatusNoContent},
	} {
		available = test.available
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.want {
			t.Errorf("%s returned %d with dependency available=%t, want %d", test.path, response.Code, available, test.want)
		}
	}
}
