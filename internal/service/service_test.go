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
	handler := healthHandler(ctx)

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
	err := serve(context.Background(), config.Server{ListenAddress: "127.0.0.1:0"}, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("startup check has no deadline")
		}
		return startupError
	}, logger)
	if !errors.Is(err, startupError) {
		t.Fatalf("serve error = %v, want %v", err, startupError)
	}
}
