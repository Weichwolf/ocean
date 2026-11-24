package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadServerDefaultsAndOverrides(t *testing.T) {
	defaults, err := LoadServer("", "127.0.0.1:8081")
	if err != nil || defaults.ListenAddress != "127.0.0.1:8081" || defaults.LogLevel != slog.LevelInfo || defaults.TLS != nil {
		t.Fatalf("LoadServer defaults = %+v, %v", defaults, err)
	}
	path := writeSettings(t, `{"listenAddress":"0.0.0.0:8443","logLevel":"DEBUG","tls":{"certificateFile":"cert.pem","keyFile":"key.pem"}}`)
	settings, err := LoadServer(path, "127.0.0.1:8081")
	if err != nil || settings.ListenAddress != "0.0.0.0:8443" || settings.LogLevel != slog.LevelDebug || settings.TLS == nil || settings.TLS.KeyFile != "key.pem" {
		t.Fatalf("LoadServer overrides = %+v, %v", settings, err)
	}
}

func TestLoadServerRejectsInvalidSettings(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want string
	}{
		{"unknown field", `{"port":8080}`, "unknown field"},
		{"invalid level", `{"logLevel":"trace"}`, "level"},
		{"trailing object", `{} {}`, "one JSON object"},
		{"null", `null`, "must be a JSON object"},
		{"bad address", `{"listenAddress":"127.0.0.1:70000"}`, "invalid listenAddress"},
		{"public cleartext", `{"listenAddress":"0.0.0.0:8080"}`, "TLS is required"},
		{"missing TLS key", `{"tls":{"certificateFile":"cert.pem"}}`, "certificateFile and keyFile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadServer(writeSettings(t, test.json), "127.0.0.1:8081")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadServer error = %v, want %q", err, test.want)
			}
		})
	}
}

func writeSettings(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
