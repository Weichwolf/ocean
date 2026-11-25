package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
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

func FuzzLoadServerConfig(f *testing.F) {
	for _, input := range []string{
		`{}`,
		`{"listenAddress":"[::1]:8080","logLevel":"DEBUG"}`,
		`{"listenAddress":"0.0.0.0:8443","tls":{"certificateFile":"cert.pem","keyFile":"key.pem"}}`,
		`{"listenAddress":"[::]:8080"}`,
		`{"tls":{"certificateFile":"cert.pem","keyFile":"key.pem","optionalClientCA":true}}`,
		`{"tls":{"unknown":true}}`,
		`{"listenAddress":`,
		`{} null`,
		`null`,
		`[]`,
	} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		defaults := Server{ListenAddress: "127.0.0.1:8081"}
		settings, err := Decode(bytes.NewReader(input), defaults)
		if err != nil {
			return
		}
		trimmed := bytes.TrimSpace(input)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(input) {
			t.Fatal("decoder accepted input other than a single JSON object")
		}
		if settings.Validate() != nil {
			return
		}
		addr, err := netip.ParseAddrPort(settings.ListenAddress)
		if err != nil {
			t.Fatalf("accepted invalid listener address: %v", err)
		}
		if settings.TLS == nil && !addr.Addr().Unmap().IsLoopback() {
			t.Fatal("accepted a plaintext non-loopback listener")
		}
		if settings.TLS != nil && (settings.TLS.CertificateFile == "" || settings.TLS.KeyFile == "" ||
			(settings.TLS.OptionalClientCA && settings.TLS.ClientCAFile == "")) {
			t.Fatal("accepted incomplete TLS settings")
		}
		encoded, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Decode(bytes.NewReader(encoded), defaults)
		if err != nil || !reflect.DeepEqual(settings, restored) {
			t.Fatalf("configuration changed after re-encoding: %v", err)
		}
	})
}

func writeSettings(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
