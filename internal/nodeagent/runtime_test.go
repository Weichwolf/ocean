package nodeagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		want   string
	}{
		{"rootless", "printf 'true\\n'", ""},
		{"rootful", "printf 'false\\n'", "rootless mode"},
		{"probe error", "exit 1", "probe Podman"},
		{"missing binary", "", "executable file not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("PATH", directory)
			if test.script != "" {
				path := filepath.Join(directory, "podman")
				if err := os.WriteFile(path, []byte("#!/bin/sh\n"+test.script+"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := CheckRuntime(context.Background())
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("CheckRuntime error = %v, want %q", err, test.want)
			}
		})
	}
}
