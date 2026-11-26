package nodeagent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareVMRuntime(t *testing.T) {
	for _, name := range []string{"fresh", "private_parent"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "ocean-vm")
			locals := filepath.Join(root, "locals")
			if name == "private_parent" {
				if err := os.MkdirAll(locals, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareVMRuntime(root); err != nil {
				t.Fatal(err)
			}
			for path, mode := range map[string]os.FileMode{root: 0755, locals: 0700} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if !info.IsDir() || info.Mode().Perm() != mode {
					t.Fatalf("%s has mode %s, want directory with %04o permissions", path, info.Mode(), mode)
				}
			}
		})
	}
}
