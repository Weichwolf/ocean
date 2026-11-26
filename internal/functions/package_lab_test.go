//go:build e2e

package functions

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nodeZIPRuntime = "mcr.microsoft.com/azure-functions/node@sha256:76b0a2318403992100bdc72f2698e9d938e1a3b1e210c28c11aaaeb57221a6c1"

func TestNativeZIPFunction(t *testing.T) {
	if os.Getenv("OCEAN_E2E_FUNCTIONS_ZIP_NATIVE") != "1" {
		t.Skip("requires rootless Podman and the pinned native Functions runtime")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"first", "second"} {
		t.Run(version, func(t *testing.T) {
			var files []packageFixtureFile
			for _, name := range []string{"host.json", "hello/function.json", "hello/index.js"} {
				data, err := os.ReadFile(filepath.Join(root, "tests/e2e/testdata/workloads/functions-zip", name))
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, packageFixtureFile{name, 0644, string(data)})
			}
			files = append(files, packageFixtureFile{"hello/package-version.js", 0644, fmt.Sprintf("module.exports = %q;\n", version)})
			artifact, err := ReadZIPPackage(zipFixture(t, files...))
			if err != nil {
				t.Fatal(err)
			}
			tree, err := artifact.Unpack(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			command := exec.CommandContext(t.Context(), "python3", "-B", "-c", `
from pathlib import Path
from sys import argv
from verify_function_fixtures import podman, run_fixture
if podman("info", "--format", "{{.Host.Security.Rootless}}", capture=True) != "true":
    raise RuntimeError("The native ZIP probe requires rootless Podman.")
print(run_fixture(argv[1], argv[2], package=Path(argv[3])))
`, nodeZIPRuntime, "zip:"+version+":fixture", tree)
			command.Dir = filepath.Join(root, "lab")
			result, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native ZIP fixture failed: %v: %s", err, result)
			}
			t.Logf("Package sha256:%s indexed, served version %s and enforced Function keys in %d ms using %s.",
				artifact.Digest(), version, time.Since(start).Milliseconds(), strings.TrimSpace(string(result)))
		})
	}
}
