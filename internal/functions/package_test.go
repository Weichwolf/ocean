package functions

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type packageFixtureFile struct {
	name string
	mode fs.FileMode
	body string
}

func zipFixture(t *testing.T, files ...packageFixtureFile) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, file := range files {
		header := zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetMode(file.mode)
		entry, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, file.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestZIPPackageVerifiesAndUnpacks(t *testing.T) {
	files := []packageFixtureFile{
		{"host.json", 0644, `{"version":"2.0","extensions":{"http":{"routePrefix":"api"}}}`},
		{"hello/index.js", 0755, "module.exports = async function () {};"},
		{"hello/", fs.ModeDir | 0755, ""},
		{"empty/", fs.ModeDir | 0755, ""},
	}
	payload := zipFixture(t, files...)
	pkg, err := ReadZIPPackage(payload)
	if err != nil || pkg.Digest() != fmt.Sprintf("%x", sha256.Sum256(payload)) {
		t.Fatalf("ZIP verification or digest failed: %v", err)
	}
	root, err := pkg.Unpack(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("the package tree is accessible outside the worker account: %v", err)
	}
	for _, item := range files {
		target := filepath.Join(root, item.name)
		if item.mode.IsDir() {
			info, err := os.Stat(target)
			if err != nil || !info.IsDir() {
				t.Fatalf("could not restore an explicit package directory: %v", err)
			}
			continue
		}
		data, err := os.ReadFile(target)
		if err != nil || string(data) != item.body {
			t.Fatalf("could not reproduce the admitted package bytes: %v", err)
		}
	}
}

func TestZIPPackageRejectsUnsafeAndBrokenArchives(t *testing.T) {
	host := packageFixtureFile{"host.json", 0644, `{"version":"2.0"}`}
	file := packageFixtureFile{"node/index.js", 0644, "fixture"}
	tests := []struct {
		name  string
		files []packageFixtureFile
	}{
		{"wrong layout", []packageFixtureFile{{"app/host.json", 0644, host.body}, file}},
		{"wrong version", []packageFixtureFile{{"host.json", 0644, `{"version":"3.0"}`}, file}},
		{"relative traversal", []packageFixtureFile{host, {"node/../../outside", 0644, "write"}}},
		{"absolute path", []packageFixtureFile{host, {"/outside", 0644, "write"}}},
		{"backslash path", []packageFixtureFile{host, {"node\\index.js", 0644, "write"}}},
		{"oversized path component", []packageFixtureFile{host, {strings.Repeat("a", 256), 0644, "write"}}},
		{"symlink", []packageFixtureFile{host, {"node", fs.ModeSymlink | 0777, "/outside"}}},
		{"FIFO", []packageFixtureFile{host, {"node", fs.ModeNamedPipe | 0600, ""}}},
		{"duplicate file", []packageFixtureFile{host, file, file}},
		{"file shadows directory", []packageFixtureFile{host, file, {"node", 0644, "write"}}},
		{"directory shadows file", []packageFixtureFile{host, {"node", 0644, "write"}, file}},
		{"expanded file too large", []packageFixtureFile{host, {"large", 0644, strings.Repeat("0", maxZIPMemberBytes+1)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadZIPPackage(zipFixture(t, test.files...)); err == nil {
				t.Fatal("accepted an unsupported package")
			}
		})
	}
	if _, err := ReadZIPPackage(make([]byte, MaxZIPBytes+1)); !errors.Is(err, ErrZIPPackageTooLarge) {
		t.Fatal("did not apply the limit to the compressed package")
	}
	tooMany := make([]packageFixtureFile, 0, maxZIPMembers+1)
	tooMany = append(tooMany, host)
	for index := range maxZIPMembers {
		tooMany = append(tooMany, packageFixtureFile{fmt.Sprintf("%d.js", index), 0644, ""})
	}
	if _, err := ReadZIPPackage(zipFixture(t, tooMany...)); !errors.Is(err, ErrZIPPackageTooLarge) {
		t.Fatal("did not apply the limit to the number of archive entries")
	}
	wide := []packageFixtureFile{host}
	expanded := strings.Repeat("0", maxZIPMemberBytes)
	for index := range maxZIPExpanded / maxZIPMemberBytes {
		wide = append(wide, packageFixtureFile{fmt.Sprintf("%d.bin", index), 0644, expanded})
	}
	if _, err := ReadZIPPackage(zipFixture(t, wide...)); !errors.Is(err, ErrZIPPackageTooLarge) {
		t.Fatal("did not apply the aggregate expansion limit")
	}
	broken := zipFixture(t, host, file)
	centralHeader := bytes.LastIndex(broken, []byte{'P', 'K', 1, 2})
	if centralHeader < 0 || len(broken) < centralHeader+17 {
		t.Fatal("could not locate the fixture's central file header")
	}
	broken[centralHeader+16] ^= 1
	if _, err := ReadZIPPackage(broken); !errors.Is(err, ErrInvalidZIPPackage) {
		t.Fatal("accepted an entry with the wrong CRC")
	}
}
