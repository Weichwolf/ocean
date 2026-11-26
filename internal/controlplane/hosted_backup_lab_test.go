//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
)

func configureHostedBackupLab(t *testing.T, policy *hostedRegionPolicy, shortRetentionSeconds int64) *age.X25519Identity {
	t.Helper()
	privateDir := func() string {
		path := t.TempDir()
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	policy.BackupStagingDirectory = privateDir()
	policy.BackupTargets = map[string]hostedBackupTarget{
		"approved": {OperatorPool: "primary", ArchiveDirectory: privateDir(), Recipient: key.Recipient().String(), RetentionSeconds: 120},
		"partner":  {OperatorPool: "partner", ArchiveDirectory: privateDir(), Recipient: key.Recipient().String(), RetentionSeconds: 120},
		"short":    {OperatorPool: "primary", ArchiveDirectory: privateDir(), Recipient: key.Recipient().String(), RetentionSeconds: shortRetentionSeconds},
	}
	return key
}

func verifyHostedBackup(t *testing.T, ctx context.Context, cfg regionConfig, r *Region, scope arm.SubscriptionScope,
	quota enrollment.Capacity, key *age.X25519Identity, dir string) string {
	t.Helper()
	started := time.Now()
	configPath := filepath.Join(dir, "backup.json")
	writeConfig := func(value regionConfig) {
		t.Helper()
		data, err := json.Marshal(settings{Region: &value})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(cfg)
	run := hostedBackupLabCLI(t, ctx, configPath)
	result := func(raw []byte) HostedBackupResult {
		t.Helper()
		var out HostedBackupResult
		if err := json.Unmarshal(raw, &out); err != nil || filepath.Base(out.Archive) != out.Archive || out.SourceBytes <= 0 || !out.ExpiresAt.After(time.Now()) {
			t.Fatalf("invalid backup result: %v", err)
		}
		return out
	}
	entries := func(target string, count int) {
		t.Helper()
		rows, err := os.ReadDir(cfg.HostedWorkplace.BackupTargets[target].ArchiveDirectory)
		if err != nil || len(rows) != count {
			t.Fatalf("unexpected number of objects at target %s: %d: %v", target, len(rows), err)
		}
	}
	run("create", "unknown", "outside the approved regional policy", nil)
	run("create", "partner", "a tenant policy does not authorize this regional snapshot target", nil)
	mismatch := cfg
	policy := *cfg.HostedWorkplace
	policy.Country = "FR"
	mismatch.HostedWorkplace = &policy
	writeConfig(mismatch)
	run("create", "approved", "differs from the persisted hosted region", nil)
	writeConfig(cfg)
	fixture := []byte("synthetic private tenant export bytes\n")
	checksum := fmt.Sprintf("%x", sha256.Sum256(fixture))
	exportArgs := []string{"-kind", "export", "-tenant", scope.TenantID, "-subscription", scope.SubscriptionID, "-sha256", checksum}
	run("create", "partner", "tenant policy does not authorize this backup target", fixture, exportArgs...)
	run("create", "approved", "failed its SHA-256 checksum", fixture[:len(fixture)-2], exportArgs...)
	entries("approved", 0)
	entries("partner", 0)

	request := HostedBackupRequest{Target: "approved", Kind: "export", TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		SHA256: checksum, Input: &backupPolicyChangingReader{reader: bytes.NewReader(fixture), change: func() error {
			quota.CPUMillis++
			return r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"primary"}, Quota: quota})
		}}}
	if _, err := SaveHostedBackup(ctx, configPath, request); err == nil || !strings.Contains(err.Error(), "policy changed during backup") {
		t.Fatalf("backup published across a moving policy barrier: %v", err)
	}
	entries("approved", 0)
	if rows, err := os.ReadDir(cfg.HostedWorkplace.BackupStagingDirectory); err != nil || len(rows) != 0 {
		t.Fatalf("rejected input left staging bytes: %v", err)
	}

	backup := result(run("create", "approved", "", nil))
	archiveDir := cfg.HostedWorkplace.BackupTargets["approved"].ArchiveDirectory
	archivePath := filepath.Join(archiveDir, backup.Archive)
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if info, err := file.Stat(); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("regional archive is not owner-only: %v", err)
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(file, wrong); err == nil {
		t.Fatal("the wrong recipient decrypted the regional archive")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	plain, err := age.Decrypt(file, key)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "region.snapshot")
	output, err := os.OpenFile(snapshot, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, copyErr := io.Copy(output, plain)
	if err := errors.Join(copyErr, output.Close()); err != nil || n != backup.SourceBytes {
		t.Fatalf("the decrypted native snapshot has unexpected contents: %v", err)
	}

	if _, err := r.client.Put(ctx, "/outside-fixture", "synthetic"); err != nil {
		t.Fatal(err)
	}
	run("create", "approved", "require a dedicated etcd cluster", nil)
	entries("approved", 1)
	short := result(run("create", "short", "", fixture, exportArgs...))
	shortDir := cfg.HostedWorkplace.BackupTargets["short"].ArchiveDirectory
	sealed, err := os.ReadFile(filepath.Join(shortDir, short.Archive))
	if err != nil || bytes.Contains(sealed, fixture) {
		t.Fatalf("expected an encrypted export: %v", err)
	}
	decrypted, err := age.Decrypt(bytes.NewReader(sealed), key)
	if err != nil {
		t.Fatal(err)
	}
	if contents, err := io.ReadAll(decrypted); err != nil || !bytes.Equal(contents, fixture) {
		t.Fatalf("approved scoped export did not round-trip: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shortDir, "unrelated.age"), []byte("independent file"), 0600); err != nil {
		t.Fatal(err)
	}
	run("prune", "short", "", nil)
	entries("short", 2)
	pollVMWorker(t, ctx, 7*time.Second, "the short backup retention interval", func() bool { return !time.Now().Before(short.ExpiresAt) })
	offline := cfg
	offline.Etcd.Endpoints = []string{"https://127.0.0.1:1"}
	writeConfig(offline)
	raw := run("prune", "short", "", nil)
	var deleted struct{ Removed int }
	if err := json.Unmarshal(raw, &deleted); err != nil || deleted.Removed != 1 {
		t.Fatalf("the expiry operation did not remove exactly one archive: %v", err)
	}
	entries("short", 1)
	entries("approved", 1)
	t.Logf("ocean-backup encrypted and verified a native etcd snapshot and a tenant export, withheld unapproved, incomplete and concurrent captures, and expired one archive with the source offline. Verification took %d ms.", time.Since(started).Milliseconds())
	return snapshot
}

func hostedBackupLabCLI(t *testing.T, ctx context.Context, configPath string) func(string, string, string, []byte, ...string) []byte {
	t.Helper()
	binary := filepath.Join("..", "..", "bin", "ocean-backup")
	return func(op, target, want string, input []byte, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, append([]string{op, "-config", configPath, "-target", target}, args...)...)
		command.Stdin = bytes.NewReader(input)
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		output, err := command.Output()
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(diagnostics.String(), want)) {
			t.Fatalf("backup %s of %s expected %q: %v: %s", op, target, want, err, diagnostics.String())
		}
		return output
	}
}

type backupPolicyChangingReader struct {
	reader *bytes.Reader
	change func() error
}

func (r *backupPolicyChangingReader) Read(data []byte) (int, error) {
	if r.change != nil {
		change := r.change
		r.change = nil
		if err := change(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(data)
}
