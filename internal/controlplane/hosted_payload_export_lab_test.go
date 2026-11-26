//go:build e2e

package controlplane

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/Weichwolf/ocean/internal/arm"
)

func verifyHostedSMBArchive(t *testing.T, ctx context.Context, cfg regionConfig, scope arm.SubscriptionScope, foreignTenant string,
	share arm.ResourceAddress, recipient *age.X25519Identity, metadata, payload []byte) {
	t.Helper()
	var page struct {
		Format         string
		TenantID       string
		SubscriptionID string
		CapturedAt     time.Time
		NextLink       string
		Records        []struct {
			Kind string
			Data struct{ ID string }
		}
	}
	if err := json.Unmarshal(metadata, &page); err != nil || page.Format != "ocean-hosted-export-v1" ||
		page.TenantID != scope.TenantID || page.SubscriptionID != scope.SubscriptionID || page.CapturedAt.IsZero() || page.NextLink != "" {
		t.Fatalf("invalid export for the small regional fixture: %v", err)
	}
	shareID := share.ID(scope)
	foundShare := false
	for _, record := range page.Records {
		if record.Kind == "resource" {
			if !strings.HasPrefix(record.Data.ID, "/subscriptions/"+scope.SubscriptionID+"/") {
				t.Fatal("the exported resource belongs to a different subscription")
			}
			foundShare = foundShare || record.Data.ID == shareID
		}
	}
	if !foundShare || !bytes.Equal(payload, []byte("ocean Kerberos SMB payload\n")) || bytes.Contains(metadata, payload) {
		t.Fatal("the export must contain the actual managed share reference and its separately acquired SMB checkpoint")
	}
	var bundle bytes.Buffer
	tarball := tar.NewWriter(&bundle)
	for _, input := range []struct {
		name string
		data []byte
	}{
		{"regional.json", metadata},
		{"files/ocean-managed-checkpoint.bin", payload},
	} {
		if err := tarball.WriteHeader(&tar.Header{Name: input.name, Mode: 0600, Size: int64(len(input.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarball.Write(input.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarball.Close(); err != nil {
		t.Fatal(err)
	}
	defer clear(bundle.Bytes())
	hash := fmt.Sprintf("%x", sha256.Sum256(bundle.Bytes()))
	configPath := filepath.Join(t.TempDir(), "backup.json")
	settings, err := json.Marshal(settings{Region: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, settings, 0600); err != nil {
		t.Fatal(err)
	}
	backup := hostedBackupLabCLI(t, ctx, configPath)
	args := []string{"-kind", "export", "-subscription", scope.SubscriptionID, "-sha256", hash}
	backup("create", "short", "backup requires the active tenant subscription", bundle.Bytes(), append(args, "-tenant", foreignTenant)...)
	args = append(args, "-tenant", scope.TenantID)
	backup("create", "partner", "tenant policy does not authorize this backup target", bundle.Bytes(), args...)
	archiveDir := cfg.HostedWorkplace.BackupTargets["short"].ArchiveDirectory
	for _, destination := range []string{archiveDir, cfg.HostedWorkplace.BackupTargets["partner"].ArchiveDirectory} {
		if rows, err := os.ReadDir(destination); err != nil || len(rows) != 0 {
			t.Fatalf("a denied export left an archive, count %d: %v", len(rows), err)
		}
	}
	var approved HostedBackupResult
	if err := json.Unmarshal(backup("create", "short", "", bundle.Bytes(), args...), &approved); err != nil ||
		filepath.Base(approved.Archive) != approved.Archive || filepath.Ext(approved.Archive) != ".age" ||
		approved.SourceBytes != int64(bundle.Len()) || !approved.ExpiresAt.After(time.Now()) {
		t.Fatalf("invalid approved export receipt: %v", err)
	}
	path := filepath.Join(archiveDir, approved.Archive)
	var pruned struct{ Removed int }
	if err := json.Unmarshal(backup("prune", "short", "", nil), &pruned); err != nil || pruned.Removed != 0 {
		t.Fatalf("prune must keep the export before expiry: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("approved export was not stored as a private regular file: %v", err)
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil || bytes.Contains(ciphertext, payload) {
		t.Fatalf("approved SMB export was not encrypted: %v", err)
	}
	stranger, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(bytes.NewReader(ciphertext), stranger); err == nil {
		t.Fatal("an unauthorized recipient opened the archive")
	}
	plain, err := age.Decrypt(bytes.NewReader(ciphertext), recipient)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(plain)
	defer clear(restored)
	if err != nil || !bytes.Equal(restored, bundle.Bytes()) {
		t.Fatalf("the authorized recipient did not recover the exact regional metadata and SMB bytes: %v", err)
	}
	pollVMWorker(t, ctx, 12*time.Second, "the configured SMB export retention", func() bool { return !time.Now().Before(approved.ExpiresAt) })
	if err := json.Unmarshal(backup("prune", "short", "", nil), &pruned); err != nil || pruned.Removed != 1 {
		t.Fatalf("expiry did not remove the exact archive: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired export still present: %v", err)
	}
}
