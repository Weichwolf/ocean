//go:build e2e

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestEncryptedRBDDataPath(t *testing.T) {
	config := os.Getenv("OCEAN_E2E_RBD_CONFIG")
	if config == "" {
		t.Skip("dedicated RBD lab is not configured")
	}
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var profile Config
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	backend, err := Open(profile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(os.Getenv("OCEAN_E2E_RBD_KEY"))
	if err != nil || len(key) != KeySize {
		t.Fatal("the lab encryption key is unavailable")
	}
	defer clear(key)
	id := os.Getenv("OCEAN_E2E_RBD_ID")
	if !ValidID(id) {
		t.Fatal("invalid lab volume ID")
	}
	backup := os.Getenv("OCEAN_E2E_RBD_BACKUP")
	account, err := user.Lookup("ocean-agent")
	if err != nil {
		t.Fatal(err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		t.Fatal("invalid lab runtime identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	marker := []byte("ocean-encrypted-checkpoint-" + id + "\n")
	if expected := os.Getenv("OCEAN_E2E_RBD_CHECKSUM"); expected != "" {
		marker = []byte(expected + "\n")
	}
	unmount := func(id string) {
		t.Helper()
		if err := backend.Unmount(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	readMarker := func(id string, key []byte) {
		t.Helper()
		path, err := backend.Mount(ctx, id, key, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		defer unmount(id)
		got, err := os.ReadFile(filepath.Join(path, "checkpoint"))
		if err != nil || !bytes.Equal(got, marker) {
			t.Fatal("the encrypted file system did not contain the expected checkpoint")
		}
	}
	switch os.Getenv("OCEAN_E2E_RBD_MODE") {
	case "write":
		volume := Volume{ID: id, SizeMiB: 1024}
		for range 2 {
			if err := backend.Initialize(ctx, volume, key); err != nil {
				t.Fatal(err)
			}
		}
		path, err := backend.Mount(ctx, id, key, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "checkpoint"), marker, 0600); err != nil {
			t.Fatal(err)
		}
		unmount(id)
		if err := backend.Snapshot(ctx, id, "checkpoint"); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(backup, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := backend.Export(ctx, id, "checkpoint", file); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if found, err := containsMarker(file, marker); err != nil || found {
			t.Fatal("the exported RBD snapshot exposed the cleartext checkpoint or could not be read")
		}
		t.Log("LUKS2 and ext4 survived initialization retries. The raw snapshot export contained no plaintext checkpoint.")
	case "recovery-copy":
		checksum := os.Getenv("OCEAN_E2E_RBD_CHECKSUM")
		if len(checksum) != 64 {
			t.Fatal("invalid recovery checkpoint digest")
		}
		file, err := os.Open(backup)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := backend.Import(ctx, id, file); err != nil {
			t.Fatal(err)
		}
		wrong := make([]byte, KeySize)
		if _, err := backend.Mount(ctx, id, wrong, uid, gid); err == nil {
			unmount(id)
			t.Fatal("the isolated data copy accepted an unauthorized key")
		}
		readMarker(id, key)
		t.Log("The independent copy returned the checkpoint with the restored metadata key.")
	case "restore":
		wrongKey := make([]byte, KeySize)
		if _, err := backend.Mount(ctx, id, wrongKey, uid, gid); err == nil {
			unmount(id)
			t.Fatal("a volume mount accepted an unauthorized key")
		}
		readMarker(id, key)
		file, err := os.Open(backup)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		restored := "restored-" + id
		if err := backend.Import(ctx, restored, file); err != nil {
			t.Fatal(err)
		}
		readMarker(restored, key)
		t.Log("A separate KVM worker reopened the original volume and restored the independent export with the authorized key.")
	default:
		t.Fatal("unknown RBD lab test mode")
	}
}

func containsMarker(source io.Reader, marker []byte) (bool, error) {
	buffer := make([]byte, (1<<16)+len(marker)-1)
	prior := 0
	for {
		count, err := source.Read(buffer[prior:])
		window := buffer[:prior+count]
		if bytes.Contains(window, marker) {
			return true, nil
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return false, err
		}
		prior = min(len(marker)-1, len(window))
		copy(buffer, window[len(window)-prior:])
	}
}
