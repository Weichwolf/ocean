//go:build e2e

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	labVMOSOffset   = 8 << 20
	labVMVarsOffset = 4 << 10
)

func TestEncryptedVMDisk(t *testing.T) {
	backend, key, id := rbdLabBackend(t)
	uid, gid := rbdLabWorker(t)
	disk := VMDisk{ID: id, SizeGiB: 32, ImageSHA256: os.Getenv("OCEAN_E2E_VM_DISK_SHA"), FirmwareSHA256: os.Getenv("OCEAN_E2E_VM_VARS_SHA")}
	if !disk.Valid() {
		t.Fatal("the dedicated VM disk profile requires pinned input digests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := backend.Unmount(cleanup, disk.ID); err != nil {
			t.Error(err)
		}
	})
	mode := os.Getenv("OCEAN_E2E_RBD_MODE")
	if mode == "write" {
		qualifyVMImport(t, ctx, backend, disk, key, uid, gid)
	} else if mode != "reopen" {
		t.Fatal("unknown VM disk lab test mode")
	}
	wrongKey := make([]byte, KeySize)
	if _, err := backend.AttachVMDisk(ctx, disk, wrongKey, uid, gid); err == nil {
		t.Fatal("the VM disk was exposed with the wrong encryption key")
	}
	files, err := backend.AttachVMDisk(ctx, disk, key, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("ocean-vm-acknowledged-write-" + id)
	for _, check := range []struct {
		path   string
		offset int64
	}{{files.Disk, labVMOSOffset}, {files.FirmwareVars, labVMVarsOffset}} {
		contents := executeAsVMWorker(t, ctx, "dd", "if="+check.path, "iflag=skip_bytes,count_bytes",
			fmt.Sprintf("skip=%d", check.offset), fmt.Sprintf("count=%d", len(marker)), "status=none")
		if !bytes.Equal(contents, marker) {
			t.Fatalf("VM backing data did not retain acknowledged write at %d", check.offset)
		}
	}
	if err := backend.Unmount(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Log("reopened the same encrypted VM disk and UEFI state with the acknowledged writes and rejected the wrong key")
}

func qualifyVMImport(t *testing.T, ctx context.Context, backend Backend, disk VMDisk, key []byte, uid, gid int) {
	t.Helper()
	source := t.TempDir()
	inputs := VMPaths{Disk: filepath.Join(source, guestDiskName), FirmwareVars: filepath.Join(source, guestFirmwareName)}
	file, err := os.OpenFile(inputs.Disk, os.O_WRONLY|os.O_EXCL|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(disk.SizeGiB << 30); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	const base = "seeded-guest-disk"
	if _, err := file.WriteAt([]byte(base), labVMOSOffset); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	vars := make([]byte, guestFirmwareBytes)
	copy(vars[labVMVarsOffset:], "seeded-guest-vars")
	if fmt.Sprintf("%x", sha256.Sum256(vars)) != disk.FirmwareSHA256 {
		t.Fatal("the lab firmware pin does not match its fixture")
	}
	if err := os.WriteFile(inputs.FirmwareVars, vars, 0600); err != nil {
		t.Fatal(err)
	}
	bad := disk
	bad.ImageSHA256 = strings.Repeat("a", 64)
	if err := backend.InitializeVMDisk(ctx, bad, key, inputs); err == nil || !strings.Contains(err.Error(), "pinned image digest") {
		t.Fatalf("the VM disk did not reject the wrong image digest: %v", err)
	}
	if _, err := backend.AttachVMDisk(ctx, disk, key, uid, gid); err == nil {
		t.Fatal("an uncommitted import was attached")
	}
	if err := backend.InitializeVMDisk(ctx, disk, key, inputs); err != nil {
		t.Fatal(err)
	}
	files, err := backend.AttachVMDisk(ctx, disk, key, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(files.Disk)
	executeAsVMWorker(t, ctx, "test", "!", "-w", root)
	executeAsVMWorker(t, ctx, "test", "!", "-r", filepath.Join(root, guestReceiptName))
	seed := executeAsVMWorker(t, ctx, "dd", "if="+files.Disk, "iflag=skip_bytes,count_bytes", fmt.Sprintf("skip=%d", labVMOSOffset),
		fmt.Sprintf("count=%d", len(base)), "status=none")
	if string(seed) != base {
		t.Fatal("the imported disk did not contain the pinned seed")
	}
	marker := "ocean-vm-acknowledged-write-" + disk.ID
	for _, write := range []struct {
		path   string
		offset int64
	}{{files.Disk, labVMOSOffset}, {files.FirmwareVars, labVMVarsOffset}} {
		command := exec.CommandContext(ctx, "/usr/sbin/runuser", "-u", "ocean-agent", "--", "/usr/bin/dd", "of="+write.path,
			"oflag=seek_bytes", fmt.Sprintf("seek=%d", write.offset), "conv=notrunc,fsync", "status=none")
		command.Stdin = strings.NewReader(marker)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("write VM backing file: %v: %s", err, output)
		}
	}
	opened, err := os.Open(files.Disk)
	if err != nil {
		t.Fatal(err)
	}
	busy := backend.Unmount(ctx, disk.ID)
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if busy == nil {
		t.Fatal("the VM disk detached while a process held the file open")
	}
	if err := backend.Unmount(ctx, disk.ID); err != nil {
		t.Fatal(err)
	}
	if err := backend.InitializeVMDisk(ctx, disk, key, VMPaths{}); err != nil {
		t.Fatalf("replaying the committed import requires no source and must preserve guest changes: %v", err)
	}
	if err := backend.Snapshot(ctx, disk.ID, "vm-ready"); err != nil {
		t.Fatal(err)
	}
	file, err = os.CreateTemp(t.TempDir(), "vm-export-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := backend.Export(ctx, disk.ID, "vm-ready", file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if found, err := containsMarker(file, []byte(marker)); err != nil || found {
		t.Fatal("the encrypted VM snapshot leaked its plaintext marker or was unreadable")
	}
	t.Log("verified image pin rejection, resumable import, restricted runtime access, busy detach refusal and encrypted snapshot export")
}

func executeAsVMWorker(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	output, err := exec.CommandContext(ctx, "/usr/sbin/runuser", append([]string{"-u", "ocean-agent", "--"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("VM runtime file permissions or contents failed: %v: %s", err, output)
	}
	return output
}
