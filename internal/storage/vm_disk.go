package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	guestFirmwareBytes = 540672 // OVMF_VARS_4M.fd
	guestDiskName      = "disk.raw"
	guestFirmwareName  = "OVMF_VARS.fd"
	guestReceiptName   = "prepared.json"
)

// VMDisk binds a volume to a qualified raw OS disk and its paired firmware
// variables. The image digests identify the initial contents, which the guest
// can change after the import has been committed.
type VMDisk struct {
	ID             string `json:"id"`
	SizeGiB        int64  `json:"sizeGiB"`
	ImageSHA256    string `json:"imageSha256"`
	FirmwareSHA256 string `json:"firmwareSha256"`
}

type VMPaths struct {
	Disk         string
	FirmwareVars string
}

func vmDiskID(id string) bool { return strings.HasPrefix(id, "vm-") }

func validSHA256(digest string) bool {
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
}

func (d VMDisk) Valid() bool {
	return vmDiskID(d.ID) && ValidID(d.ID) && len(d.ID) > 3 && d.SizeGiB >= 32 && d.SizeGiB <= 128 &&
		validSHA256(d.ImageSHA256) && validSHA256(d.FirmwareSHA256)
}

func (d VMDisk) volume() Volume {
	// Allow for the LUKS header, the filesystem, its journal and the UEFI
	// state even after all of the guest's logical blocks have been written.
	return Volume{ID: d.ID, SizeMiB: d.SizeGiB*1024 + 2048}
}

func (b Backend) VMPaths(id string) VMPaths {
	path := b.MountPath(id)
	return VMPaths{Disk: filepath.Join(path, guestDiskName), FirmwareVars: filepath.Join(path, guestFirmwareName)}
}

// InitializeVMDisk imports a prepared image under the exclusive initialization
// grant. The caller supplies root-owned files from its local image catalog.
// An exact retry accepts the stored receipt and preserves subsequent writes.
func (b Backend) InitializeVMDisk(ctx context.Context, disk VMDisk, key []byte, source VMPaths) error {
	if !disk.Valid() || len(key) != KeySize {
		return errors.New("invalid VM disk enrollment")
	}
	path := b.MountPath(disk.ID)
	mounted, err := existingMount(ctx, path)
	if err != nil {
		return err
	}
	if mounted == "" {
		if err := b.initialize(ctx, disk.volume(), key, []string{"-T", "largefile4", "-m", "0"}); err != nil {
			return err
		}
	}
	_, err = b.mount(ctx, disk.ID, key, func(path string) error { return prepareVMDisk(ctx, path, disk, source) })
	if err != nil {
		return err
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	return b.Unmount(cleanup, disk.ID)
}

// AttachVMDisk is allowed only after the caller obtains the current writer
// grant. The runtime account can change the two backing files and has no
// directory write access to the initialization receipt.
func (b Backend) AttachVMDisk(ctx context.Context, disk VMDisk, key []byte, uid, gid int) (VMPaths, error) {
	if !disk.Valid() || len(key) != KeySize || uid < 1 || gid < 1 {
		return VMPaths{}, errors.New("invalid VM disk attachment")
	}
	files := b.VMPaths(disk.ID)
	_, err := b.mount(ctx, disk.ID, key, func(path string) error {
		if err := verifyVMDisk(path, disk); err != nil {
			return err
		}
		for _, file := range []string{files.Disk, files.FirmwareVars} {
			if err := os.Chown(file, uid, gid); err != nil {
				return err
			}
			if err := os.Chmod(file, 0600); err != nil {
				return err
			}
		}
		if err := os.Chown(path, 0, gid); err != nil {
			return err
		}
		return os.Chmod(path, 0710)
	})
	if err != nil {
		return VMPaths{}, err
	}
	return files, nil
}

func verifyVMDisk(path string, disk VMDisk) error {
	receipt := filepath.Join(path, guestReceiptName)
	info, err := os.Lstat(receipt)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024 || info.Mode().Perm()&0077 != 0 {
		return errors.New("invalid VM disk preparation receipt")
	}
	data, err := os.ReadFile(receipt)
	if err != nil {
		return err
	}
	var prepared VMDisk
	if json.Unmarshal(data, &prepared) != nil || prepared != disk {
		return errors.New("the VM disk preparation receipt does not match its image and volume")
	}
	for _, file := range []struct {
		name  string
		bytes int64
	}{{guestDiskName, disk.SizeGiB << 30}, {guestFirmwareName, guestFirmwareBytes}} {
		info, err := os.Lstat(filepath.Join(path, file.name))
		if err != nil || !info.Mode().IsRegular() || info.Size() != file.bytes {
			return errors.New("a prepared VM backing file is missing or has an unexpected length")
		}
	}
	return nil
}

func prepareVMDisk(ctx context.Context, path string, disk VMDisk, source VMPaths) error {
	if err := verifyVMDisk(path, disk); err == nil || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	// The absence of a receipt permits replacement of interrupted staging
	// data. An attached VM must have a receipt before it can open either file.
	for _, name := range []string{guestDiskName, guestFirmwareName, guestReceiptName + ".partial"} {
		if err := os.Remove(filepath.Join(path, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	diskSource, err := openVMImageFile(source.Disk, disk.SizeGiB<<30)
	if err != nil {
		return err
	}
	defer func() { _ = diskSource.Close() }()
	firmware, err := openVMImageFile(source.FirmwareVars, guestFirmwareBytes)
	if err != nil {
		return err
	}
	defer func() { _ = firmware.Close() }()
	vars, err := io.ReadAll(io.LimitReader(firmware, guestFirmwareBytes+1))
	if err != nil || len(vars) != guestFirmwareBytes || fmt.Sprintf("%x", sha256.Sum256(vars)) != disk.FirmwareSHA256 {
		return errors.New("the supplied VM firmware variables do not match the pinned image")
	}
	image := filepath.Join(path, guestDiskName)
	copy := exec.CommandContext(ctx, "/usr/bin/qemu-img", "convert", "-f", "raw", "-O", "raw", "-S", "4k", "/proc/self/fd/3", image)
	copy.ExtraFiles = []*os.File{diskSource}
	if output, err := copy.CombinedOutput(); err != nil {
		return fmt.Errorf("import sparse VM disk: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := syncVMImage(ctx, image, disk); err != nil {
		return err
	}
	if err := writeVMFile(filepath.Join(path, guestFirmwareName), vars); err != nil {
		return err
	}
	return recordVMDisk(path, disk)
}

func openVMImageFile(path string, size int64) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("the VM image catalog requires an absolute file path")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	err = unix.Fstat(int(file.Fd()), &stat)
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0077 != 0 || stat.Size != size {
		return nil, errors.Join(errors.New("VM image files must be private root-owned files of the expected size"), err, file.Close())
	}
	return file, nil
}

func syncVMImage(ctx context.Context, image string, disk VMDisk) (err error) {
	file, err := os.OpenFile(image, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	if info, err := file.Stat(); err != nil || info.Size() != disk.SizeGiB<<30 {
		return errors.New("the imported VM disk has an unexpected length")
	}
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, err := file.Read(buffer)
		if count != 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != disk.ImageSHA256 {
		return errors.New("the imported VM disk does not match the pinned image digest")
	}
	return errors.Join(file.Chmod(0600), file.Sync())
}

func writeVMFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Sync(), file.Close())
}

func recordVMDisk(path string, disk VMDisk) (err error) {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	if err := directory.Sync(); err != nil {
		return err
	}
	receipt, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	prepared := filepath.Join(path, guestReceiptName)
	partial := prepared + ".partial"
	if err := writeVMFile(partial, receipt); err != nil {
		return err
	}
	if err := os.Rename(partial, prepared); err != nil {
		return err
	}
	return directory.Sync()
}
