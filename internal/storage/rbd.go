// Package storage manages replicated, encrypted RBD volumes on qualified hosts.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const KeySize = 32

var (
	identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	deviceName = regexp.MustCompile(`^/dev/rbd[0-9]+$`)
)

type Config struct {
	Pool       string `json:"pool"`
	Client     string `json:"client"`
	CephConfig string `json:"cephConfig"`
	Keyring    string `json:"keyring"`
	MountRoot  string `json:"mountRoot"`
}

type Backend struct{ config Config }

type Volume struct {
	ID      string `json:"id"`
	SizeMiB int64  `json:"sizeMiB"`
}

func Open(config Config) (Backend, error) {
	if !identifier.MatchString(config.Pool) || !identifier.MatchString(config.Client) ||
		!filepath.IsAbs(config.CephConfig) || !filepath.IsAbs(config.Keyring) || !filepath.IsAbs(config.MountRoot) ||
		config.MountRoot == "/" || config.MountRoot != filepath.Clean(config.MountRoot) {
		return Backend{}, errors.New("RBD requires explicit Ceph paths, identities, and a dedicated mount directory")
	}
	return Backend{config: config}, nil
}

func ValidID(id string) bool { return identifier.MatchString(id) }

func (b Backend) image(id string) string { return b.config.Pool + "/" + id }

func (b Backend) MountPath(id string) string { return filepath.Join(b.config.MountRoot, id) }

func (b Backend) rbd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "/usr/bin/rbd", append([]string{"--conf", b.config.CephConfig,
		"--id", b.config.Client, "--keyring", b.config.Keyring}, args...)...)
}

func exitCode(err error, code int) bool {
	var failure *exec.ExitError
	return errors.As(err, &failure) && failure.ExitCode() == code
}

func output(command *exec.Cmd, label string) ([]byte, error) {
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return data, nil
}

func action(command *exec.Cmd, label string) error {
	_, err := output(command, label)
	return err
}

func (b Backend) imageSize(ctx context.Context, id string) (int64, error) {
	data, err := b.rbd(ctx, "info", b.image(id), "--format", "json").Output()
	if exitCode(err, 2) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read RBD volume: %w", err)
	}
	var info struct {
		Size     int64    `json:"size"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Size <= 0 {
		return 0, errors.New("invalid RBD volume description")
	}
	return info.Size, nil
}

// Create allocates a thin replicated image. An existing image must have the
// expected size, so a retry cannot resize an unrelated volume.
func (b Backend) Create(ctx context.Context, volume Volume) error {
	if !ValidID(volume.ID) || volume.SizeMiB < 128 || volume.SizeMiB > 32768 {
		return errors.New("invalid RBD volume identifier or capacity")
	}
	size, err := b.imageSize(ctx, volume.ID)
	if err != nil {
		return err
	}
	if size == 0 {
		err = action(b.rbd(ctx, "create", b.image(volume.ID), "--size", strconv.FormatInt(volume.SizeMiB, 10)+"M",
			"--image-feature", "layering,exclusive-lock"), "create RBD volume")
		if err != nil {
			if size, readErr := b.imageSize(ctx, volume.ID); readErr != nil || size != volume.SizeMiB<<20 {
				return err
			}
		}
		return nil
	}
	if size != volume.SizeMiB<<20 {
		return errors.New("existing RBD capacity does not match the volume")
	}
	return nil
}

type device struct {
	Pool   string `json:"pool"`
	Name   string `json:"name"`
	Device string `json:"device"`
	Snap   string `json:"snap"`
}

func (b Backend) lookup(ctx context.Context, id string) (string, error) {
	data, err := output(b.rbd(ctx, "device", "list", "--format", "json"), "list mapped RBD devices")
	if err != nil {
		return "", err
	}
	var mappings []device
	if err := json.Unmarshal(data, &mappings); err != nil {
		return "", errors.New("invalid RBD device inventory")
	}
	var found string
	for _, item := range mappings {
		if item.Name != id || item.Pool != b.config.Pool || item.Snap != "" && item.Snap != "-" {
			continue
		}
		if found != "" || !deviceName.MatchString(item.Device) {
			return "", errors.New("ambiguous RBD device mapping")
		}
		found = item.Device
	}
	return found, nil
}

func (b Backend) mapDevice(ctx context.Context, id string) (string, error) {
	path, err := b.lookup(ctx, id)
	if err != nil || path != "" {
		return path, err
	}
	mapped, err := output(b.rbd(ctx, "device", "map", "--exclusive", "--options", "ms_mode=secure,lock_timeout=8",
		b.image(id)), "map RBD volume exclusively")
	if err != nil {
		return "", err
	}
	path = strings.TrimSpace(string(mapped))
	if !deviceName.MatchString(path) {
		return "", errors.New("RBD returned an unexpected mapped device")
	}
	return path, nil
}

func (b Backend) unmap(ctx context.Context, device string) error {
	return action(b.rbd(ctx, "device", "unmap", device), "release exclusive RBD device")
}

func mapperName(id string) string { return "ocean-" + id }

func withKey(ctx context.Context, key []byte, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/sbin/cryptsetup", args...)
	command.Stdin = bytes.NewReader(key)
	return command
}

// Initialize formats a newly allocated image as LUKS2 and ext4. It is safe to
// resume before and after each format step, provided the caller holds the
// initialization claim for the volume.
func (b Backend) Initialize(ctx context.Context, volume Volume, key []byte) (err error) {
	if len(key) != KeySize {
		return errors.New("invalid volume encryption key")
	}
	if err := b.Create(ctx, volume); err != nil {
		return err
	}
	device, err := b.mapDevice(ctx, volume.ID)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		err = errors.Join(err, b.closeDevice(cleanup, volume.ID, device))
	}()
	probe := exec.CommandContext(ctx, "/usr/sbin/cryptsetup", "isLuks", "--type", "luks2", device).Run()
	if exitCode(probe, 1) {
		if err := action(withKey(ctx, key, "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", "--pbkdf", "argon2id",
			"--pbkdf-memory", "32768", "--pbkdf-parallel", "2", "--iter-time", "500", device), "format encrypted volume"); err != nil {
			return err
		}
	} else if probe != nil {
		return fmt.Errorf("check volume encryption format: %w", probe)
	}
	mapped, err := openCrypt(ctx, volume.ID, device, key)
	if err != nil {
		return err
	}
	format, probe := exec.CommandContext(ctx, "/usr/sbin/blkid", "-p", "-o", "value", "-s", "TYPE", mapped).Output()
	if exitCode(probe, 2) {
		return action(exec.CommandContext(ctx, "/usr/sbin/mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", mapped),
			"initialize encrypted file system")
	}
	if probe != nil || strings.TrimSpace(string(format)) != "ext4" {
		return errors.New("the encrypted volume has an unexpected file system")
	}
	return nil
}

func openCrypt(ctx context.Context, id, device string, key []byte) (string, error) {
	name := mapperName(id)
	mapped := filepath.Join("/dev/mapper", name)
	if _, err := os.Stat(mapped); err == nil {
		if err := action(withKey(ctx, key, "open", "--test-passphrase", "--type", "luks2", "--key-file", "-", device), "verify existing encrypted volume key"); err != nil {
			return "", err
		}
		return mapped, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := action(withKey(ctx, key, "open", "--type", "luks2", "--key-file", "-", device, name), "unlock encrypted volume"); err != nil {
		return "", err
	}
	return mapped, nil
}

func (b Backend) closeDevice(ctx context.Context, id, device string) error {
	if _, err := os.Stat(filepath.Join("/dev/mapper", mapperName(id))); err == nil {
		if err := action(exec.CommandContext(ctx, "/usr/sbin/cryptsetup", "close", mapperName(id)), "close encrypted volume"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return b.unmap(ctx, device)
}

// Mount delivers an already authorized filesystem to a dedicated local path.
// A caller must hold the cluster writer grant for this volume and generation.
func (b Backend) Mount(ctx context.Context, id string, key []byte, uid, gid int) (_ string, err error) {
	if !ValidID(id) || len(key) != KeySize || uid < 1 || gid < 1 {
		return "", errors.New("invalid encrypted volume mount request")
	}
	path := b.MountPath(id)
	if err := os.MkdirAll(b.config.MountRoot, 0755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}
	device, err := b.mapDevice(ctx, id)
	if err != nil {
		return "", err
	}
	wasMounted, mountedHere := false, false
	defer func() {
		if err == nil || wasMounted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		if mountedHere {
			err = errors.Join(err, action(exec.CommandContext(cleanup, "/usr/bin/umount", path), "withdraw incomplete encrypted mount"))
		}
		err = errors.Join(err, b.closeDevice(cleanup, id, device))
	}()
	mapped, err := openCrypt(ctx, id, device, key)
	if err != nil {
		return "", err
	}
	target, probe := existingMount(ctx, path)
	if probe != nil {
		return "", probe
	}
	if target != "" {
		wasMounted = true
		if !sameDevice(target, mapped) {
			return "", errors.New("mount point is owned by another device")
		}
	} else {
		if err := action(exec.CommandContext(ctx, "/usr/bin/mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", mapped, path),
			"mount encrypted volume"); err != nil {
			return "", err
		}
		mountedHere = true
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return "", err
	}
	return path, nil
}

func sameDevice(left, right string) bool {
	first, err := os.Stat(left)
	if err != nil {
		return false
	}
	second, err := os.Stat(right)
	return err == nil && os.SameFile(first, second)
}

func existingMount(ctx context.Context, path string) (string, error) {
	data, err := exec.CommandContext(ctx, "/usr/bin/findmnt", "--mountpoint", path, "--noheadings", "--output", "SOURCE").Output()
	if exitCode(err, 1) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect encrypted volume mount: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (b Backend) Unmount(ctx context.Context, id string) error {
	if !ValidID(id) {
		return errors.New("invalid volume ID")
	}
	path := b.MountPath(id)
	source, err := existingMount(ctx, path)
	if err != nil {
		return err
	}
	if source != "" {
		if !sameDevice(source, filepath.Join("/dev/mapper", mapperName(id))) {
			return errors.New("mount point is owned by another device")
		}
		if err := action(exec.CommandContext(ctx, "/usr/bin/umount", path), "unmount encrypted volume"); err != nil {
			return err
		}
	}
	device, err := b.lookup(ctx, id)
	if err != nil || device == "" {
		return err
	}
	return b.closeDevice(ctx, id, device)
}

// Snapshot captures the raw encrypted image. Callers coordinate guest flushes
// when an application-consistent checkpoint is required.
func (b Backend) Snapshot(ctx context.Context, volume, name string) error {
	if !ValidID(volume) || !ValidID(name) {
		return errors.New("invalid snapshot identifier")
	}
	return action(b.rbd(ctx, "snap", "create", b.image(volume)+"@"+name), "snapshot encrypted volume")
}

func (b Backend) Export(ctx context.Context, volume, snapshot string, destination io.Writer) error {
	if !ValidID(volume) || !ValidID(snapshot) {
		return errors.New("invalid backup source")
	}
	cmd := b.rbd(ctx, "export", "--export-format", "2", "--no-progress", b.image(volume)+"@"+snapshot, "-")
	cmd.Stdout = destination
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("export encrypted snapshot: %w", err)
	}
	return nil
}

func (b Backend) Import(ctx context.Context, volume string, source io.Reader) error {
	if !ValidID(volume) {
		return errors.New("invalid restore destination")
	}
	cmd := b.rbd(ctx, "import", "--export-format", "2", "--no-progress", "-", b.image(volume))
	cmd.Stdin = source
	return action(cmd, "restore encrypted image")
}

// Remove deletes an unbound image. Ceph refuses the removal while any client
// has the image mapped or while snapshots still reference it.
func (b Backend) Remove(ctx context.Context, id string) error {
	if !ValidID(id) {
		return errors.New("invalid volume ID")
	}
	size, err := b.imageSize(ctx, id)
	if err != nil || size == 0 {
		return err
	}
	return action(b.rbd(ctx, "rm", b.image(id)), "remove unbound encrypted volume")
}
