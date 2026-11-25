package storage

import (
	"context"
	"errors"
	"strings"
)

// OpenSMBVolume initializes and mounts the granted image with a root-owned
// filesystem and ext4 project quota. The grant belongs to the active member.
func (b Backend) OpenSMBVolume(ctx context.Context, volume Volume, key []byte) error {
	if !ValidID(volume.ID) || !strings.HasPrefix(volume.ID, "vol-") ||
		volume.SizeMiB < 128 || volume.SizeMiB > 32768 || len(key) != KeySize {
		return errors.New("invalid SMB volume grant")
	}
	mounted, err := existingMount(ctx, b.MountPath(volume.ID))
	if err != nil {
		return err
	}
	if mounted == "" {
		if err := b.initialize(ctx, volume, key, []string{"-m", "0", "-O", "quota,project"}); err != nil {
			return err
		}
	}
	_, err = b.mount(ctx, volume.ID, key, nil, "prjquota")
	return err
}
