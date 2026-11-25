package storage

import (
	"context"
	"errors"
	"strings"
)

func ValidSMBStateVolumeID(id string) bool {
	return ValidID(id) && strings.HasPrefix(id, "smb-state-") && len(id) > len("smb-state-")
}

// OpenSMBMemberState opens already provisioned Samba machine state. The
// runtime never creates a replacement identity on an empty or missing image.
func (b Backend) OpenSMBMemberState(ctx context.Context, id string, key []byte) error {
	if !ValidSMBStateVolumeID(id) || len(key) != KeySize {
		return errors.New("invalid encrypted SMB state grant")
	}
	_, err := b.mount(ctx, id, key, nil)
	return err
}

// OpenSMBVolume mounts the granted image with ext4 project quota. Only a
// volume that has never been published can be allocated and formatted.
func (b Backend) OpenSMBVolume(ctx context.Context, volume Volume, key []byte, mayInitialize bool) error {
	if !ValidID(volume.ID) || !strings.HasPrefix(volume.ID, "vol-") ||
		volume.SizeMiB < 128 || volume.SizeMiB > 32768 || len(key) != KeySize {
		return errors.New("invalid SMB volume grant")
	}
	if mayInitialize {
		mounted, err := existingMount(ctx, b.MountPath(volume.ID))
		if err != nil {
			return err
		}
		if mounted == "" {
			if err := b.initialize(ctx, volume, key, []string{"-m", "0", "-O", "quota,project"}); err != nil {
				return err
			}
		}
	}
	_, err := b.mount(ctx, volume.ID, key, nil, "prjquota")
	return err
}
