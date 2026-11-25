package smb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

const sambaConfig = "/etc/samba/smb.conf"

// ApplyPlan reconciles the dedicated member and reports after Samba has
// published the requested configuration and retired all withdrawn mounts.
func ApplyPlan(ctx context.Context, backend storage.Backend, plan Plan) error {
	if !plan.Valid() {
		return ErrInvalidPlan
	}
	if plan.Member.StateVolumeID != "" {
		if err := preparePlacement(ctx, backend, plan); err != nil {
			return err
		}
	}
	for _, grant := range plan.Volumes {
		if !grant.Withdraw {
			if err := backend.OpenSMBVolume(ctx, grant.Volume, grant.Key, !grant.Initialized); err != nil {
				return fmt.Errorf("mount SMB volume %s: %w", grant.Volume.ID, err)
			}
		}
	}
	previous, err := os.ReadFile(sambaConfig)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ensureWinbind(ctx, plan.Member, previous); err != nil {
		return err
	}
	// Existing smbd processes can retain their authorized session token. Drop
	// those processes before changing the configuration or releasing storage.
	var stop func() error
	if !bytes.Equal(previous, configuration(plan.Member)) || len(plan.Member.Shares) == 0 {
		stop = func() error { return Stop(ctx) }
	}
	if err := prepare(ctx, plan.Member, sambaConfig, stop); err != nil {
		return err
	}
	for _, grant := range plan.Volumes {
		if !grant.Withdraw {
			continue
		}
		if err := backend.Unmount(ctx, grant.Volume.ID); err != nil {
			return fmt.Errorf("release SMB volume %s: %w", grant.Volume.ID, err)
		}
		if err := backend.Remove(ctx, grant.Volume.ID); err != nil {
			return fmt.Errorf("delete SMB volume %s: %w", grant.Volume.ID, err)
		}
	}
	if plan.Member.StateVolumeID != "" {
		placement, err := readPlacement()
		if err != nil {
			return err
		}
		placement.Volumes = slices.DeleteFunc(placement.Volumes, func(id string) bool {
			return slices.ContainsFunc(plan.Volumes, func(grant VolumeGrant) bool {
				return grant.Volume.ID == id && grant.Withdraw
			})
		})
		if err := writePlacement(placement); err != nil {
			return err
		}
	}
	return EnsureActive(ctx, plan.Member)
}

func ensureWinbind(ctx context.Context, member Member, previous []byte) error {
	if member.StateVolumeID != "" && !bytes.Contains(previous, []byte("private dir = "+member.stateDirectory()+"/private\n")) {
		initial := member
		initial.Shares = nil
		if err := Prepare(ctx, initial, sambaConfig); err != nil {
			return err
		}
		_, err := run(ctx, "/usr/bin/systemctl", "restart", "winbind.service")
		return err
	}
	_, err := run(ctx, "/usr/bin/systemctl", "start", "winbind.service")
	return err
}

func Stop(ctx context.Context) error {
	_, err := run(ctx, "/usr/bin/systemctl", "stop", "smbd.service")
	return err
}

func EnsureActive(ctx context.Context, member Member) error {
	if member.StateVolumeID != "" {
		present, err := serviceAddressPresent(member)
		if err != nil {
			return err
		}
		if !present {
			return errors.New("the active member is missing its private SMB address")
		}
	}
	if len(member.Shares) == 0 {
		return nil
	}
	if _, err := run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "smbd.service"); err != nil {
		if _, err := run(ctx, "/usr/bin/systemctl", "start", "smbd.service"); err != nil {
			return err
		}
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	socket, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(member.Address.String(), "445"))
	if err != nil {
		return fmt.Errorf("probe the SMB member listener: %w", err)
	}
	return socket.Close()
}
