package smb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

const sambaConfig = "/etc/samba/smb.conf"

type Authorization struct {
	member     Member
	writer     DirectoryWriter
	generation string
	checked    time.Time
}

// ApplyPlan reconciles the dedicated member and reports after Samba has
// published the requested configuration and retired all withdrawn mounts.
func (a *Authorization) ApplyPlan(ctx context.Context, backend storage.Backend, plan Plan) error {
	if !plan.Valid() {
		return ErrInvalidPlan
	}
	if plan.Suspension != nil {
		*a = Authorization{}
		return applySuspension(ctx, backend, *plan.Suspension)
	}
	if a.generation == plan.Generation && a.writer == plan.Directory && reflect.DeepEqual(a.member, plan.Member) {
		return a.Refresh(ctx)
	}
	// Withdraw the previous configuration before applying a new policy or
	// waiting for a storage operation. No old handles survive this change.
	if err := Stop(ctx); err != nil {
		return err
	}
	*a = Authorization{}
	if err := preparePlacement(ctx, backend, plan); err != nil {
		return err
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
	member := plan.Member
	if len(member.Shares) != 0 {
		policy, cancel := context.WithTimeout(ctx, 4*time.Second)
		member.access, err = readDirectoryAccess(policy, member, plan.Directory)
		cancel()
		if err != nil {
			return err
		}
	}
	if err := Prepare(ctx, member, sambaConfig); err != nil {
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
	a.member, a.writer, a.generation, a.checked = plan.Member, plan.Directory, plan.Generation, time.Now()
	return EnsureActive(ctx, member)
}

func applySuspension(ctx context.Context, backend storage.Backend, plan SuspensionPlan) error {
	if err := Withdraw(ctx, backend); err != nil {
		return err
	}
	if _, err := run(ctx, "/usr/bin/systemctl", "stop", "winbind.service"); err != nil {
		return err
	}
	for _, id := range plan.Volumes {
		if err := backend.Unmount(ctx, id); err != nil {
			return fmt.Errorf("release suspended SMB volume %s: %w", id, err)
		}
	}
	if plan.PurgeVolume != "" {
		return backend.Remove(ctx, plan.PurgeVolume)
	}
	return nil
}

// Refresh reevaluates membership with the directory writer even if the
// regional API is unreachable. The Samba configuration names the currently
// authorized users so that reconnecting with an old PAC cannot re-grant access.
func (a *Authorization) Refresh(ctx context.Context) error {
	if len(a.member.Shares) == 0 {
		return nil
	}
	if time.Since(a.checked) < 3*time.Second {
		return EnsureActive(ctx, a.member)
	}
	member := a.member
	policy, cancel := context.WithTimeout(ctx, 4*time.Second)
	access, err := readDirectoryAccess(policy, member, a.writer)
	cancel()
	if err != nil {
		a.checked = time.Time{}
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		return errors.Join(err, Stop(stop))
	}
	member.access = access
	existing, err := os.ReadFile(sambaConfig)
	if err != nil || !bytes.Equal(existing, configuration(member)) {
		a.checked = time.Time{}
		if err := Stop(ctx); err != nil {
			return err
		}
		staged, err := stageConfiguration(ctx, member, sambaConfig)
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(staged) }()
		if err := os.Rename(staged, sambaConfig); err != nil {
			return err
		}
	}
	a.checked = time.Now()
	return EnsureActive(ctx, member)
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
