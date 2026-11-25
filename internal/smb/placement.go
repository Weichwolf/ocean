package smb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

const memberPlacementFile = "/run/ocean-smb/placement.json"

type localPlacement struct {
	Member  Member   `json:"member"`
	Volumes []string `json:"volumes"`
}

func readPlacement() (localPlacement, error) {
	var placement localPlacement
	content, err := os.ReadFile(memberPlacementFile)
	if errors.Is(err, os.ErrNotExist) {
		return placement, nil
	}
	if err != nil {
		return placement, err
	}
	if json.Unmarshal(content, &placement) != nil || placement.Member.StateVolumeID == "" || placement.Member.Validate() != nil {
		return localPlacement{}, errors.New("invalid local SMB placement")
	}
	for _, id := range placement.Volumes {
		if !storage.ValidID(id) || id == placement.Member.StateVolumeID {
			return localPlacement{}, errors.New("invalid local SMB volume")
		}
	}
	return placement, nil
}

func writePlacement(placement localPlacement) error {
	content, err := json.Marshal(placement)
	if err != nil {
		return err
	}
	directory := filepath.Dir(memberPlacementFile)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	staged, err := os.CreateTemp(directory, ".placement-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged.Name()) }()
	_, err = staged.Write(content)
	if err := errors.Join(err, staged.Close()); err != nil {
		return err
	}
	return os.Rename(staged.Name(), memberPlacementFile)
}

func serviceAddressPresent(member Member) (bool, error) {
	link, err := net.InterfaceByName(member.ServiceInterface)
	if err != nil {
		return false, err
	}
	addrs, err := link.Addrs()
	if err != nil {
		return false, err
	}
	prefix := netip.PrefixFrom(member.Address, 32).String()
	return slices.ContainsFunc(addrs, func(addr net.Addr) bool { return addr.String() == prefix }), nil
}

func announceServiceAddress(ctx context.Context, member Member) error {
	present, err := serviceAddressPresent(member)
	if err != nil || present {
		return err
	}
	prefix := netip.PrefixFrom(member.Address, 32).String()
	if _, err := run(ctx, "/usr/sbin/ip", "-4", "address", "add", prefix, "dev", member.ServiceInterface); err != nil {
		return err
	}
	_, err = run(ctx, "/usr/bin/arping", "-U", "-c", "2", "-w", "2", "-I", member.ServiceInterface, member.Address.String())
	if err == nil {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, removeErr := run(cleanup, "/usr/sbin/ip", "-4", "address", "delete", prefix, "dev", member.ServiceInterface)
	return errors.Join(err, removeErr)
}

func preparePlacement(ctx context.Context, backend storage.Backend, plan Plan) error {
	prior, err := readPlacement()
	if err != nil {
		return err
	}
	member := plan.Member
	member.Shares = nil
	if prior.Member.StateVolumeID != "" && (prior.Member.StateVolumeID != member.StateVolumeID ||
		prior.Member.Address != member.Address || prior.Member.ServiceInterface != member.ServiceInterface) {
		return errors.New("the prior SMB placement must be withdrawn first")
	}
	placement := localPlacement{Member: member, Volumes: prior.Volumes}
	for _, grant := range plan.Volumes {
		if !slices.Contains(placement.Volumes, grant.Volume.ID) {
			placement.Volumes = append(placement.Volumes, grant.Volume.ID)
		}
	}
	if err := writePlacement(placement); err != nil {
		return err
	}
	if err := backend.OpenSMBMemberState(ctx, member.StateVolumeID, plan.StateKey); err != nil {
		return fmt.Errorf("mount trusted Samba membership state: %w", err)
	}
	return announceServiceAddress(ctx, member)
}

// Withdraw stops service and releases the network and locally held volumes.
// A retained placement record makes interrupted cleanup safe to retry.
func Withdraw(ctx context.Context, backend storage.Backend) error {
	if err := Stop(ctx); err != nil {
		return err
	}
	placement, err := readPlacement()
	if err != nil || placement.Member.StateVolumeID == "" {
		return err
	}
	member := placement.Member
	if _, err := run(ctx, "/usr/bin/systemctl", "stop", "winbind.service"); err != nil {
		return err
	}
	present, err := serviceAddressPresent(member)
	if err != nil {
		return err
	}
	if present {
		prefix := netip.PrefixFrom(member.Address, 32).String()
		if _, err := run(ctx, "/usr/sbin/ip", "-4", "address", "delete", prefix, "dev", member.ServiceInterface); err != nil {
			return err
		}
	}
	for _, id := range append(placement.Volumes, member.StateVolumeID) {
		if err := backend.Unmount(ctx, id); err != nil {
			return err
		}
	}
	return os.Remove(memberPlacementFile)
}
