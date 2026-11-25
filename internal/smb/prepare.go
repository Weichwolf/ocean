package smb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Prepare publishes a Samba configuration after checking the member trust,
// encrypted filesystems and local POSIX grants for every published share.
// With no shares it prepares the private member configuration for enrollment.
func Prepare(ctx context.Context, member Member, destination string) error {
	if err := member.Validate(); err != nil {
		return err
	}
	for _, directory := range []string{stateRoot + "/private", stateRoot + "/state", "/var/cache/ocean-smb"} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".ocean-smb-*.conf")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, err = file.Write(configuration(member))
	if err = errors.Join(err, file.Sync(), file.Close()); err != nil {
		return err
	}
	if _, err := run(ctx, "/usr/bin/testparm", "-s", file.Name()); err != nil {
		return fmt.Errorf("validate the generated Samba configuration: %w", err)
	}
	if len(member.Shares) != 0 {
		if err := verifyDomain(ctx, member, file.Name()); err != nil {
			return err
		}
		root, err := os.OpenRoot(MountRoot)
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		acls := make([][]string, len(member.Shares))
		for i, share := range member.Shares {
			acl, err := validateShare(ctx, root, member.DomainSID, share)
			if err != nil {
				return fmt.Errorf("validate share %s: %w", share.Name, err)
			}
			acls[i] = acl
		}
		for i, share := range member.Shares {
			if err := applySharePolicy(ctx, root, share, acls[i]); err != nil {
				return fmt.Errorf("apply policy on share %s: %w", share.Name, err)
			}
		}
	}
	return os.Rename(file.Name(), destination)
}

func verifyDomain(ctx context.Context, member Member, config string) error {
	if _, err := run(ctx, "/usr/bin/net", "-s", config, "ads", "testjoin"); err != nil {
		return fmt.Errorf("verify the Samba member trust: %w", err)
	}
	output, err := run(ctx, "/usr/bin/net", "-s", config, "getdomainsid")
	if err != nil {
		return fmt.Errorf("read the member domain SID: %w", err)
	}
	expected := "SID for domain " + member.NetBIOSDomain + " is: " + member.DomainSID
	if !slices.Contains(strings.Split(output, "\n"), expected) {
		return errors.New("the Samba member trust does not belong to the configured tenant domain")
	}
	return nil
}

func validateShare(ctx context.Context, root *os.Root, domain string, share Share) ([]string, error) {
	volume, err := root.Lstat(share.VolumeID)
	if err != nil || !rootOwnedDirectory(volume) || volume.Mode().Perm()&0022 != 0 {
		return nil, errors.New("the assigned mount directory must be owned and writable by root only")
	}
	if err := verifyMount(ctx, filepath.Join(MountRoot, share.VolumeID), share.QuotaMiB > 0); err != nil {
		return nil, err
	}
	rules := []string{"u::rwx", "g::---", "o::---", "d:u::rwx", "d:g::---", "d:o::---"}
	for _, grants := range []struct {
		sids        []string
		permissions string
	}{{share.ReaderSIDs, "r-x"}, {share.WriterSIDs, "rwx"}} {
		for _, sid := range grants.sids {
			id, err := verifyGroup(ctx, domain, sid)
			if err != nil {
				return nil, err
			}
			entry := "g:" + strconv.Itoa(id) + ":" + grants.permissions
			rules = append(rules, entry, "d:"+entry)
		}
	}
	return rules, nil
}

func applySharePolicy(ctx context.Context, root *os.Root, share Share, rules []string) error {
	directory := filepath.Join(share.VolumeID, "data")
	if err := root.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat(directory)
	if err != nil || !rootOwnedDirectory(info) {
		return errors.New("the assigned share data path must be a root-owned directory")
	}
	if share.QuotaMiB > 0 {
		if err := applyProjectQuota(ctx, root, directory, share.QuotaMiB); err != nil {
			return err
		}
	}
	_, err = run(ctx, "/usr/bin/setfacl", "--physical", "--set", strings.Join(rules, ","), filepath.Join(MountRoot, directory))
	return err
}

func rootOwnedDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.IsDir()
}

func verifyMount(ctx context.Context, path string, needsQuota bool) error {
	output, err := run(ctx, "/usr/bin/findmnt", "-nro", "SOURCE,FSTYPE,VFS-OPTIONS,FS-OPTIONS", "--mountpoint", path)
	fields := strings.Fields(output)
	if err != nil || len(fields) != 4 || fields[1] != "ext4" || !strings.HasPrefix(fields[0], "/dev/") {
		return errors.New("a dedicated ext4 volume must be mounted at the assigned path")
	}
	options := strings.Split(fields[2], ",")
	for _, required := range []string{"rw", "nodev", "nosuid", "noexec"} {
		if !slices.Contains(options, required) {
			return errors.New("the assigned volume is missing its required mount options")
		}
	}
	if needsQuota && !slices.Contains(strings.Split(fields[3], ","), "prjquota") {
		return errors.New("the assigned volume must have ext4 project quotas enabled")
	}
	details, err := run(ctx, "/usr/sbin/cryptsetup", "status", fields[0])
	if err != nil || !slices.ContainsFunc(strings.Split(details, "\n"), func(line string) bool {
		return slices.Equal(strings.Fields(line), []string{"type:", "LUKS2"})
	}) {
		return errors.New("the assigned filesystem must use an active LUKS2 device")
	}
	return nil
}

func verifyGroup(ctx context.Context, domain, sid string) (int, error) {
	id, valid := groupID(domain, sid)
	info, err := run(ctx, "/usr/bin/wbinfo", "--sid-to-name", sid)
	// AD names can contain spaces. Winbind appends a numeric SID type.
	fields := strings.Fields(info)
	if !valid || err != nil || len(fields) < 2 || !slices.Contains([]string{"2", "4"}, fields[len(fields)-1]) {
		return 0, errors.New("the configured SID is not a tenant domain group")
	}
	mapped, err := run(ctx, "/usr/bin/wbinfo", "--sid-to-gid", sid)
	if err != nil || mapped != strconv.Itoa(id) {
		return 0, errors.New("the Samba group does not match the configured RID mapping")
	}
	return id, nil
}

func run(ctx context.Context, executable string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", filepath.Base(executable), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}
