package smb

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Each share has its own file system. A fixed project ID survives restore and
// charges every writer and subdirectory to one quota.
const shareProjectID = "1"

func applyProjectQuota(ctx context.Context, root *os.Root, directory string, quotaMiB int) error {
	path := filepath.Join(MountRoot, directory)
	output, err := run(ctx, "/usr/bin/lsattr", "-pd", path)
	fields := strings.Fields(output)
	if err != nil || len(fields) != 3 {
		return errors.New("cannot read the share's filesystem project")
	}
	needsProject := fields[0] != shareProjectID || !strings.Contains(fields[1], "P")
	if needsProject {
		folder, err := root.Open(directory)
		if err != nil {
			return err
		}
		_, readErr := folder.Readdirnames(1)
		closeErr := folder.Close()
		if readErr == nil {
			return errors.New("cannot enable a project quota on an existing untracked share")
		}
		if !errors.Is(readErr, io.EOF) || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
	}
	blocks := strconv.Itoa(quotaMiB * 1024)
	if _, err := run(ctx, "/usr/sbin/setquota", "-P", shareProjectID, blocks, blocks, "0", "0", filepath.Dir(path)); err != nil {
		return err
	}
	if needsProject {
		_, err = run(ctx, "/usr/bin/chattr", "-p", shareProjectID, "+P", path)
	}
	return err
}
