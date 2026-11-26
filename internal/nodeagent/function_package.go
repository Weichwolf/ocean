package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

// functionPackageMount prepares approved content on the workload's encrypted
// volume and gives the runtime only a read-only view of the code tree.
func (j *joinClient) functionPackageMount(ctx context.Context, task workload.Task) (string, error) {
	if !storage.ValidID(task.VolumeID) || !task.Function.EmptySlot && (task.Function.Package == nil || !task.Function.Package.Valid()) {
		return "", errors.New("invalid Function package assignment")
	}
	parent := filepath.Join(workloadMountRoot, task.VolumeID, "packages")
	if err := os.Mkdir(parent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("the Function package directory is not private")
	}
	entry := "empty-slot"
	if !task.Function.EmptySlot {
		entry = task.Function.Package.SHA256
	}
	target := filepath.Join(parent, entry)
	info, err := os.Lstat(target)
	if err == nil && (!info.IsDir() || info.Mode().Perm() != 0700) {
		return "", errors.New("the installed Function package directory is not private")
	}
	if errors.Is(err, os.ErrNotExist) {
		if task.Function.EmptySlot {
			err = installEmptyFunctionSlot(parent, target)
		} else {
			err = j.installFunctionPackage(ctx, task.AssignmentID, *task.Function.Package, parent, target)
		}
	}
	if err != nil {
		return "", err
	}
	return "type=bind,source=" + target + ",target=/home/site/wwwroot,ro,nosuid,nodev", nil
}

func installEmptyFunctionSlot(parent, target string) error {
	stage, err := os.MkdirTemp(parent, "function-empty-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	if err := os.WriteFile(filepath.Join(stage, "host.json"), []byte(`{"version":"2.0"}`), 0644); err != nil {
		return err
	}
	return os.Rename(stage, target)
}

func (j *joinClient) installFunctionPackage(ctx context.Context, id workload.AssignmentID, ref functions.PackageReference, parent, target string) error {
	params := url.Values{"tenant": {id.TenantID}, "subscription": {id.SubscriptionID}, "generation": {id.Generation}, "revision": {id.Revision}}
	path := j.url() + "/container-tasks/" + id.ID + "/package?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Function package request returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength != int64(ref.Bytes) || response.Header.Get("Content-Type") != "application/zip" {
		return errors.New("invalid Function package headers")
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, int64(ref.Bytes)+1))
	defer clear(archive)
	if err != nil || len(archive) != ref.Bytes {
		return errors.New("invalid Function package response")
	}
	pkg, err := functions.ReadZIPPackage(archive)
	if err != nil || pkg.Digest() != ref.SHA256 {
		return errors.New("the delivered Function package did not match its verified digest")
	}
	staged, err := pkg.Unpack(parent)
	if err != nil {
		return err
	}
	if err := os.Rename(staged, target); err != nil {
		return errors.Join(err, os.RemoveAll(staged))
	}
	return nil
}
