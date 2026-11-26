package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

const (
	workloadMountRoot  = "/run/ocean-storage/mounts"
	workloadMountState = "/run/ocean-storage/writers"
)

func mountMarker(id string) string { return filepath.Join(workloadMountState, id) }

func mountReady(id, generation string) bool {
	marker, err := os.ReadFile(mountMarker(id))
	return err == nil && string(marker) == generation
}

func writerMounted(id string) bool {
	_, err := os.Stat(mountMarker(id))
	return !errors.Is(err, os.ErrNotExist)
}

func (j *joinClient) reconcileVolumeMounts(ctx context.Context, backend storage.Backend, logger *slog.Logger) {
	account, err := user.Lookup("ocean-agent")
	if err != nil {
		logger.Error("storage requires the dedicated runtime account")
		return
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		logger.Error("storage requires a qualified runtime UID and GID")
		return
	}
	asWorker := func(ctx context.Context, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", append([]string{"-u", account.Username, "--", "/usr/bin/env",
			"XDG_RUNTIME_DIR=/run/user/" + account.Uid, "/usr/bin/podman"}, args...)...)
		cmd.Dir = account.HomeDir
		return cmd
	}
	if err := os.MkdirAll(workloadMountState, 0755); err != nil {
		logger.Error("could not create the local mount authorization directory", "error", err)
		return
	}
	interval := time.NewTicker(time.Second)
	defer interval.Stop()
	for ctx.Err() == nil {
		mounts, err := j.volumeMountAssignments(ctx)
		if err == nil {
			err = j.syncVolumeMounts(ctx, backend, mounts, uid, gid, asWorker)
		}
		if err != nil && ctx.Err() == nil {
			logger.Warn("volume mount reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-interval.C:
		}
	}
}

func (j *joinClient) syncVolumeMounts(ctx context.Context, backend storage.Backend, tasks []storage.MountTask, uid, gid int,
	podman func(context.Context, ...string) *exec.Cmd) error {
	var failures []error
	for _, task := range tasks {
		run, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := j.applyVolumeMount(run, backend, task, uid, gid, podman)
		cancel()
		clear(task.VolumeKey)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (j *joinClient) applyVolumeMount(ctx context.Context, backend storage.Backend, task storage.MountTask, uid, gid int,
	podman func(context.Context, ...string) *exec.Cmd) error {
	path := mountMarker(task.VolumeID)
	if task.Remove {
		name := containerName(workload.AssignmentID{ID: task.PlacementID, TenantID: task.TenantID,
			SubscriptionID: task.SubscriptionID, Generation: task.Generation})
		status, exists, err := inspectContainer(ctx, name, podman)
		if err != nil || exists && status.Running {
			return err
		}
		if err := backend.Unmount(ctx, task.VolumeID); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if task.Suspend {
			return nil
		}
		return j.sendUnmountReceipt(ctx, task)
	}
	if mountReady(task.VolumeID, task.Generation) {
		return nil
	}
	if writerMounted(task.VolumeID) {
		return errors.New("the prior local storage generation must be withdrawn first")
	}
	if _, err := backend.Mount(ctx, task.VolumeID, task.VolumeKey, uid, gid); err != nil {
		return err
	}
	if err := publishFile(path, []byte(task.Generation)); err != nil {
		return err
	}
	return os.Chmod(path, 0644)
}

func (j *joinClient) volumeMountAssignments(ctx context.Context) ([]storage.MountTask, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url()+"/volume-mounts", nil)
	if err != nil {
		return nil, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("volume mount request returned HTTP %d", response.StatusCode)
	}
	var page struct {
		Mounts []storage.MountTask `json:"mounts"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 512<<10)).Decode(&page); err != nil {
		return nil, errors.New("invalid volume mount assignment page")
	}
	for _, task := range page.Mounts {
		if !storage.ValidID(task.VolumeID) || !storage.ValidID(task.PlacementID) || !storage.ValidID(task.Generation) ||
			!storage.ValidID(task.TenantID) || !storage.ValidID(task.SubscriptionID) || !storage.ValidID(task.Revision) || task.Remove && len(task.VolumeKey) != 0 ||
			!task.Remove && (task.Suspend || len(task.VolumeKey) != storage.KeySize) {
			return nil, errors.New("invalid encrypted volume mount assignment")
		}
	}
	return page.Mounts, nil
}

func (j *joinClient) sendUnmountReceipt(ctx context.Context, task storage.MountTask) error {
	receipt := storage.UnmountReceipt{VolumeID: task.VolumeID, TenantID: task.TenantID, SubscriptionID: task.SubscriptionID,
		PlacementID: task.PlacementID, Generation: task.Generation, Revision: task.Revision}
	body, _ := json.Marshal(receipt)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/volume-unmounts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusConflict {
		return fmt.Errorf("volume unmount receipt returned HTTP %d", response.StatusCode)
	}
	return nil
}
