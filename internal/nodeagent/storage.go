package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/storage"
)

// RunStorage uses the enrolled worker identity to perform assigned RBD
// operations. A successful acknowledgement follows the actual data operation.
func RunStorage(ctx context.Context, settingsPath, agentPath string, logger *slog.Logger) error {
	cfg, err := config.Load(settingsPath, storage.Config{})
	if err != nil {
		return err
	}
	backend, err := storage.Open(cfg)
	if err != nil {
		return err
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	if cfg.MountRoot != workloadMountRoot {
		return errors.New("storage must use the packaged workload mount path")
	}
	go client.reconcileVolumeMounts(ctx, backend, logger)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		err := client.reconcileShareJobs(ctx, backend)
		if err != nil && ctx.Err() == nil {
			logger.Warn("storage job reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return nil
}

func (j *joinClient) reconcileShareJobs(ctx context.Context, backend storage.Backend) error {
	jobs, err := j.shareJobs(ctx)
	if err != nil {
		return err
	}
	defer func() {
		for _, job := range jobs {
			clear(job.VolumeKey)
		}
	}()
	var failures []error
	for _, job := range jobs {
		run, cancel := context.WithTimeout(ctx, 55*time.Second)
		if job.Delete {
			err = backend.Remove(run, job.Volume.ID)
		} else {
			err = backend.Initialize(run, job.Volume, job.VolumeKey)
		}
		cancel()
		if err == nil {
			err = j.completeShareJob(ctx, job.ID)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (j *joinClient) shareJobs(ctx context.Context) ([]storage.Job, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url()+"/share-jobs", nil)
	if err != nil {
		return nil, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("share job request returned HTTP %d", response.StatusCode)
	}
	var page struct {
		Jobs []storage.Job `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(&page); err != nil || len(page.Jobs) > 8 {
		return nil, errors.New("invalid share job page")
	}
	for _, job := range page.Jobs {
		if !storage.ValidID(job.ID) || !storage.ValidID(job.Volume.ID) || job.Delete && len(job.VolumeKey) != 0 ||
			!job.Delete && len(job.VolumeKey) != storage.KeySize {
			return nil, errors.New("invalid share job")
		}
	}
	return page.Jobs, nil
}

func (j *joinClient) completeShareJob(ctx context.Context, id string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/share-jobs/"+id+"/complete", nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("share job completion returned HTTP %d", response.StatusCode)
	}
	return nil
}
