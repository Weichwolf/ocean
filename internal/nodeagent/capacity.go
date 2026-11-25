package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

func (j *joinClient) ready(ctx context.Context) error {
	last := j.lastAdvertisement.Load()
	if last == nil || time.Since(*last) >= enrollment.HostAvailabilityTTL {
		return errors.New("host capacity is unavailable")
	}
	return j.confirm(ctx)
}

func (j *joinClient) heartbeat(ctx context.Context) error {
	report, err := probeHost(j.config.Interface)
	if err != nil {
		return err
	}
	if status, err := os.Stat(filepath.Join(workloadRuntimeDirectory, ".available")); err == nil {
		report.ContainerNetwork = time.Since(status.ModTime()) < policyLease
	}
	report.DirectoryRuntime = report.ContainerNetwork && j.directoryRuntimeAvailable(ctx)
	body, _ := json.Marshal(report)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnprocessableEntity {
			j.lastAdvertisement.Store(nil)
		}
		return fmt.Errorf("host capacity report returned HTTP %d", response.StatusCode)
	}
	now := time.Now()
	j.lastAdvertisement.Store(&now)
	return nil
}

func (j *joinClient) reportCapacity(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := j.heartbeat(ctx); err != nil && ctx.Err() == nil {
				logger.Warn("Host capacity report will retry", "error", err)
			}
		}
	}
}
