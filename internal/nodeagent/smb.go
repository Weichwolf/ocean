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
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
)

var errSMBRevoked = errors.New("SMB member authorization was withdrawn")

// RunSMB applies revisions from the regional service on a dedicated member.
func RunSMB(ctx context.Context, storagePath, agentPath string, logger *slog.Logger) error {
	settings, err := config.Load(storagePath, storage.Config{})
	if err != nil {
		return err
	}
	if settings.MountRoot != smb.MountRoot {
		return errors.New("SMB requires the dedicated member mount directory")
	}
	backend, err := storage.Open(settings)
	if err != nil {
		return err
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	if err := smb.Stop(ctx); err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		if err := smb.Stop(shutdown); err != nil {
			logger.Error("failed to stop the dedicated SMB member", "error", err)
		}
	}()
	var applied int64 = -1
	var reported int64
	interval := time.NewTicker(time.Second)
	defer interval.Stop()
	for ctx.Err() == nil {
		err := client.syncSMB(ctx, backend, &applied, &reported)
		if errors.Is(err, errSMBRevoked) {
			applied, reported = -1, 0
			stop, cancel := context.WithTimeout(ctx, 12*time.Second)
			err = errors.Join(err, smb.Stop(stop))
			cancel()
		}
		if err != nil && ctx.Err() == nil {
			logger.Warn("SMB member reconciliation will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-interval.C:
		}
	}
	return nil
}

func (j *joinClient) syncSMB(ctx context.Context, backend storage.Backend, applied, reported *int64) error {
	plan, err := j.smbPlan(ctx)
	if err != nil {
		return err
	}
	defer plan.ClearKeys()
	if *applied != plan.Revision {
		apply, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := smb.ApplyPlan(apply, backend, plan)
		cancel()
		if err != nil {
			return err
		}
		*applied = plan.Revision
	} else {
		probe, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := smb.EnsureActive(probe, plan.Member)
		cancel()
		if err != nil {
			return err
		}
	}
	if plan.Revision > 0 && *reported != plan.Revision {
		if err := j.reportSMBPlan(ctx, plan.Revision); err != nil {
			return err
		}
		*reported = plan.Revision
	}
	return nil
}

func (j *joinClient) smbPlan(ctx context.Context) (smb.Plan, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url()+"/smb-plan", nil)
	if err != nil {
		return smb.Plan{}, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return smb.Plan{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return smb.Plan{}, errSMBRevoked
	}
	if response.StatusCode != http.StatusOK {
		return smb.Plan{}, fmt.Errorf("SMB member plan returned HTTP %d", response.StatusCode)
	}
	var plan smb.Plan
	decoder := json.NewDecoder(io.LimitReader(response.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || !plan.Valid() {
		plan.ClearKeys()
		return smb.Plan{}, smb.ErrInvalidPlan
	}
	return plan, nil
}

func (j *joinClient) reportSMBPlan(ctx context.Context, revision int64) error {
	body, err := json.Marshal(map[string]int64{"revision": revision})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/smb-plan", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return errSMBRevoked
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("SMB plan confirmation returned HTTP %d", response.StatusCode)
	}
	return nil
}
