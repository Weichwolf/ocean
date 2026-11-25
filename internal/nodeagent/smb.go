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
	if err := smb.Withdraw(ctx, backend); err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		if err := smb.Withdraw(shutdown, backend); err != nil {
			logger.Error("failed to stop the dedicated SMB member", "error", err)
		}
	}()
	var applied, reported smb.Receipt
	var authorization smb.Authorization
	interval := time.NewTicker(time.Second)
	defer interval.Stop()
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, 12*time.Second)
		err := authorization.Refresh(probe)
		cancel()
		err = errors.Join(err, client.syncSMB(ctx, backend, &authorization, &applied, &reported))
		if errors.Is(err, errSMBRevoked) {
			applied, reported = smb.Receipt{}, smb.Receipt{}
			authorization = smb.Authorization{}
			stop, cancel := context.WithTimeout(ctx, 12*time.Second)
			err = smb.Withdraw(stop, backend)
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

func (j *joinClient) syncSMB(ctx context.Context, backend storage.Backend, authorization *smb.Authorization, applied, reported *smb.Receipt) error {
	plan, err := j.smbPlan(ctx)
	if err != nil {
		return err
	}
	defer plan.ClearKeys()
	receipt := smb.Receipt{Revision: plan.Revision, Generation: plan.Generation, Directory: plan.Directory}
	if *applied != receipt {
		apply, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := authorization.ApplyPlan(apply, backend, plan)
		cancel()
		if err != nil {
			return err
		}
		*applied = receipt
	}
	if receipt.Valid() && *reported != receipt {
		if err := j.reportSMBPlan(ctx, receipt); err != nil {
			return err
		}
		*reported = receipt
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

func (j *joinClient) reportSMBPlan(ctx context.Context, receipt smb.Receipt) error {
	body, err := json.Marshal(receipt)
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
