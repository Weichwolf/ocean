package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
)

var errNativeDenied = errors.New("native desktop access denied")

func requestNativeAdmission(ctx context.Context, client *http.Client, region, account string, lease bool) (*http.Response, error) {
	body, err := json.Marshal(desktop.NativeAdmissionRequest{User: account, Lease: lease})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, region+desktop.NativeAdmissionPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return client.Do(request)
}

func readNativeLease(ctx context.Context, client *http.Client, region, account, machine string) (desktop.NativeLease, error) {
	var empty desktop.NativeLease
	started := time.Now()
	response, err := requestNativeAdmission(ctx, client, region, account, true)
	if err != nil {
		return empty, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusForbidden {
		return empty, errNativeDenied
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.ContentLength > 1024 {
		return empty, errors.New("native desktop authorization is unavailable")
	}
	reader := &io.LimitedReader{R: response.Body, N: 1025}
	lease, err := config.Decode(reader, empty)
	now := time.Now()
	deadline := now.Add(lease.ExpiresAt.Sub(now))
	if bound := started.Add(desktop.NativeLeaseLifetime); bound.Before(deadline) {
		deadline = bound
	}
	if err != nil || reader.N == 0 || lease.MachineID != machine || !enrollment.ValidDirectoryJoinID(machine) ||
		!enrollment.ValidDirectoryJoinID(lease.AssignmentID) || !enrollment.ValidDirectoryJoinID(lease.UserID) ||
		!enrollment.ValidDirectoryJoinID(lease.Generation) || !now.Before(deadline) {
		return empty, errors.New("invalid native desktop authorization")
	}
	lease.ExpiresAt = deadline
	return lease, nil
}

func sameNativeAssignment(a, b desktop.NativeLease) bool {
	return a.AssignmentID == b.AssignmentID && a.MachineID == b.MachineID && a.UserID == b.UserID && a.Generation == b.Generation
}
