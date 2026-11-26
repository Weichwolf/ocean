package desktopgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
)

type regionClient struct {
	origin string
	http   *http.Client
}

var errDesktopAccess = errors.New("the current identity cannot open this desktop")

func (c regionClient) request(ctx context.Context, id, action, token string) (arm.DesktopLaunch, error) {
	const limit = 8192
	var empty arm.DesktopLaunch
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+id+"/"+action+"?api-version="+arm.DesktopAPIVersion, nil)
	if err != nil {
		return empty, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return empty, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return empty, errDesktopAccess
	case http.StatusOK:
	default:
		return empty, fmt.Errorf("regional desktop API returned status %d", resp.StatusCode)
	}
	if resp.ContentLength > limit || resp.Header.Get("Cache-Control") != "no-store" {
		return empty, errors.New("invalid regional desktop response headers")
	}
	reader := &io.LimitedReader{R: resp.Body, N: limit + 1}
	result, err := config.Decode(reader, arm.DesktopLaunch{})
	if err != nil || reader.N == 0 {
		return empty, errors.New("invalid regional desktop response")
	}
	now := time.Now()
	if !enrollment.ValidDirectoryJoinID(result.AssignmentID) || !enrollment.ValidDirectoryJoinID(result.MachineID) ||
		!enrollment.ValidDirectoryJoinID(result.Generation) || result.User == "" || result.NetworkInterface == "" || result.SubnetID == "" ||
		!result.PrivateIP.Is4() || !result.PrivateIP.IsPrivate() || !now.Before(result.ExpiresAt) || result.ExpiresAt.Sub(now) > desktop.LaunchLifetime ||
		action == "launch" && !desktop.IsLaunchPassword([]byte(result.Credential)) || action == "renew" && result.Credential != "" {
		return empty, errors.New("invalid regional desktop authorization")
	}
	return result, nil
}
