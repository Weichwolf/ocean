package rack

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

func managementClient(caFile string) (*http.Client, error) {
	ca, err := readBounded(caFile, 1<<20, false)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("CA file contains no certificate")
	}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			MaxResponseHeaderBytes: 32 << 10,
			MaxIdleConns:           8,
			IdleConnTimeout:        30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func readManagementJSON(client *http.Client, req *http.Request, service string, result any) error {
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", service, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return managementStatus{service: service, code: response.StatusCode}
	}
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", service, err)
	}
	if len(raw) > limit {
		return fmt.Errorf("%s response exceeds its size limit", service)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("invalid %s response", service)
	}
	return nil
}

type managementStatus struct {
	service string
	code    int
}

func (e managementStatus) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.service, e.code)
}
