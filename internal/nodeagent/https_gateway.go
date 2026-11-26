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
	"net/netip"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
)

var gatewaySlotName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type httpsRegistry struct {
	Slots map[string]network.HTTPSGatewaySlot `json:"slots"`
}

type httpsRuntimeState struct {
	generation string
	publicIPv4 netip.Addr
}

// RunHTTPSGateways reconciles enrolled gateway assignments in operator-owned
// namespaces. Each active assignment renews its local kernel lease.
func RunHTTPSGateways(ctx context.Context, agentPath, registryPath string, logger *slog.Logger) error {
	registry, err := readHTTPSRegistry(registryPath)
	if err != nil {
		return err
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	active := make(map[string]httpsRuntimeState)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := reconcileHTTPSGateways(round, registry, client, active); err != nil && ctx.Err() == nil {
			logger.Warn("HTTPS gateway reconciliation will retry", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var errorsFound []error
	for name, slot := range registry.Slots {
		errorsFound = append(errorsFound, stopHTTPSGateway(shutdown, name, slot, active[name].publicIPv4))
	}
	return errors.Join(errorsFound...)
}

func readHTTPSRegistry(path string) (httpsRegistry, error) {
	slots, err := readGatewaySlots[network.HTTPSGatewaySlot](path)
	registry := httpsRegistry{Slots: slots}
	if err != nil {
		return registry, err
	}
	namespaces := make(map[string]bool)
	for name, slot := range registry.Slots {
		if namespaces[slot.Namespace] {
			return registry, errors.New("HTTPS slots need unique routing namespaces")
		}
		if err := slot.Validate(); err != nil {
			return registry, fmt.Errorf("slot %s: %w", name, err)
		}
		namespaces[slot.Namespace] = true
	}
	return registry, nil
}

func readGatewaySlots[T any](path string) (map[string]T, error) {
	const maxBytes = 64 << 10
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > maxBytes {
		return nil, errors.New("gateway slots require a small, root-owned configuration file")
	}
	content := &io.LimitedReader{R: file, N: maxBytes + 1}
	decoder := json.NewDecoder(content)
	decoder.DisallowUnknownFields()
	var registry struct {
		Slots map[string]T `json:"slots"`
	}
	if err := decoder.Decode(&registry); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF || content.N == 0 || len(registry.Slots) == 0 || len(registry.Slots) > 64 {
		return nil, errors.New("gateway configuration requires one to 64 slots")
	}
	for name := range registry.Slots {
		if !gatewaySlotName.MatchString(name) {
			return nil, errors.New("invalid gateway slot name")
		}
	}
	return registry.Slots, nil
}

func reconcileHTTPSGateways(ctx context.Context, registry httpsRegistry, client *joinClient, active map[string]httpsRuntimeState) error {
	assignments, err := client.httpsAssignments(ctx)
	if err != nil {
		return err // The kernel closes access if this host loses its control-plane lease.
	}
	var failures []error
	for name, current := range active {
		if _, exists := assignments[name]; !exists {
			if err := stopHTTPSGateway(ctx, name, registry.Slots[name], current.publicIPv4); err != nil {
				failures = append(failures, err)
				continue
			}
			delete(active, name)
		}
	}
	for name, assignment := range assignments {
		slot, configured := registry.Slots[name]
		if !configured {
			failures = append(failures, fmt.Errorf("slot %s has no local operator binding", name))
			continue
		}
		status := enrollment.GatewayStatus{Generation: assignment.Generation}
		if assignment.Delete {
			if err := stopHTTPSGateway(ctx, name, slot, assignment.PublicIPv4); err != nil {
				failures = append(failures, err)
				continue
			}
			delete(active, name)
			status.Removed = true
		} else {
			current := active[name]
			if current.generation != assignment.Generation {
				if err := startHTTPSGateway(ctx, name, slot, assignment, current.publicIPv4); err != nil {
					failures = append(failures, err)
					continue
				}
				active[name] = httpsRuntimeState{generation: assignment.Generation, publicIPv4: assignment.PublicIPv4}
			} else if err := slot.RefreshLease(ctx, assignment.PublicIPv4); err != nil {
				if err := slot.InstallLease(ctx, assignment.PublicIPv4); err != nil {
					failures = append(failures, err)
					continue
				}
			}
			status.Ready, status.OwnsAddress, err = httpsGatewayReady(ctx, name, slot, assignment)
			if err != nil {
				failures = append(failures, err)
				continue
			}
		}
		if err := client.reportGatewayStatus(ctx, "https", name, status); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (client *joinClient) httpsAssignments(ctx context.Context) (map[string]enrollment.HTTPSAssignment, error) {
	page, err := fetchGatewayAssignments[enrollment.HTTPSAssignment](ctx, client, "https")
	if err != nil {
		return nil, err
	}
	assignments := make(map[string]enrollment.HTTPSAssignment, len(page))
	for _, assignment := range page {
		if !gatewaySlotName.MatchString(assignment.Slot) || !gatewaySlotName.MatchString(assignment.Generation) ||
			!assignment.PublicIPv4.Is4() || !assignment.PublicIPv4.IsGlobalUnicast() ||
			!assignment.Delete && len(assignment.CertificateBundle) == 0 {
			return nil, errors.New("invalid HTTPS gateway assignment")
		}
		if _, duplicate := assignments[assignment.Slot]; duplicate {
			return nil, errors.New("duplicate HTTPS gateway assignment")
		}
		assignments[assignment.Slot] = assignment
	}
	return assignments, nil
}

func fetchGatewayAssignments[T any](ctx context.Context, client *joinClient, kind string) ([]T, error) {
	path := client.url() + "/" + kind + "-assignments"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s assignment lookup returned HTTP %d", kind, response.StatusCode)
	}
	const limit = 6 << 20
	content := &io.LimitedReader{R: response.Body, N: limit + 1}
	decoder := json.NewDecoder(content)
	var page struct {
		Assignments []T `json:"assignments"`
	}
	if err := decoder.Decode(&page); err != nil || decoder.Decode(new(any)) != io.EOF || content.N == 0 || len(page.Assignments) > 64 {
		return nil, errors.New("invalid gateway assignment response")
	}
	return page.Assignments, nil
}

func (client *joinClient) reportGatewayStatus(ctx context.Context, kind, slot string, status any) error {
	payload, _ := json.Marshal(status)
	path := client.url() + "/" + kind + "-assignments/" + slot + "/status"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%s gateway status returned HTTP %d", kind, response.StatusCode)
	}
	return nil
}
