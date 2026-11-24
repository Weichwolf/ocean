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
	var registry httpsRegistry
	const maxBytes = 64 << 10
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return registry, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return registry, err
	}
	if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > maxBytes {
		return registry, errors.New("HTTPS slots require a small, root-owned configuration file")
	}
	content := &io.LimitedReader{R: file, N: maxBytes + 1}
	decoder := json.NewDecoder(content)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, err
	}
	if decoder.Decode(new(any)) != io.EOF || content.N == 0 || len(registry.Slots) == 0 || len(registry.Slots) > 64 {
		return registry, errors.New("HTTPS configuration requires one to 64 gateway slots")
	}
	namespaces := make(map[string]bool)
	for name, slot := range registry.Slots {
		if !gatewaySlotName.MatchString(name) || namespaces[slot.Namespace] {
			return registry, errors.New("HTTPS slots need unique, valid names and routing namespaces")
		}
		if err := slot.Validate(); err != nil {
			return registry, fmt.Errorf("slot %s: %w", name, err)
		}
		namespaces[slot.Namespace] = true
	}
	return registry, nil
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
		status := enrollment.HTTPSGatewayStatus{Generation: assignment.Generation}
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
		if err := client.reportHTTPSGatewayStatus(ctx, name, status); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (client *joinClient) httpsAssignments(ctx context.Context) (map[string]enrollment.HTTPSAssignment, error) {
	path := client.url() + "/https-assignments"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS assignment lookup returned HTTP %d", response.StatusCode)
	}
	const limit = 6 << 20
	content := &io.LimitedReader{R: response.Body, N: limit + 1}
	decoder := json.NewDecoder(content)
	var page struct {
		Assignments []enrollment.HTTPSAssignment `json:"assignments"`
	}
	if err := decoder.Decode(&page); err != nil || decoder.Decode(new(any)) != io.EOF || content.N == 0 || len(page.Assignments) > 64 {
		return nil, errors.New("invalid HTTPS assignment response")
	}
	assignments := make(map[string]enrollment.HTTPSAssignment, len(page.Assignments))
	for _, assignment := range page.Assignments {
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

func (client *joinClient) reportHTTPSGatewayStatus(ctx context.Context, slot string, status enrollment.HTTPSGatewayStatus) error {
	payload, _ := json.Marshal(status)
	path := client.url() + "/https-assignments/" + slot + "/status"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("HTTPS gateway status returned HTTP %d", response.StatusCode)
	}
	return nil
}
