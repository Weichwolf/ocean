package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
)

type ipsecSlot struct {
	Namespace  string     `json:"namespace"`
	Tunnel     string     `json:"tunnel"`
	Underlay   string     `json:"underlay"`
	Inside     string     `json:"inside"`
	Socket     string     `json:"socket"`
	PublicIPv4 netip.Addr `json:"publicIPv4"`
}

func (s ipsecSlot) gateway(assignment enrollment.IPsecAssignment) network.IPsecGateway {
	gateway := network.IPsecGateway{Tunnel: s.Tunnel, Underlay: s.Underlay, Inside: s.Inside, Socket: s.Socket,
		LocalEndpoint: s.PublicIPv4, LocalPrefixes: []netip.Prefix{assignment.InsideIPv4.Masked()},
		ProtectedPrefixes: assignment.ProtectedPrefixes}
	if assignment.Peer != nil {
		gateway.RemoteEndpoint, gateway.RemotePrefixes = assignment.Peer.Endpoint, assignment.Peer.Prefixes
	}
	return gateway
}

type ipsecRuntime struct {
	generation string
	removed    bool
}

// RunIPsecGateways reconciles dedicated namespaces through the enrolled host channel.
func RunIPsecGateways(ctx context.Context, agentPath, registryPath string, logger *slog.Logger) error {
	slots, err := readGatewaySlots[ipsecSlot](registryPath)
	if err != nil {
		return err
	}
	namespaces, sockets := make(map[string]bool, len(slots)), make(map[string]bool, len(slots))
	addresses := make(map[netip.Addr]bool, len(slots))
	for name, slot := range slots {
		if err := slot.gateway(enrollment.IPsecAssignment{}).ValidateRuntime(slot.Namespace); err != nil ||
			!slot.PublicIPv4.Is4() || !slot.PublicIPv4.IsGlobalUnicast() || namespaces[slot.Namespace] || sockets[slot.Socket] || addresses[slot.PublicIPv4] {
			return fmt.Errorf("invalid or duplicate IPsec namespace or daemon for slot %s", name)
		}
		namespaces[slot.Namespace], sockets[slot.Socket] = true, true
		addresses[slot.PublicIPv4] = true
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	active := make(map[string]ipsecRuntime, len(slots))
	for name, slot := range slots {
		initial, stop := context.WithTimeout(ctx, 5*time.Second)
		err := slot.stop(initial)
		stop()
		if err != nil {
			return fmt.Errorf("initialize IPsec slot %s: %w", name, err)
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := reconcileIPsecGateways(round, slots, client, active); err != nil && ctx.Err() == nil {
			logger.Warn("IPsec reconciliation will retry", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	var failures []error
	for _, slot := range slots {
		failures = append(failures, slot.stop(shutdown))
	}
	return errors.Join(failures...)
}

func reconcileIPsecGateways(ctx context.Context, slots map[string]ipsecSlot, client *joinClient, active map[string]ipsecRuntime) error {
	page, err := fetchGatewayAssignments[enrollment.IPsecAssignment](ctx, client, "ipsec")
	if err != nil {
		return err // Kernel forwarding expires while the control plane is unreachable.
	}
	defer func() {
		for _, item := range page {
			clear(item.SharedKey)
		}
	}()
	assignments := make(map[string]enrollment.IPsecAssignment, len(page))
	for _, assignment := range page {
		if _, duplicate := assignments[assignment.Slot]; duplicate || !gatewaySlotName.MatchString(assignment.Slot) ||
			!gatewaySlotName.MatchString(assignment.Generation) || assignment.Remove && assignment.Peer != nil ||
			assignment.ReleaseAddress && !assignment.Remove ||
			(assignment.Peer == nil) != (len(assignment.SharedKey) == 0) {
			return errors.New("invalid or duplicate IPsec gateway assignment")
		}
		assignments[assignment.Slot] = assignment
	}
	var failures []error
	for name := range active {
		if _, assigned := assignments[name]; assigned {
			continue
		}
		slot := slots[name]
		if err := slot.stop(ctx); err != nil {
			failures = append(failures, err)
			continue
		}
		delete(active, name)
	}
	for name, assignment := range assignments {
		slot, configured := slots[name]
		if !configured {
			failures = append(failures, fmt.Errorf("IPsec slot %s has no local operator binding", name))
			continue
		}
		current := active[name]
		status, err := slot.reconcile(ctx, assignment, current)
		if err != nil {
			active[name] = ipsecRuntime{}
			failures = append(failures, fmt.Errorf("reconcile IPsec slot %s: %w", name, err))
			status = enrollment.IPsecStatus{Generation: assignment.Generation}
		} else {
			active[name] = ipsecRuntime{assignment.Generation, status.Removed}
		}
		if err := client.reportGatewayStatus(ctx, "ipsec", name, status); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (slot ipsecSlot) reconcile(ctx context.Context, assignment enrollment.IPsecAssignment, current ipsecRuntime) (enrollment.IPsecStatus, error) {
	status := enrollment.IPsecStatus{Generation: assignment.Generation}
	if assignment.PublicIPv4 != slot.PublicIPv4 {
		return status, errors.Join(errors.New("the regional endpoint differs from the local IPsec slot"), slot.stop(ctx))
	}
	gateway := slot.gateway(assignment)
	changed := current.generation != assignment.Generation || current.removed != assignment.Remove
	if assignment.Remove {
		if changed {
			if err := gateway.Remove(ctx, slot.Namespace); err != nil {
				return status, err
			}
			if assignment.ReleaseAddress {
				if err := gateway.SetPublicAddress(ctx, slot.Namespace, false); err != nil {
					return status, err
				}
			}
		}
		status.Removed = true
		return status, nil
	}
	if err := gateway.SetPublicAddress(ctx, slot.Namespace, true); err != nil {
		return status, err
	}
	if err := gateway.CheckAttachment(ctx, slot.Namespace, assignment.InsideIPv4); err != nil {
		return status, errors.Join(err, gateway.Remove(ctx, slot.Namespace))
	}
	if assignment.Peer == nil {
		if changed {
			if err := gateway.Remove(ctx, slot.Namespace); err != nil {
				return status, err
			}
		}
		status.Ready = true
		return status, nil
	}
	if changed {
		if err := gateway.Apply(ctx, slot.Namespace, assignment.SharedKey); err != nil {
			return status, err
		}
	} else if err := gateway.RefreshLease(ctx, slot.Namespace); err != nil {
		return status, err
	}
	active, err := gateway.Connected(ctx, slot.Namespace)
	if err != nil {
		return status, errors.Join(err, gateway.Remove(ctx, slot.Namespace))
	}
	status.Ready, status.Connected = true, active
	return status, nil
}

func (slot ipsecSlot) stop(ctx context.Context) error {
	gateway := slot.gateway(enrollment.IPsecAssignment{})
	return errors.Join(gateway.Remove(ctx, slot.Namespace), gateway.SetPublicAddress(ctx, slot.Namespace, false))
}
