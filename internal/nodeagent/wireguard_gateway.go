package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
)

const (
	wireGuardService = "ocean-wireguard-agent.service"
	wireGuardRoot    = "/run/ocean-wireguard-agent"
)

type wireGuardSlot struct {
	Namespace      string                `json:"namespace"`
	Tunnel         string                `json:"tunnel"`
	Underlay       string                `json:"underlay"`
	Inside         string                `json:"inside"`
	ListenPort     uint16                `json:"listenPort"`
	PrivateKeyFile string                `json:"privateKeyFile"`
	Router         netip.Prefix          `json:"router"`
	Redundancy     network.WireGuardVRRP `json:"redundancy"`
	VRRPID         uint8                 `json:"vrrpId"`
	Priority       uint8                 `json:"priority"`
}

func (slot wireGuardSlot) valid() bool {
	return network.ValidRoutingLink(slot.Namespace) && network.ValidRoutingLink(slot.Tunnel) &&
		network.ValidRoutingLink(slot.Underlay) && network.ValidRoutingLink(slot.Inside) &&
		slot.Tunnel != slot.Underlay && slot.Tunnel != slot.Inside && slot.Inside != slot.Underlay &&
		slot.ListenPort != 0 && filepath.IsAbs(slot.PrivateKeyFile) && slot.Router.Addr().Is4() &&
		slot.Router.Addr().IsPrivate() && slot.Router.Bits() <= 29 && slot.VRRPID != 0 &&
		slot.Priority > 0 && slot.Priority < 255 && slot.Router.Contains(slot.Redundancy.Address) &&
		slot.Router.Contains(slot.Redundancy.Peer) && slot.Redundancy.Address != slot.Redundancy.Peer
}

func (slot wireGuardSlot) gateway(assignment enrollment.WireGuardAssignment) network.WireGuardGateway {
	return network.WireGuardGateway{
		Tunnel: slot.Tunnel, Underlay: slot.Underlay, Inside: slot.Inside, ListenPort: slot.ListenPort,
		PrivateKeyFile: slot.PrivateKeyFile, LocalTunnel: assignment.Peer.GatewayTunnel,
		PeerTunnel: assignment.Peer.CustomerTunnel, PeerEndpoint: assignment.Peer.Endpoint, PeerPublicKey: assignment.Peer.PublicKey,
		LocalPrefixes: assignment.LocalPrefixes, RemotePrefixes: assignment.CustomerPrefixes, ProtectedPrefixes: assignment.ProtectedPrefixes,
		Redundancy: &slot.Redundancy, LeaseControlled: true,
	}
}

// RunWireGuardGateways applies approved site connections over the enrolled host channel.
func RunWireGuardGateways(ctx context.Context, agentPath, registryPath string, logger *slog.Logger) error {
	slots, err := readGatewaySlots[wireGuardSlot](registryPath)
	if err != nil {
		return err
	}
	namespaces := make(map[string]bool)
	for name, slot := range slots {
		if !slot.valid() || namespaces[slot.Namespace] {
			return fmt.Errorf("invalid or duplicate WireGuard routing namespace for slot %s", name)
		}
		namespaces[slot.Namespace] = true
	}
	client, err := loadEnrolledClient(agentPath)
	if err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	active := make(map[string]string)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := reconcileWireGuard(round, slots, client, active); err != nil && ctx.Err() == nil {
			logger.Warn("WireGuard reconciliation will retry", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var failures []error
	for name, slot := range slots {
		failures = append(failures, stopWireGuard(shutdown, name, slot))
	}
	return errors.Join(failures...)
}

func reconcileWireGuard(ctx context.Context, slots map[string]wireGuardSlot, client *joinClient, active map[string]string) error {
	page, err := fetchGatewayAssignments[enrollment.WireGuardAssignment](ctx, client, "wireguard")
	if err != nil {
		return err
	}
	assignments := make(map[string]enrollment.WireGuardAssignment, len(page))
	for _, item := range page {
		if !gatewaySlotName.MatchString(item.Slot) || !gatewaySlotName.MatchString(item.Generation) {
			return errors.New("invalid WireGuard assignment")
		}
		if _, duplicate := assignments[item.Slot]; duplicate {
			return errors.New("duplicate WireGuard assignment")
		}
		assignments[item.Slot] = item
	}
	var failures []error
	for name := range active {
		if _, exists := assignments[name]; !exists {
			if err := stopWireGuard(ctx, name, slots[name]); err != nil {
				failures = append(failures, err)
				continue
			}
			delete(active, name)
		}
	}
	for name, assignment := range assignments {
		slot, configured := slots[name]
		if !configured {
			failures = append(failures, fmt.Errorf("WireGuard slot %s has no local operator binding", name))
			continue
		}
		status := enrollment.GatewayStatus{Generation: assignment.Generation}
		if assignment.Delete {
			if err := stopWireGuard(ctx, name, slot); err != nil {
				failures = append(failures, err)
				continue
			}
			delete(active, name)
			status.Removed = true
		} else {
			gateway := slot.gateway(assignment)
			if active[name] != assignment.Generation {
				if err := startWireGuard(ctx, name, slot, gateway); err != nil {
					failures = append(failures, err)
					continue
				}
				active[name] = assignment.Generation
			} else if err := gateway.RefreshLease(ctx, slot.Namespace); err != nil {
				if err := gateway.Apply(ctx, slot.Namespace); err != nil {
					failures = append(failures, err)
					continue
				}
			}
			ready, owns, err := wireGuardReady(ctx, name, slot, gateway)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			status.Ready, status.OwnsAddress = ready, owns
		}
		if err := client.reportGatewayStatus(ctx, "wireguard", name, status); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func wireGuardUnit(slot string) string { return "ocean-wireguard-" + slot + "-vrrp.service" }

func startWireGuard(ctx context.Context, name string, slot wireGuardSlot, gateway network.WireGuardGateway) error {
	if err := stopWireGuard(ctx, name, slot); err != nil {
		return err
	}
	keepalived, err := gateway.Keepalived(slot.Namespace, slot.Router, slot.VRRPID, slot.Priority)
	if err != nil {
		return err
	}
	folder := filepath.Join(wireGuardRoot, name)
	if err := os.Mkdir(folder, 0700); err != nil {
		return err
	}
	config := filepath.Join(folder, "keepalived.conf")
	if err := os.WriteFile(config, []byte(keepalived), 0600); err != nil {
		return err
	}
	if err := gateway.Apply(ctx, slot.Namespace); err != nil {
		return err
	}
	command := []string{"/usr/sbin/keepalived", "--vrrp", "--dont-fork", "--log-console", "--use-file", config,
		"--pid", filepath.Join(folder, "keepalived.pid"), "--vrrp_pid", filepath.Join(folder, "vrrp.pid")}
	return launchGatewayUnit(ctx, wireGuardService, wireGuardUnit(name), slot.Namespace, command)
}

func stopWireGuard(ctx context.Context, name string, slot wireGuardSlot) error {
	// Close forwarding before waiting for the address owner to stop.
	if err := network.RemoveWireGuardTunnel(ctx, slot.Namespace, slot.Tunnel); err != nil {
		return err
	}
	if err := stopGatewayUnit(ctx, wireGuardUnit(name)); err != nil {
		return err
	}
	owns, err := network.WireGuardOwnsAddress(ctx, slot.Namespace, slot.Inside, slot.Router.Addr())
	if err != nil {
		return err
	}
	if owns {
		return errors.New("the stopped WireGuard gateway still owns its router address")
	}
	return os.RemoveAll(filepath.Join(wireGuardRoot, name))
}

func wireGuardReady(ctx context.Context, name string, slot wireGuardSlot, gateway network.WireGuardGateway) (bool, bool, error) {
	state, err := httpsRuntimeCommand(ctx, "/usr/bin/systemctl", "show", "--property=ActiveState", "--value", wireGuardUnit(name))
	if err != nil {
		return false, false, err
	}
	if strings.TrimSpace(string(state)) != "active" || gateway.Probe(ctx, slot.Namespace) != nil {
		return false, false, nil
	}
	owns, err := gateway.OwnsAddress(ctx, slot.Namespace, slot.Router.Addr())
	return err == nil, owns, err
}
