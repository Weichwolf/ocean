package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
)

const (
	httpsService = "ocean-https-agent.service"
	httpsRoot    = "/run/ocean-https-agent"
)

var httpsRoles = []string{"proxy", "dns", "vrrp"}

func httpsUnit(name, role string) string {
	return "ocean-https-" + name + "-" + role + ".service"
}

func httpsRuntimeCommand(ctx context.Context, command string, args ...string) ([]byte, error) {
	result, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", filepath.Base(command), args[0], err, bytes.TrimSpace(result))
	}
	return result, nil
}

func httpsInNamespace(ctx context.Context, slot network.HTTPSGatewaySlot, command string, args ...string) ([]byte, error) {
	return httpsRuntimeCommand(ctx, "/usr/bin/ip", append([]string{"netns", "exec", slot.Namespace, command}, args...)...)
}

func verifyHTTPSLinks(ctx context.Context, slot network.HTTPSGatewaySlot, assignment enrollment.HTTPSAssignment) error {
	verifyRoute := func(address netip.Addr, device string, acceptedSource func(netip.Addr) bool) error {
		raw, err := httpsRuntimeCommand(ctx, "/usr/bin/ip", "-n", slot.Namespace, "-4", "-j", "route", "get", address.String())
		if err != nil {
			return err
		}
		var route []struct {
			Device string     `json:"dev"`
			Source netip.Addr `json:"prefsrc"`
		}
		if err := json.Unmarshal(raw, &route); err != nil {
			return err
		}
		if len(route) != 1 || route[0].Device != device || !acceptedSource(route[0].Source) {
			return errors.New("the HTTPS gateway route does not use its operator-assigned link")
		}
		return nil
	}
	if err := verifyRoute(slot.PeerAddress, slot.PublicInterface, func(address netip.Addr) bool {
		return address == slot.PublicLink.Addr()
	}); err != nil {
		return err
	}
	return verifyRoute(assignment.Backend.Addr(), slot.BackendInterface, assignment.BackendSubnet.Contains)
}

func startHTTPSGateway(ctx context.Context, name string, slot network.HTTPSGatewaySlot,
	assignment enrollment.HTTPSAssignment, oldAddress netip.Addr) (err error) {
	if err := stopHTTPSGateway(ctx, name, slot, oldAddress); err != nil {
		return err
	}
	if err := verifyHTTPSLinks(ctx, slot, assignment); err != nil {
		return err
	}
	folder := filepath.Join(httpsRoot, name)
	if err := os.Mkdir(folder, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, stopHTTPSGateway(ctx, name, slot, assignment.PublicIPv4))
		}
	}()
	bundle := filepath.Join(folder, "ingress.pem")
	if err := os.WriteFile(bundle, assignment.CertificateBundle, 0600); err != nil {
		return err
	}
	ingress := network.HTTPSIngress{
		PublicIPv4: assignment.PublicIPv4, Hostname: assignment.Hostname, CertificateFile: bundle,
		Backend: assignment.Backend, BackendSubnet: assignment.BackendSubnet,
	}
	proxy, err := ingress.HAProxy()
	if err != nil {
		return err
	}
	vrrp, err := slot.Keepalived(assignment.PublicIPv4, assignment.Backend)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name, content string
		mode          os.FileMode
	}{
		{"haproxy.conf", proxy, 0600}, {"keepalived.conf", vrrp, 0600},
		{"public-ipv4", assignment.PublicIPv4.String(), 0600},
	} {
		if err := os.WriteFile(filepath.Join(folder, file.name), []byte(file.content), file.mode); err != nil {
			return err
		}
	}
	if _, err := httpsInNamespace(ctx, slot, "/usr/sbin/haproxy", "-c", "-f", filepath.Join(folder, "haproxy.conf")); err != nil {
		return err
	}
	if err := slot.InstallLease(ctx, assignment.PublicIPv4); err != nil {
		return err
	}
	services := [][]string{
		{"/usr/sbin/haproxy", "-db", "-f", filepath.Join(folder, "haproxy.conf")},
		{"/usr/sbin/dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
			"--listen-address=" + slot.PublicLink.Addr().String(), "--bind-interfaces", "--local-ttl=30",
			"--address=/" + assignment.Hostname + "/" + assignment.PublicIPv4.String()},
		{"/usr/sbin/keepalived", "--vrrp", "--dont-fork", "--log-console", "--use-file", filepath.Join(folder, "keepalived.conf"),
			"--pid", filepath.Join(folder, "keepalived.pid"), "--vrrp_pid", filepath.Join(folder, "vrrp.pid")},
	}
	for index, role := range httpsRoles {
		args := []string{"--quiet", "--no-block", "--collect", "--service-type=exec", "--unit", httpsUnit(name, role),
			"--property", "BindsTo=" + httpsService, "--property", "After=" + httpsService,
			"--property", "Restart=on-failure", "--property", "RestartSec=1s",
			"/usr/bin/ip", "netns", "exec", slot.Namespace}
		if _, err := httpsRuntimeCommand(ctx, "/usr/bin/systemd-run", append(args, services[index]...)...); err != nil {
			return err
		}
	}
	return nil
}

func stopHTTPSGateway(ctx context.Context, name string, slot network.HTTPSGatewaySlot, address netip.Addr) error {
	folder := filepath.Join(httpsRoot, name)
	if !address.IsValid() {
		saved, err := os.ReadFile(filepath.Join(folder, "public-ipv4"))
		if err == nil {
			address, err = netip.ParseAddr(string(saved))
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = slot.RevokeLease(ctx)
	for index := len(httpsRoles) - 1; index >= 0; index-- {
		unit := httpsUnit(name, httpsRoles[index])
		state, err := httpsRuntimeCommand(ctx, "/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(state)) != "not-found" {
			if _, err := httpsRuntimeCommand(ctx, "/usr/bin/systemctl", "stop", unit); err != nil {
				return err
			}
		}
	}
	if address.IsValid() {
		owned, err := slot.OwnsAddress(ctx, address)
		if err != nil {
			return err
		}
		if owned {
			return errors.New("the stopped gateway still owns its public address")
		}
	}
	return os.RemoveAll(folder)
}

func httpsGatewayReady(ctx context.Context, name string, slot network.HTTPSGatewaySlot,
	assignment enrollment.HTTPSAssignment) (bool, bool, error) {
	args := []string{"show", "--property=ActiveState", "--value"}
	for _, role := range httpsRoles {
		args = append(args, httpsUnit(name, role))
	}
	state, err := httpsRuntimeCommand(ctx, "/usr/bin/systemctl", args...)
	if err != nil {
		return false, false, err
	}
	units := strings.Fields(string(state))
	if len(units) != len(httpsRoles) || slices.ContainsFunc(units, func(value string) bool { return value != "active" }) {
		return false, false, nil
	}
	if _, err := httpsInNamespace(ctx, slot, "/usr/libexec/ocean/https-ready",
		assignment.PublicIPv4.String(), assignment.Backend.String()); err != nil {
		return false, false, nil
	}
	active, err := slot.OwnsAddress(ctx, assignment.PublicIPv4)
	return err == nil, active, err
}
