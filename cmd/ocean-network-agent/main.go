package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Weichwolf/ocean/internal/nodeagent"
)

func main() {
	mode := flag.String("mode", "firewall", "firewall, https, wireguard, ipsec, containers, storage, smb, or vm")
	vmAction := flag.String("vm-action", "", "internal unprivileged VM control action")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	const config = "/etc/ocean-agent/"
	var err error
	switch *mode {
	case "firewall":
		err = nodeagent.RunNetworkPolicies(ctx, config+"config.json", config+"network.json", slog.Default())
	case "storage":
		err = nodeagent.RunStorage(ctx, config+"storage.json", config+"config.json", slog.Default())
	case "smb":
		err = nodeagent.RunSMB(ctx, config+"smb-storage.json", config+"config.json", slog.Default())
	case "vm":
		err = nodeagent.RunVMWorker(ctx, config, slog.Default())
	case "vm-guest":
		err = nodeagent.RunVMGuestControl(ctx, *vmAction, os.Stdin, os.Stdout)
	case "containers":
		err = nodeagent.RunContainerNetwork(ctx, config+"workload-network.json", config+"config.json", slog.Default())
	case "https":
		err = nodeagent.RunHTTPSGateways(ctx, config+"config.json", config+"https.json", slog.Default())
	case "wireguard":
		err = nodeagent.RunWireGuardGateways(ctx, config+"config.json", config+"wireguard.json", slog.Default())
	case "ipsec":
		err = nodeagent.RunIPsecGateways(ctx, config+"config.json", config+"ipsec.json", slog.Default())
	default:
		slog.Error("unknown network policy service mode", "mode", *mode)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("network policy service failed", "error", err)
		os.Exit(1)
	}
}
