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
	mode := flag.String("mode", "firewall", "firewall, https, or wireguard")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	const config = "/etc/ocean-agent/"
	var err error
	switch *mode {
	case "firewall":
		err = nodeagent.RunNetworkPolicies(ctx, config+"config.json", config+"network.json", slog.Default())
	case "https":
		err = nodeagent.RunHTTPSGateways(ctx, config+"config.json", config+"https.json", slog.Default())
	case "wireguard":
		err = nodeagent.RunWireGuardGateways(ctx, config+"config.json", config+"wireguard.json", slog.Default())
	default:
		slog.Error("unknown network policy service mode", "mode", *mode)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("network policy service failed", "error", err)
		os.Exit(1)
	}
}
