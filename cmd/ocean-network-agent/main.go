package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Weichwolf/ocean/internal/nodeagent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	const config = "/etc/ocean-agent/"
	if err := nodeagent.RunNetworkPolicies(ctx, config+"config.json", config+"network.json", slog.Default()); err != nil {
		slog.Error("network policy service failed", "error", err)
		os.Exit(1)
	}
}
