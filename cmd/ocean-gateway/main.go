package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/network"
)

type gatewayConfig struct {
	Namespace string                    `json:"namespace"`
	Egress    *network.FixedEgress      `json:"egress"`
	WireGuard *network.WireGuardGateway `json:"wireguard"`
}

func main() {
	path := flag.String("config", "/etc/ocean-gateway/config.json", "gateway configuration file")
	mode := flag.String("mode", "apply", "apply, remove, activate, or deactivate")
	flag.Parse()
	if err := run(*path, *mode); err != nil {
		fmt.Fprintf(os.Stderr, "ocean-gateway: %v\n", err)
		os.Exit(1)
	}
}

func run(path, mode string) error {
	settings, err := config.Load(path, gatewayConfig{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if (settings.Egress == nil) == (settings.WireGuard == nil) {
		return fmt.Errorf("configure exactly one gateway role")
	}
	if settings.WireGuard != nil {
		switch mode {
		case "apply":
			return settings.WireGuard.Apply(ctx, settings.Namespace)
		case "remove":
			return settings.WireGuard.Remove(ctx, settings.Namespace)
		default:
			return fmt.Errorf("unknown WireGuard gateway mode %q", mode)
		}
	}
	switch mode {
	case "apply":
		return settings.Egress.Apply(ctx, settings.Namespace)
	case "activate", "deactivate":
		return settings.Egress.SetActive(ctx, settings.Namespace, mode == "activate")
	default:
		return fmt.Errorf("unknown gateway mode %q", mode)
	}
}
