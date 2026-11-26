package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/controlplane"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocean-backup:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "create" && args[0] != "prune" {
		return errors.New("use ocean-backup create or ocean-backup prune")
	}
	options := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configuration := options.String("config", "", "pinned hosted regional configuration")
	target := options.String("target", "", "approved backup target")
	if args[0] == "prune" {
		if err := options.Parse(args[1:]); err != nil {
			return err
		}
		if options.NArg() != 0 {
			return errors.New("unexpected prune arguments")
		}
		n, err := controlplane.PruneHostedBackups(*configuration, *target)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]int{"removed": n})
	}
	kind := options.String("kind", "etcd", "etcd, directory, volume, or export")
	tenant := options.String("tenant", "", "tenant of the supplied archive")
	subscription := options.String("subscription", "", "subscription of the supplied archive")
	checksum := options.String("sha256", "", "expected SHA-256 of the completed archive supplied on standard input")
	timeout := options.Duration("timeout", 10*time.Minute, "backup time limit")
	if err := options.Parse(args[1:]); err != nil {
		return err
	}
	if options.NArg() != 0 || *timeout <= 0 {
		return errors.New("unexpected backup arguments or invalid time limit")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if *kind != "etcd" {
		detach := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
		defer detach()
	}
	result, err := controlplane.SaveHostedBackup(ctx, *configuration, controlplane.HostedBackupRequest{
		Target: *target, Kind: *kind, TenantID: *tenant, SubscriptionID: *subscription, SHA256: *checksum, Input: os.Stdin})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
