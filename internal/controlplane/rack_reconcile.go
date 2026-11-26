package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Weichwolf/ocean/internal/rack"
)

func (r *Region) reconcileRackHosts(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		r.reconcileRackFeed(ctx, logger)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (r *Region) reconcileRackFeed(ctx context.Context, logger *slog.Logger) {
	cfg := r.rack.cfg
	feed, err := rack.LoadInventory(cfg.InventoryFile, cfg.SignatureFile, cfg.PublicKeyFile, time.Now())
	if err != nil {
		logger.Warn("cannot read the approved rack inventory", "error", err)
		return
	}
	active, stop := context.WithDeadline(ctx, feed.ExpiresAt)
	defer stop()
	checkpoint, cancel := context.WithTimeout(active, 5*time.Second)
	record, err := r.acceptRackFeed(checkpoint, feed)
	cancel()
	if err != nil {
		logger.Warn("cannot accept the approved rack inventory", "error", err)
		return
	}
	var group sync.WaitGroup
	workers := min(8, len(feed.Assets))
	for worker := range workers {
		group.Go(func() {
			for index := worker; index < len(feed.Assets) && active.Err() == nil; index += workers {
				asset := feed.Assets[index]
				attempt, cancel := context.WithTimeout(active, 40*time.Second)
				err := r.reconcileRackAsset(attempt, record, asset)
				cancel()
				if err != nil {
					logger.Warn("rack host is awaiting provisioning", "host", asset.HostID, "rack", asset.Rack, "error", err)
				}
			}
		})
	}
	group.Wait()
}

func (r *Region) reconcileRackAsset(ctx context.Context, feed string, asset rack.Asset) error {
	policy, ok := r.rack.cfg.Racks[asset.Rack]
	if !ok {
		return errors.New("approved asset has no rack policy")
	}
	assignment, revision, err := r.loadRackAssignment(ctx, asset, policy)
	if err != nil {
		return err
	}
	if assignment.DNSPublished {
		if r.rack.install == nil {
			return nil
		}
		return r.reconcileRackInstallation(ctx, feed, assignment, revision, policy)
	}
	if err := r.rack.bmcs[asset.Rack].Verify(ctx, asset); err != nil {
		return err
	}
	if err := r.rack.ironic.Verify(ctx, asset); err != nil {
		return err
	}
	if revision == 0 {
		assignment, revision, err = r.reserveRackHost(ctx, feed, asset, policy)
		if err != nil || assignment.DNSPublished {
			return err
		}
	}
	return r.publishRackDNS(ctx, asset, policy, assignment, revision)
}
