package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
)

// RecoverVolumeKey restores one key envelope with the operator's separate
// key file and authenticated access to a restored regional metadata store.
func RecoverVolumeKey(ctx context.Context, configuration, tenant, subscription, shareID, destination string) error {
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: subscription}
	parts := strings.Split(strings.TrimPrefix(shareID, "/"), "/")
	if !validScope(scope) || len(parts) != 12 || !strings.EqualFold(parts[0], "subscriptions") || parts[1] != subscription ||
		!strings.EqualFold(parts[2], "resourceGroups") || !strings.EqualFold(parts[4], "providers") {
		return errors.New("recovery requires a scoped file share ID")
	}
	address := arm.ResourceAddress{Group: parts[3], Path: strings.Join(parts[5:], "/")}
	account := arm.ResourceAddress{Group: address.Group, Path: strings.Join(parts[5:8], "/")}
	if !address.Valid() || !ownedShare(address, account) || destination == "" {
		return errors.New("invalid file share or key destination")
	}
	settings, err := config.Load(configuration, settings{})
	if err != nil {
		return err
	}
	if settings.Region == nil || settings.Region.Storage == nil {
		return errors.New("recovery requires regional storage and key configuration")
	}
	region, err := openRegion(*settings.Region)
	if err != nil {
		return err
	}
	defer func() { _ = region.client.Close() }()
	lookup, err := region.client.Get(ctx, region.shareKey(scope, address))
	if err != nil {
		return err
	}
	var share storageShareRecord
	if len(lookup.Kvs) != 1 || json.Unmarshal(lookup.Kvs[0].Value, &share) != nil || share.Scope != scope ||
		share.Address.Key() != address.Key() || share.Deleting {
		return arm.ErrStorageMissing
	}
	key, err := region.shareEncryptionKey(share)
	if err != nil {
		return err
	}
	defer clear(key)
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(key); err != nil {
		return errors.Join(err, file.Close(), os.Remove(destination))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close(), os.Remove(destination))
	}
	if err := file.Close(); err != nil {
		return errors.Join(err, os.Remove(destination))
	}
	return nil
}
