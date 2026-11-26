package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
)

// RecoverVolumeKey restores one key envelope with the operator's separate
// key file and authenticated access to a restored regional metadata store.
func RecoverVolumeKey(ctx context.Context, configuration, tenant, subscription, shareID, targetName, destination string) error {
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: subscription}
	address, err := recoveryShareAddress(scope, shareID)
	if err != nil {
		return err
	}
	if destination == "" {
		return errors.New("invalid file share or key destination")
	}
	settings, err := config.Load(configuration, settings{})
	if err != nil {
		return err
	}
	if settings.Region == nil || settings.Region.Storage == nil {
		return errors.New("recovery requires regional storage and key configuration")
	}
	target, err := settings.Region.authorizeRecoveryTarget(targetName, destination)
	if err != nil {
		return err
	}
	region, err := openRegion(*settings.Region)
	if err != nil {
		return err
	}
	defer func() { _ = region.close() }()
	if err := region.verifyRecoveryTarget(ctx, scope, target); err != nil {
		return err
	}
	openFile, remove := os.OpenFile, os.Remove
	if target.KeyDirectory != "" {
		root, err := target.openKeyDirectory()
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		openFile, remove = root.OpenFile, root.Remove
		destination = filepath.Base(destination)
	}
	key, err := region.recoverShareKey(ctx, scope, address)
	if err != nil {
		return err
	}
	defer clear(key)
	file, err := openFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(key); err != nil {
		return errors.Join(err, file.Close(), remove(destination))
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close(), remove(destination))
	}
	if err := file.Close(); err != nil {
		return errors.Join(err, remove(destination))
	}
	return nil
}

func recoveryShareAddress(scope arm.SubscriptionScope, shareID string) (arm.ResourceAddress, error) {
	parts := strings.Split(strings.TrimPrefix(shareID, "/"), "/")
	if !validScope(scope) || len(parts) != 8 && len(parts) != 12 ||
		!strings.EqualFold(parts[0], "subscriptions") || parts[1] != scope.SubscriptionID ||
		!strings.EqualFold(parts[2], "resourceGroups") || !strings.EqualFold(parts[4], "providers") {
		return arm.ResourceAddress{}, errors.New("recovery requires a scoped file share ID")
	}
	address := arm.ResourceAddress{Group: parts[3], Path: strings.Join(parts[5:], "/")}
	if len(parts) == 8 {
		if _, valid := smbShareName(address); valid {
			return address, nil
		}
	} else {
		account := arm.ResourceAddress{Group: address.Group, Path: strings.Join(parts[5:8], "/")}
		if address.Valid() && ownedShare(address, account) {
			return address, nil
		}
	}
	return arm.ResourceAddress{}, errors.New("invalid file share ID")
}

func (r *Region) recoverShareKey(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) ([]byte, error) {
	if _, isSMB := smbShareName(address); isSMB {
		if r.smb == nil {
			return nil, arm.ErrStorageMissing
		}
		binding, ok := r.smb.bindings[scope]
		if !ok {
			return nil, arm.ErrStorageMissing
		}
		lookup, err := r.client.Get(ctx, r.smbMemberKey(binding))
		if err != nil {
			return nil, err
		}
		records, _, err := smbRecords(binding, lookup.Kvs)
		if err != nil {
			return nil, err
		}
		index := slices.IndexFunc(records, func(record smbShareRecord) bool {
			return record.Address.Key() == address.Key() && record.Ready && !record.Deleting
		})
		if index == -1 {
			return nil, arm.ErrStorageMissing
		}
		return r.smbShareEncryptionKey(binding, records[index])
	}
	lookup, err := r.client.Get(ctx, r.shareKey(scope, address))
	if err != nil {
		return nil, err
	}
	var share storageShareRecord
	if len(lookup.Kvs) != 1 || json.Unmarshal(lookup.Kvs[0].Value, &share) != nil || share.Scope != scope ||
		share.Address.Key() != address.Key() || share.Deleting {
		return nil, arm.ErrStorageMissing
	}
	return r.shareEncryptionKey(share)
}
