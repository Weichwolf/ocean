package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type storageAccountRecord struct {
	Address     arm.ResourceAddress `json:"address"`
	KeyEnvelope []byte              `json:"keyEnvelope"`
}

func (r *Region) storageAccountsPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "storage/accounts/" + strings.ToLower(group) + "/"
}

func (r *Region) storageAccountKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "storage/accounts/" + address.Key()
}

func (r *Region) storageNameKey(name string) string { return r.root + "/storage/names/" + name }

func (r *Region) StorageNameAvailable(ctx context.Context, name string) (bool, error) {
	if !storage.ValidAccount(name) {
		return false, arm.ErrStorageMissing
	}
	current, err := r.client.Get(ctx, r.storageNameKey(name), clientv3.WithCountOnly())
	return err == nil && current.Count == 0, err
}

func (r *Region) PutStorageAccount(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	input storage.AccountRequest) (arm.InventoryResource, bool, error) {
	storageKey := r.storageAccountKey(scope, address)
	nameKey := r.storageNameKey(storageAccountName(address))
	groupKey := r.groupPrefix(scope) + strings.ToLower(address.Group)
	inventoryKey := r.inventoryPrefix(scope) + address.Key()
	for range 8 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(storageKey),
			clientv3.OpGet(inventoryKey), clientv3.OpGet(nameKey)).Commit()
		if err != nil {
			return arm.InventoryResource{}, false, err
		}
		groups := read.Responses[0].GetResponseRange().Kvs
		if len(groups) != 1 {
			return arm.InventoryResource{}, false, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groups[0].Value, strings.ToLower(address.Group))
		if err != nil || group.DeleteOperation != "" {
			if err == nil {
				err = arm.ErrGroupDeleting
			}
			return arm.InventoryResource{}, false, err
		}
		accounts, inventory, names := read.Responses[1].GetResponseRange().Kvs, read.Responses[2].GetResponseRange().Kvs, read.Responses[3].GetResponseRange().Kvs
		if len(accounts) == 1 && len(inventory) == 1 && len(names) == 1 && string(names[0].Value) == storageKey {
			current, err := decodeInventoryResource(inventory[0].Value, address.Key())
			if err == nil && !maps.Equal(current.Tags, input.Tags) {
				err = arm.ErrStorageChanged
			}
			return current, false, err
		}
		if len(names) != 0 {
			return arm.InventoryResource{}, false, arm.ErrStorageNameInUse
		}
		if len(inventory) != 0 || len(accounts) != 0 {
			return arm.InventoryResource{}, false, errors.New("inconsistent storage account inventory")
		}
		address.Group = group.Name
		secret := make([]byte, 64)
		rand.Read(secret)
		envelope := r.storage.sealer.Seal(nil, nil, secret, []byte(storageKey))
		clear(secret)
		account := storageAccountRecord{Address: address, KeyEnvelope: envelope}
		now := time.Now().UTC()
		props := map[string]any{"provisioningState": arm.OperationSucceeded, "supportsHttpsTrafficOnly": true,
			"publicNetworkAccess": "Disabled", "allowBlobPublicAccess": false, "allowSharedKeyAccess": true, "minimumTlsVersion": "TLS1_2",
			"encryption": map[string]any{"keySource": "Microsoft.Storage", "services": map[string]any{"file": map[string]bool{"enabled": true}}}}
		properties, _ := json.Marshal(props)
		projection := arm.InventoryResource{Address: address, APIVersion: storage.AccountAPIVersion, Location: input.Location,
			Kind: input.Kind, SKU: arm.ResourceSKU{Name: "Standard_LRS", Tier: "Standard"}, Tags: input.Tags, Properties: properties,
			ProvisioningState: arm.OperationSucceeded, CreatedAt: now, ChangedAt: now}
		event := arm.AuditEvent{Time: now, Actor: actor, Action: storage.AccountType + "/write", Target: address.ID(scope), Outcome: arm.OperationSucceeded}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups[0].ModRevision),
			clientv3.Compare(clientv3.Version(storageKey), "=", 0), clientv3.Compare(clientv3.Version(inventoryKey), "=", 0),
			clientv3.Compare(clientv3.Version(nameKey), "=", 0)).Then(putJSON(storageKey, account), putJSON(inventoryKey, projection),
			clientv3.OpPut(nameKey, storageKey), r.auditOp(scope, event)).Commit()
		if err != nil || result.Succeeded {
			return projection, result != nil && result.Succeeded, err
		}
	}
	return arm.InventoryResource{}, false, arm.ErrStorageBusy
}

func storageAccountName(address arm.ResourceAddress) string {
	return address.Path[strings.LastIndexByte(address.Path, '/')+1:]
}

func (r *Region) storageAccountSecret(record storageAccountRecord, key string) ([]byte, error) {
	secret, err := r.storage.sealer.Open(nil, nil, record.KeyEnvelope, []byte(key))
	if err != nil || len(secret) != 64 {
		clear(secret)
		return nil, errors.New("invalid storage credential envelope")
	}
	return secret, nil
}

func secondaryStorageKey(primary []byte) []byte {
	mac := hmac.New(sha512.New, primary)
	mac.Write([]byte("ocean/storage/account/key2"))
	return mac.Sum(nil)
}

func (r *Region) GetStorageAccountKeys(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) ([2]string, error) {
	key := r.storageAccountKey(scope, address)
	lookup, err := r.client.Get(ctx, key)
	if err != nil {
		return [2]string{}, err
	}
	if len(lookup.Kvs) != 1 {
		return [2]string{}, arm.ErrStorageMissing
	}
	var record storageAccountRecord
	if err := json.Unmarshal(lookup.Kvs[0].Value, &record); err != nil || record.Address.Key() != address.Key() {
		return [2]string{}, errors.New("invalid storage account record")
	}
	secret, err := r.storageAccountSecret(record, key)
	if err != nil {
		return [2]string{}, err
	}
	defer clear(secret)
	event := arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: storage.AccountType + "/listKeys/action",
		Target: record.Address.ID(scope), Outcome: arm.OperationSucceeded}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", lookup.Kvs[0].ModRevision)).Then(r.auditOp(scope, event)).Commit()
	if err != nil {
		return [2]string{}, err
	}
	if !result.Succeeded {
		return [2]string{}, arm.ErrStorageMissing
	}
	secondary := secondaryStorageKey(secret)
	defer clear(secondary)
	return [2]string{base64.StdEncoding.EncodeToString(secret), base64.StdEncoding.EncodeToString(secondary)}, nil
}

func (r *Region) storageSharesPrefix(scope arm.SubscriptionScope, account arm.ResourceAddress) string {
	return r.armPrefix(scope) + "storage/shares/" + account.Key() + "/"
}

func (r *Region) DeleteStorageAccount(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) error {
	key := r.storageAccountKey(scope, address)
	dependent := r.storageSharesPrefix(scope, address)
	nameKey := r.storageNameKey(storageAccountName(address))
	for range 8 {
		current, err := r.client.Txn(ctx).Then(clientv3.OpGet(key), clientv3.OpGet(dependent, clientv3.WithPrefix(), clientv3.WithCountOnly())).Commit()
		if err != nil {
			return err
		}
		accounts := current.Responses[0].GetResponseRange().Kvs
		if len(accounts) == 0 {
			return nil
		}
		if current.Responses[1].GetResponseRange().Count != 0 {
			return arm.ErrStorageBusy
		}
		event := arm.AuditEvent{Time: time.Now().UTC(), Actor: actor, Action: storage.AccountType + "/delete",
			Target: address.ID(scope), Outcome: arm.OperationSucceeded}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", accounts[0].ModRevision),
			clientv3.Compare(clientv3.Version(dependent), "=", 0).WithPrefix(), clientv3.Compare(clientv3.Value(nameKey), "=", key)).
			Then(clientv3.OpDelete(key), clientv3.OpDelete(nameKey), clientv3.OpDelete(r.inventoryPrefix(scope)+address.Key()), r.auditOp(scope, event)).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return arm.ErrStorageBusy
}
