package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	createFileShare = "CreateFileShare"
	deleteFileShare = "DeleteFileShare"
)

type storageShareRecord struct {
	Address   arm.ResourceAddress   `json:"address"`
	Account   arm.ResourceAddress   `json:"account"`
	Scope     arm.SubscriptionScope `json:"scope"`
	Volume    storage.Volume        `json:"volume"`
	QuotaGiB  int                   `json:"quotaGiB"`
	Envelope  []byte                `json:"envelope"`
	Operation string                `json:"operation"`
	Host      string                `json:"host"`
	Deleting  bool                  `json:"deleting,omitempty"`
}

func (r *Region) shareKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "storage/shares/" + address.Key()
}

func (r *Region) writerKey(scope arm.SubscriptionScope, volume string) string {
	return r.armPrefix(scope) + "storage/writers/" + volume
}

func (r *Region) storageJobKey(host, id string) string {
	return r.hostKey("share-jobs", host) + "/" + id
}

func (r *Region) availableStorageWorker(ctx context.Context) (string, clientv3.Cmp, error) {
	for _, host := range r.storage.workers {
		key := r.hostKey("live", host)
		live, err := r.client.Get(ctx, key)
		if err != nil {
			return "", clientv3.Cmp{}, err
		}
		if len(live.Kvs) == 1 && live.Kvs[0].Lease != 0 {
			return host, clientv3.Compare(clientv3.ModRevision(key), "=", live.Kvs[0].ModRevision), nil
		}
	}
	return "", clientv3.Cmp{}, arm.ErrContainerCapacity
}

func ownedShare(address, account arm.ResourceAddress) bool {
	prefix := strings.ToLower(account.Path + "/fileServices/default/shares/")
	return strings.EqualFold(address.Group, account.Group) && strings.HasPrefix(strings.ToLower(address.Path), prefix) &&
		storage.ValidShare(address.Path[len(prefix):])
}

func (r *Region) PutFileShare(ctx context.Context, scope arm.SubscriptionScope, actor string, account, address arm.ResourceAddress,
	properties storage.ShareProperties) (arm.InventoryResource, *arm.Operation, bool, error) {
	if !ownedShare(address, account) {
		return arm.InventoryResource{}, nil, false, arm.ErrStorageMissing
	}
	key := r.shareKey(scope, address)
	accountKey := r.storageAccountKey(scope, account)
	accountInventory := r.inventoryPrefix(scope) + account.Key()
	publicKey := r.inventoryPrefix(scope) + address.Key()
	for range 8 {
		current, err := r.client.Txn(ctx).Then(clientv3.OpGet(accountKey), clientv3.OpGet(accountInventory),
			clientv3.OpGet(key), clientv3.OpGet(publicKey)).Commit()
		if err != nil {
			return arm.InventoryResource{}, nil, false, err
		}
		accounts := current.Responses[0].GetResponseRange().Kvs
		if len(accounts) != 1 || len(current.Responses[1].GetResponseRange().Kvs) != 1 {
			return arm.InventoryResource{}, nil, false, arm.ErrStorageMissing
		}
		accountView, err := decodeInventoryResource(current.Responses[1].GetResponseRange().Kvs[0].Value, account.Key())
		if err != nil {
			return arm.InventoryResource{}, nil, false, err
		}
		prior, public := current.Responses[2].GetResponseRange().Kvs, current.Responses[3].GetResponseRange().Kvs
		if len(prior) == 1 {
			var record storageShareRecord
			if json.Unmarshal(prior[0].Value, &record) != nil || len(public) != 1 || record.Scope != scope || record.Address.Key() != address.Key() {
				return arm.InventoryResource{}, nil, false, errors.New("invalid storage share record")
			}
			if record.QuotaGiB != properties.QuotaGiB {
				return arm.InventoryResource{}, nil, false, arm.ErrStorageChanged
			}
			if record.Deleting {
				return arm.InventoryResource{}, nil, false, arm.ErrStorageBusy
			}
			view, err := decodeInventoryResource(public[0].Value, address.Key())
			if err != nil {
				return view, nil, false, err
			}
			operation, err := r.operationAt(ctx, scope, record.Operation, current.Header.Revision)
			return view, operation, false, err
		}
		if len(public) != 0 {
			return arm.InventoryResource{}, nil, false, errors.New("storage share already has inconsistent inventory")
		}
		host, live, err := r.availableStorageWorker(ctx)
		if err != nil {
			return arm.InventoryResource{}, nil, false, err
		}
		address.Group, account.Group = accountView.Address.Group, accountView.Address.Group
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: createFileShare, Group: address.Group, Actor: actor, StartedAt: now, Status: arm.OperationInProgress}
		volume := storage.Volume{ID: "vol-" + operationID(), SizeMiB: int64(properties.QuotaGiB)*1024 + 32}
		record := storageShareRecord{Address: address, Account: account, Scope: scope, Volume: volume,
			QuotaGiB: properties.QuotaGiB, Operation: op.ID, Host: host}
		secret := make([]byte, storage.KeySize)
		rand.Read(secret)
		record.Envelope = r.storage.sealer.Seal(nil, nil, secret, []byte(key+"/"+volume.ID))
		clear(secret)
		view := arm.InventoryResource{Address: address, APIVersion: storage.ShareAPIVersion, Location: accountView.Location,
			CreatedAt: now, ChangedAt: now, ProvisioningState: arm.OperationInProgress, References: []arm.ResourceAddress{account}}
		view.Properties = shareProjection(record, arm.OperationInProgress)
		opKey, taskKey := r.operationKey(scope, op.ID), r.storageJobKey(host, op.ID)
		result, err := r.client.Txn(ctx).If(live, clientv3.Compare(clientv3.ModRevision(accountKey), "=", accounts[0].ModRevision),
			clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(publicKey), "=", 0),
			clientv3.Compare(clientv3.Version(opKey), "=", 0), clientv3.Compare(clientv3.Version(taskKey), "=", 0)).
			Then(putJSON(key, record), putJSON(publicKey, view), putJSON(opKey, op), clientv3.OpPut(taskKey, key), r.storageAudit(record, op, "write", now)).Commit()
		if err != nil || result.Succeeded {
			return view, &op, result != nil && result.Succeeded, err
		}
	}
	return arm.InventoryResource{}, nil, false, arm.ErrStorageBusy
}

func shareProjection(record storageShareRecord, state string) json.RawMessage {
	properties, _ := json.Marshal(map[string]any{"shareQuota": record.QuotaGiB, "enabledProtocols": "SMB",
		"accessTier": "TransactionOptimized", "provisioningState": state})
	return properties
}

func (r *Region) storageAudit(record storageShareRecord, op arm.Operation, action string, at time.Time) clientv3.Op {
	return r.auditOp(record.Scope, arm.AuditEvent{Time: at, Actor: op.Actor, Action: storage.ShareType + "/" + action,
		Target: record.Address.ID(record.Scope), Outcome: op.Status})
}

func (r *Region) DeleteFileShare(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress) (*arm.Operation, error) {
	key := r.shareKey(scope, address)
	for range 8 {
		current, err := r.client.Get(ctx, key)
		if err != nil || len(current.Kvs) == 0 {
			return nil, err
		}
		item := current.Kvs[0]
		var record storageShareRecord
		if json.Unmarshal(item.Value, &record) != nil || record.Scope != scope || record.Address.Key() != address.Key() {
			return nil, errors.New("invalid storage share")
		}
		currentOp, err := r.operationAt(ctx, scope, record.Operation, current.Header.Revision)
		if err != nil || record.Deleting {
			return currentOp, err
		}
		if currentOp.Status == arm.OperationInProgress {
			return nil, arm.ErrStorageBusy
		}
		writerKey := r.writerKey(scope, record.Volume.ID)
		writers, err := r.client.Get(ctx, writerKey, clientv3.WithCountOnly())
		if err != nil {
			return nil, err
		}
		if writers.Count != 0 {
			return nil, arm.ErrStorageBusy
		}
		host, live, err := r.availableStorageWorker(ctx)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: deleteFileShare, Group: record.Address.Group, Actor: actor, StartedAt: now, Status: arm.OperationInProgress}
		record.Operation, record.Host, record.Deleting = op.ID, host, true
		opKey, taskKey := r.operationKey(scope, op.ID), r.storageJobKey(host, op.ID)
		result, err := r.client.Txn(ctx).If(live, clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision),
			clientv3.Compare(clientv3.Version(writerKey), "=", 0), clientv3.Compare(clientv3.Version(opKey), "=", 0),
			clientv3.Compare(clientv3.Version(taskKey), "=", 0)).Then(putJSON(key, record), putJSON(opKey, op),
			clientv3.OpPut(taskKey, key), r.storageAudit(record, op, "delete", now)).Commit()
		if err != nil || result.Succeeded {
			return &op, err
		}
	}
	return nil, arm.ErrStorageBusy
}
