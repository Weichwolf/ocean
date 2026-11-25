package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type volumeBinding struct {
	ID    string              `json:"id"`
	Share arm.ResourceAddress `json:"share"`
}

type volumeWriter struct {
	Host        string              `json:"host"`
	PlacementID string              `json:"placementId"`
	Generation  string              `json:"generation"`
	Resource    arm.ResourceAddress `json:"resource"`
}

func writerFor(record containerRecord) volumeWriter {
	return volumeWriter{Host: record.Reservation.HostID, PlacementID: record.Reservation.ID,
		Generation: record.Reservation.Generation, Resource: record.Address}
}

func (r *Region) claimVolume(ctx context.Context, scope arm.SubscriptionScope, record containerRecord,
	volume workload.AzureFileVolume) (volumeBinding, []clientv3.Cmp, []clientv3.Op, error) {
	var binding volumeBinding
	nameKey := r.storageNameKey(volume.StorageAccountName)
	names, err := r.client.Get(ctx, nameKey)
	if err != nil {
		return binding, nil, nil, err
	}
	if len(names.Kvs) != 1 {
		return binding, nil, nil, arm.ErrStorageAccess
	}
	accountKey := string(names.Kvs[0].Value)
	if !strings.HasPrefix(accountKey, r.armPrefix(scope)+"storage/accounts/") {
		return binding, nil, nil, arm.ErrStorageAccess
	}
	accounts, err := r.client.Get(ctx, accountKey, clientv3.WithRev(names.Header.Revision))
	if err != nil {
		return binding, nil, nil, err
	}
	var account storageAccountRecord
	if len(accounts.Kvs) != 1 || json.Unmarshal(accounts.Kvs[0].Value, &account) != nil || r.storageAccountKey(scope, account.Address) != accountKey {
		return binding, nil, nil, errors.New("invalid storage credential registry")
	}
	secret, err := r.storageAccountSecret(account, accountKey)
	if err != nil {
		return binding, nil, nil, err
	}
	defer clear(secret)
	provided, err := base64.StdEncoding.DecodeString(volume.StorageAccountKey)
	defer clear(provided)
	if err != nil || subtle.ConstantTimeCompare(secret, provided) != 1 {
		return binding, nil, nil, arm.ErrStorageAccess
	}
	address := arm.ResourceAddress{Group: account.Address.Group, Path: account.Address.Path + "/fileServices/default/shares/" + volume.ShareName}
	key := r.shareKey(scope, address)
	shares, err := r.client.Get(ctx, key, clientv3.WithRev(names.Header.Revision))
	if err != nil {
		return binding, nil, nil, err
	}
	if len(shares.Kvs) != 1 {
		return binding, nil, nil, arm.ErrStorageMissing
	}
	var share storageShareRecord
	entry := shares.Kvs[0]
	if json.Unmarshal(entry.Value, &share) != nil || share.Scope != scope || share.Address.Key() != address.Key() {
		return binding, nil, nil, errors.New("invalid storage share projection")
	}
	op, err := r.operationAt(ctx, scope, share.Operation, names.Header.Revision)
	if err != nil {
		return binding, nil, nil, err
	}
	if op.Status != arm.OperationSucceeded || share.Deleting {
		return binding, nil, nil, arm.ErrStorageBusy
	}
	writerKey := r.writerKey(scope, share.Volume.ID)
	writers, err := r.client.Get(ctx, writerKey, clientv3.WithRev(names.Header.Revision), clientv3.WithCountOnly())
	if err != nil {
		return binding, nil, nil, err
	}
	if writers.Count != 0 {
		return binding, nil, nil, arm.ErrStorageBusy
	}
	checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(nameKey), "=", names.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(accountKey), "=", accounts.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(key), "=", entry.ModRevision), clientv3.Compare(clientv3.Version(writerKey), "=", 0)}
	return volumeBinding{ID: share.Volume.ID, Share: address}, checks, []clientv3.Op{putJSON(writerKey, writerFor(record))}, nil
}

func (r *Region) releaseVolume(ctx context.Context, scope arm.SubscriptionScope, record containerRecord) (clientv3.Cmp, clientv3.Op, error) {
	key := r.writerKey(scope, record.Volume.ID)
	current, err := r.client.Get(ctx, key)
	if err != nil {
		return clientv3.Cmp{}, clientv3.Op{}, err
	}
	var writer volumeWriter
	if len(current.Kvs) != 1 || json.Unmarshal(current.Kvs[0].Value, &writer) != nil || writer != writerFor(record) {
		return clientv3.Cmp{}, clientv3.Op{}, errors.New("storage release requires the current writer generation")
	}
	return clientv3.Compare(clientv3.ModRevision(key), "=", current.Kvs[0].ModRevision), clientv3.OpDelete(key), nil
}

func (r *Region) HostVolumeMounts(ctx context.Context, host string, certificate []byte) ([]storage.MountTask, error) {
	if r.storage == nil || !slices.Contains(r.storage.workers, host) {
		return nil, enrollment.ErrHostDenied
	}
	prefix := r.hostContainerPrefix(host)
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(prefix, clientv3.WithPrefix())).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return nil, err
	}
	var mounts []storage.MountTask
	for _, item := range snapshot.Responses[2].GetResponseRange().Kvs {
		segments := strings.Split(strings.TrimPrefix(string(item.Key), prefix), "/")
		if len(segments) != 3 || !identifier.MatchString(segments[2]) {
			return nil, errors.New("invalid assigned storage placement")
		}
		scope := arm.SubscriptionScope{TenantID: segments[0], SubscriptionID: segments[1]}
		key := string(item.Value)
		if !validScope(scope) || !strings.HasPrefix(key, r.armPrefix(scope)+"containers/") {
			return nil, errors.New("invalid assigned storage scope")
		}
		state, err := r.client.Get(ctx, key, clientv3.WithRev(snapshot.Header.Revision))
		if err != nil {
			return nil, err
		}
		var record containerRecord
		if len(state.Kvs) != 1 || json.Unmarshal(state.Kvs[0].Value, &record) != nil || r.containerKey(scope, record.Address) != key ||
			record.Reservation.HostID != host || record.Reservation.ID != segments[2] {
			return nil, errors.New("invalid assigned storage resource")
		}
		if record.Volume == nil {
			continue
		}
		grant := writerFor(record)
		mount := storage.MountTask{VolumeID: record.Volume.ID, TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
			PlacementID: grant.PlacementID, Generation: grant.Generation, Revision: record.Operation, Remove: record.Desired == workload.Removed}
		if !mount.Remove {
			read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.writerKey(scope, record.Volume.ID), clientv3.WithRev(snapshot.Header.Revision)),
				clientv3.OpGet(r.shareKey(scope, record.Volume.Share), clientv3.WithRev(snapshot.Header.Revision))).Commit()
			if err != nil {
				return nil, err
			}
			var writer volumeWriter
			var share storageShareRecord
			writers, shares := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
			if len(writers) == 0 {
				continue
			}
			if len(writers) != 1 || len(shares) != 1 || json.Unmarshal(writers[0].Value, &writer) != nil || writer != grant ||
				json.Unmarshal(shares[0].Value, &share) != nil || share.Scope != scope || share.Volume.ID != record.Volume.ID || share.Deleting {
				return nil, errors.New("the assigned volume writer is inconsistent")
			}
			mount.VolumeKey, err = r.shareEncryptionKey(share)
			if err != nil {
				return nil, err
			}
		}
		mounts = append(mounts, mount)
	}
	return mounts, nil
}

func (r *Region) unmountReceiptKey(scope arm.SubscriptionScope, volume, generation, revision string) string {
	return r.armPrefix(scope) + "storage/unmounted/" + volume + "/" + generation + "/" + revision
}

func (r *Region) ReportVolumeUnmount(ctx context.Context, host string, certificate []byte, receipt storage.UnmountReceipt) error {
	if r.storage == nil || !slices.Contains(r.storage.workers, host) {
		return enrollment.ErrHostDenied
	}
	scope := arm.SubscriptionScope{TenantID: receipt.TenantID, SubscriptionID: receipt.SubscriptionID}
	hostKey, liveKey := r.hostKey("registered", host), r.hostKey("live", host)
	assignmentKey := r.hostContainerKey(scope, host, receipt.PlacementID)
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(hostKey), clientv3.OpGet(liveKey), clientv3.OpGet(assignmentKey)).Commit()
		if err != nil {
			return err
		}
		if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
			return err
		}
		items := snapshot.Responses[2].GetResponseRange().Kvs
		if len(items) == 0 {
			return enrollment.ErrWorkloadChanged
		}
		key := string(items[0].Value)
		group, path, _ := strings.Cut(strings.TrimPrefix(key, r.armPrefix(scope)+"containers/"), "/")
		address := arm.ResourceAddress{Group: group, Path: path}
		if !address.Valid() || key != r.containerKey(scope, address) {
			return errors.New("invalid unmount assignment")
		}
		_, record, op, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return err
		}
		if op == nil || record.Desired != workload.Removed || record.Volume == nil || record.Volume.ID != receipt.VolumeID ||
			record.Reservation.HostID != host || record.Reservation.ID != receipt.PlacementID ||
			record.Reservation.Generation != receipt.Generation || record.Operation != receipt.Revision {
			return enrollment.ErrWorkloadChanged
		}
		receiptKey := r.unmountReceiptKey(scope, receipt.VolumeID, receipt.Generation, receipt.Revision)
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(hostKey), "=", snapshot.Responses[0].GetResponseRange().Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(liveKey), ">", 0), clientv3.Compare(clientv3.ModRevision(assignmentKey), "=", items[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", revision)).Then(clientv3.OpPut(receiptKey, host)).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return enrollment.ErrWorkloadChanged
}
