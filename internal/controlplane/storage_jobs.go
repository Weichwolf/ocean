package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) HostShareJobs(ctx context.Context, host string, certificate []byte) ([]storage.Job, error) {
	if r.storage == nil || !slices.Contains(r.storage.workers, host) {
		return nil, enrollment.ErrHostDenied
	}
	prefix := r.storageJobKey(host, "")
	purgePrefix := r.filePurgeJobKey(host, "")
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithLimit(8)), clientv3.OpGet(purgePrefix, clientv3.WithPrefix())).Commit()
	if err != nil {
		return nil, err
	}
	pool, err := r.authorizeStorageJobHost(host, certificate, snapshot)
	if err != nil {
		return nil, err
	}
	items := snapshot.Responses[2].GetResponseRange().Kvs
	const maxJobs = 8
	jobs := make([]storage.Job, 0, maxJobs)
	for _, item := range snapshot.Responses[3].GetResponseRange().Kvs {
		volume := strings.TrimPrefix(string(item.Key), purgePrefix)
		decision, err := r.certifyFilePurgeJob(ctx, host, pool, volume, string(item.Value), snapshot.Header.Revision)
		if err == nil {
			_, _, err = r.filePurgeBoundary(ctx, decision, snapshot.Header.Revision)
		}
		if errors.Is(err, identity.ErrHostedPurgeState) {
			continue
		}
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, storage.Job{ID: volume, Volume: storage.Volume{ID: volume}, Delete: true})
		if len(jobs) == maxJobs/2 {
			break
		}
	}
	for _, item := range items {
		if len(jobs) == maxJobs {
			break
		}
		key := string(item.Value)
		id := strings.TrimPrefix(string(item.Key), prefix)
		record, _, err := r.readShareJob(ctx, host, key, id, snapshot.Header.Revision)
		if err != nil {
			return nil, err
		}
		if _, err := r.hostedHostGuards(ctx, record.Scope, host, snapshot.Header.Revision); err != nil {
			if errors.Is(err, ErrPlacementPolicy) {
				continue
			}
			return nil, err
		}
		job := storage.Job{ID: id, Volume: record.Volume, Delete: record.Deleting}
		if !record.Deleting {
			job.VolumeKey, err = r.shareEncryptionKey(record)
			if err != nil {
				return nil, err
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (r *Region) authorizeStorageJobHost(host string, certificate []byte, snapshot *clientv3.TxnResponse) (string, error) {
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return "", err
	}
	var registration enrollment.Host
	if err := json.Unmarshal(snapshot.Responses[0].GetResponseRange().Kvs[0].Value, &registration); err != nil {
		return "", err
	}
	return registration.Pool, nil
}

func (r *Region) readShareJob(ctx context.Context, host, key, jobID string, revision int64) (storageShareRecord, int64, error) {
	var record storageShareRecord
	if !identifier.MatchString(jobID) || !strings.HasPrefix(key, r.root+"/tenants/") {
		return record, 0, errors.New("invalid storage job reference")
	}
	read, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return record, 0, err
	}
	if len(read.Kvs) != 1 || json.Unmarshal(read.Kvs[0].Value, &record) != nil || !validScope(record.Scope) ||
		!ownedShare(record.Address, record.Account) || key != r.shareKey(record.Scope, record.Address) ||
		record.Host != host || record.Operation != jobID || !storage.ValidID(record.Volume.ID) {
		return record, 0, errors.New("invalid storage job state")
	}
	return record, read.Kvs[0].ModRevision, nil
}

func (r *Region) shareEncryptionKey(record storageShareRecord) ([]byte, error) {
	binding := r.shareKey(record.Scope, record.Address) + "/" + record.Volume.ID
	key, err := r.storage.sealer.Open(nil, nil, record.Envelope, []byte(binding))
	if err != nil || len(key) != storage.KeySize {
		clear(key)
		return nil, errors.New("invalid storage encryption key envelope")
	}
	return key, nil
}

func (r *Region) CompleteShareJob(ctx context.Context, host string, certificate []byte, id string) error {
	if r.storage == nil || !slices.Contains(r.storage.workers, host) {
		return enrollment.ErrHostDenied
	}
	if strings.HasPrefix(id, "vol-") {
		return r.completeHostedFilePurge(ctx, host, certificate, id)
	}
	hostKey, liveKey, taskKey := r.hostKey("registered", host), r.hostKey("live", host), r.storageJobKey(host, id)
	for range 8 {
		snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(hostKey), clientv3.OpGet(liveKey), clientv3.OpGet(taskKey)).Commit()
		if err != nil {
			return err
		}
		if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
			return err
		}
		tasks := snapshot.Responses[2].GetResponseRange().Kvs
		if len(tasks) == 0 {
			return nil
		}
		key := string(tasks[0].Value)
		record, revision, err := r.readShareJob(ctx, host, key, id, snapshot.Header.Revision)
		if err != nil {
			return err
		}
		guards, err := r.hostedHostGuards(ctx, record.Scope, host, snapshot.Header.Revision)
		if errors.Is(err, ErrPlacementPolicy) {
			return enrollment.ErrHostDenied
		}
		if err != nil {
			return err
		}
		op, err := r.operationAt(ctx, record.Scope, id, snapshot.Header.Revision)
		if err != nil || op.Status != arm.OperationInProgress {
			return err
		}
		publicKey := r.inventoryPrefix(record.Scope) + record.Address.Key()
		public, err := r.client.Get(ctx, publicKey, clientv3.WithRev(snapshot.Header.Revision))
		if err != nil {
			return err
		}
		if len(public.Kvs) != 1 {
			return errors.New("storage operation inventory entry is missing")
		}
		now := time.Now().UTC()
		op.Status, op.FinishedAt = arm.OperationSucceeded, &now
		checks := append(guards, clientv3.Compare(clientv3.ModRevision(hostKey), "=", snapshot.Responses[0].GetResponseRange().Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(liveKey), ">", 0), clientv3.Compare(clientv3.ModRevision(taskKey), "=", tasks[0].ModRevision),
			clientv3.Compare(clientv3.ModRevision(key), "=", revision), clientv3.Compare(clientv3.ModRevision(publicKey), "=", public.Kvs[0].ModRevision))
		writes := []clientv3.Op{clientv3.OpDelete(taskKey), putJSON(r.operationKey(record.Scope, id), op), r.storageAudit(record, *op, "reconcile", now)}
		if record.Deleting {
			checks = append(checks, clientv3.Compare(clientv3.Version(r.writerKey(record.Scope, record.Volume.ID)), "=", 0))
			writes = append(writes, clientv3.OpDelete(key), clientv3.OpDelete(publicKey))
		} else {
			view, err := decodeInventoryResource(public.Kvs[0].Value, record.Address.Key())
			if err != nil {
				return err
			}
			view.ChangedAt, view.ProvisioningState = now, op.Status
			view.Properties = shareProjection(record, op.Status)
			writes = append(writes, putJSON(publicKey, view))
		}
		result, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return arm.ErrStorageBusy
}
