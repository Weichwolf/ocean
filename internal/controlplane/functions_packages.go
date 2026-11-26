package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const functionPackageChunkSize = 256 << 10

func (r *Region) HostFunctionPackage(ctx context.Context, host string, certificate []byte, assignment workload.AssignmentID) ([]byte, error) {
	scope := arm.SubscriptionScope{TenantID: assignment.TenantID, SubscriptionID: assignment.SubscriptionID}
	if r.workloads == nil || !validScope(scope) || !identifier.MatchString(assignment.ID) ||
		!identifier.MatchString(assignment.Generation) || !identifier.MatchString(assignment.Revision) {
		return nil, enrollment.ErrHostDenied
	}
	taskKey := r.hostContainerKey(scope, host, assignment.ID)
	snapshot, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("registered", host)), clientv3.OpGet(r.hostKey("live", host)),
		clientv3.OpGet(taskKey)).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.authorizeHostRole(host, certificate, "compute", snapshot); err != nil {
		return nil, err
	}
	tasks := snapshot.Responses[2].GetResponseRange().Kvs
	if len(tasks) != 1 {
		return nil, enrollment.ErrWorkloadChanged
	}
	recordKey := string(tasks[0].Value)
	if !strings.HasPrefix(recordKey, r.armPrefix(scope)+"containers/") {
		return nil, enrollment.ErrWorkloadChanged
	}
	entries, err := r.client.Get(ctx, recordKey, clientv3.WithRev(snapshot.Header.Revision))
	if err != nil {
		return nil, err
	}
	var record containerRecord
	if len(entries.Kvs) != 1 || json.Unmarshal(entries.Kvs[0].Value, &record) != nil ||
		r.containerKey(scope, record.Address) != recordKey || record.Desired != workload.Running ||
		record.Reservation.HostID != host || record.Reservation.ID != assignment.ID ||
		record.Reservation.Generation != assignment.Generation || record.Operation != assignment.Revision {
		return nil, enrollment.ErrWorkloadChanged
	}
	config, err := r.decryptContainer(scope, record)
	if err != nil {
		return nil, err
	}
	if config.Function == nil || config.Function.Runtime.Package == nil {
		return nil, enrollment.ErrWorkloadChanged
	}
	data, err := r.loadFunctionPackage(ctx, scope, *config.Function.Runtime.Package)
	if err != nil {
		return nil, err
	}
	registered, live := snapshot.Responses[0].GetResponseRange().Kvs[0], snapshot.Responses[1].GetResponseRange().Kvs[0]
	confirmed, err := r.client.Txn(ctx).If(keyUnchanged(registered), keyUnchanged(live), keyUnchanged(tasks[0]), keyUnchanged(entries.Kvs[0])).
		Then(clientv3.OpGet(taskKey, clientv3.WithCountOnly())).Commit()
	if err != nil || !confirmed.Succeeded {
		clear(data)
		if err == nil {
			err = enrollment.ErrWorkloadChanged
		}
		return nil, err
	}
	return data, nil
}

type functionPackageManifest struct {
	Package functions.PackageReference `json:"package"`
	Upload  string                     `json:"upload"`
}

type functionPackageStage struct {
	Scope   arm.SubscriptionScope      `json:"scope"`
	Package functions.PackageReference `json:"package"`
	Upload  string                     `json:"upload"`
}

func (r *Region) functionPackageKey(scope arm.SubscriptionScope, digest string) string {
	return r.armPrefix(scope) + "function-packages/" + digest
}

func (r *Region) functionPackageStageKey(upload string) string {
	return r.root + "/function-package-stages/" + upload
}

func (r *Region) functionPackageLeaseKey(upload string) string {
	return r.root + "/function-package-leases/" + upload
}

func (r *Region) functionPackageChunks(stage functionPackageStage) string {
	return r.armPrefix(stage.Scope) + "function-package-data/" + stage.Package.SHA256 + "/" + stage.Upload + "/"
}

func functionPackageChunkKey(prefix string, index int) string {
	return fmt.Sprintf("%s%06d", prefix, index)
}

// storeFunctionPackage publishes a manifest only after all immutable, sealed
// chunks have been written. An upload interrupted before publication is
// reclaimable after its staging lease expires.
func (r *Region) storeFunctionPackage(ctx context.Context, scope arm.SubscriptionScope, archive []byte) (functions.PackageReference, error) {
	if r.workloads == nil {
		return functions.PackageReference{}, arm.ErrContainerBusy
	}
	validated, err := functions.ReadZIPPackage(archive)
	if err != nil {
		return functions.PackageReference{}, err
	}
	reference := functions.PackageReference{SHA256: validated.Digest(), Bytes: len(archive)}
	manifestKey := r.functionPackageKey(scope, reference.SHA256)
	prior, err := r.client.Get(ctx, manifestKey)
	if err != nil {
		return functions.PackageReference{}, err
	}
	if len(prior.Kvs) == 1 {
		_, err := decodeFunctionPackageManifest(prior.Kvs[0].Value, reference)
		return reference, err
	}

	stage := functionPackageStage{Scope: scope, Package: reference, Upload: operationID()}
	stageKey, leaseKey := r.functionPackageStageKey(stage.Upload), r.functionPackageLeaseKey(stage.Upload)
	lease, err := r.client.Grant(ctx, 60)
	if err != nil {
		return functions.PackageReference{}, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()
		_, _ = r.client.Revoke(cleanup, lease.ID)
	}()
	marker, _ := json.Marshal(stage)
	registered, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(stageKey), "=", 0),
		clientv3.Compare(clientv3.Version(leaseKey), "=", 0)).Then(clientv3.OpPut(stageKey, string(marker)),
		clientv3.OpPut(leaseKey, stage.Upload, clientv3.WithLease(lease.ID))).Commit()
	if err != nil {
		return functions.PackageReference{}, err
	}
	if !registered.Succeeded {
		return functions.PackageReference{}, errors.New("the Functions package upload identifier is already in use")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		// The manifest transaction removes the marker on success. This
		// cleanup can only withdraw a stage that has yet to be published.
		_ = r.removeFunctionPackageStage(cleanup, stage, string(marker), false)
	}()
	leaseGuard := clientv3.Compare(clientv3.Value(leaseKey), "=", stage.Upload)
	prefix := r.functionPackageChunks(stage)
	for start, index := 0, 0; start < len(archive); start, index = start+functionPackageChunkSize, index+1 {
		key := functionPackageChunkKey(prefix, index)
		end := min(start+functionPackageChunkSize, len(archive))
		sealed := r.workloads.sealer.Seal(nil, nil, archive[start:end], []byte(key))
		put, err := r.client.Txn(ctx).If(leaseGuard).Then(clientv3.OpPut(key, string(sealed))).Commit()
		if err != nil {
			return functions.PackageReference{}, err
		}
		if !put.Succeeded {
			return functions.PackageReference{}, errors.New("the Functions package upload lease expired")
		}
	}
	manifest, _ := json.Marshal(functionPackageManifest{Package: reference, Upload: stage.Upload})
	published, err := r.client.Txn(ctx).If(leaseGuard, clientv3.Compare(clientv3.Version(manifestKey), "=", 0),
		clientv3.Compare(clientv3.Value(stageKey), "=", string(marker))).
		Then(clientv3.OpPut(manifestKey, string(manifest)), clientv3.OpDelete(stageKey), clientv3.OpDelete(leaseKey)).
		Else(clientv3.OpGet(manifestKey)).Commit()
	if err != nil {
		return functions.PackageReference{}, err
	}
	if published.Succeeded {
		return reference, nil
	}
	other := published.Responses[0].GetResponseRange().Kvs
	if len(other) != 1 {
		return functions.PackageReference{}, errors.New("the verified Functions package was not published")
	}
	_, err = decodeFunctionPackageManifest(other[0].Value, reference)
	return reference, err
}

func decodeFunctionPackageManifest(data []byte, reference functions.PackageReference) (functionPackageManifest, error) {
	var manifest functionPackageManifest
	if !reference.Valid() || json.Unmarshal(data, &manifest) != nil || manifest.Package != reference || !identifier.MatchString(manifest.Upload) {
		return functionPackageManifest{}, errors.New("invalid Functions package manifest")
	}
	return manifest, nil
}

func (r *Region) loadFunctionPackage(ctx context.Context, scope arm.SubscriptionScope, reference functions.PackageReference) ([]byte, error) {
	if r.workloads == nil || !reference.Valid() {
		return nil, errors.New("invalid Functions package reference")
	}
	entries, err := r.client.Get(ctx, r.functionPackageKey(scope, reference.SHA256))
	if err != nil {
		return nil, err
	}
	if len(entries.Kvs) != 1 {
		return nil, arm.ErrLinkedResourceMissing
	}
	manifest, err := decodeFunctionPackageManifest(entries.Kvs[0].Value, reference)
	if err != nil {
		return nil, err
	}
	stage := functionPackageStage{Scope: scope, Package: reference, Upload: manifest.Upload}
	prefix := r.functionPackageChunks(stage)
	count := (reference.Bytes + functionPackageChunkSize - 1) / functionPackageChunkSize
	archive := make([]byte, 0, reference.Bytes)
	for index := range count {
		key := functionPackageChunkKey(prefix, index)
		chunk, err := r.readFunctionPackageChunk(ctx, key, entries.Header.Revision, min(reference.Bytes-len(archive), functionPackageChunkSize))
		if err != nil {
			clear(archive)
			return nil, err
		}
		archive = append(archive, chunk...)
		clear(chunk)
	}
	hash := sha256.Sum256(archive)
	if hex.EncodeToString(hash[:]) != reference.SHA256 {
		clear(archive)
		return nil, errors.New("the Functions package failed its digest check")
	}
	return archive, nil
}

func (r *Region) readFunctionPackageChunk(ctx context.Context, key string, revision int64, size int) ([]byte, error) {
	values, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	if len(values.Kvs) != 1 || len(values.Kvs[0].Value) != size+r.workloads.sealer.Overhead() {
		return nil, errors.New("a Functions package chunk is missing or has the wrong length")
	}
	data, err := r.workloads.sealer.Open(nil, nil, values.Kvs[0].Value, []byte(key))
	if err != nil || len(data) != size {
		clear(data)
		return nil, errors.New("a Functions package chunk failed authentication")
	}
	return data, nil
}

func (r *Region) removeFunctionPackageStage(ctx context.Context, stage functionPackageStage, marker string, expiredOnly bool) error {
	key, lease := r.functionPackageStageKey(stage.Upload), r.functionPackageLeaseKey(stage.Upload)
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.Value(key), "=", marker)}
	if expiredOnly {
		guards = append(guards, clientv3.Compare(clientv3.Version(lease), "=", 0))
	}
	_, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpDelete(r.functionPackageChunks(stage), clientv3.WithPrefix()),
		clientv3.OpDelete(key), clientv3.OpDelete(lease)).Commit()
	return err
}

func (r *Region) reapFunctionPackageStages(ctx context.Context) error {
	prefix := r.functionPackageStageKey("")
	items, err := r.client.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithLimit(32), clientv3.WithSort(clientv3.SortByCreateRevision, clientv3.SortAscend))
	if err != nil {
		return err
	}
	var failures error
	for _, row := range items.Kvs {
		var stage functionPackageStage
		if json.Unmarshal(row.Value, &stage) != nil || !stage.Package.Valid() || !identifier.MatchString(stage.Upload) ||
			!identifier.MatchString(stage.Scope.TenantID) || !identifier.MatchString(stage.Scope.SubscriptionID) ||
			r.functionPackageStageKey(stage.Upload) != string(row.Key) {
			failures = errors.Join(failures, errors.New("invalid Functions package stage"))
			continue
		}
		failures = errors.Join(failures, r.removeFunctionPackageStage(ctx, stage, string(row.Value), true))
	}
	return failures
}
