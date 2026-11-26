package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	deployFunctionZIP   = "DeployFunctionZIP"
	rollbackFunctionZIP = "RollbackFunctionZIP"
)

type functionDeploymentPointer struct {
	Package   functions.PackageReference `json:"package"`
	Operation string                     `json:"operation"`
	Fallback  []byte                     `json:"fallback,omitempty"`
}

func functionDeploymentLatestKey(container string) string {
	return container + "/function-package-latest"
}

func (r *Region) DeployFunctionZIP(ctx context.Context, scope arm.SubscriptionScope, actor, host string, archive []byte) (functions.DeploymentStatus, error) {
	var result functions.DeploymentStatus
	address, err := r.functionDeploymentSite(ctx, scope, host)
	if err != nil {
		return result, err
	}
	reference, err := r.storeFunctionPackage(ctx, scope, archive)
	if err != nil {
		return result, err
	}
	key := r.containerKey(scope, address)
	for range 8 {
		resource, record, current, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return result, err
		}
		if current == nil || record.Desired == workload.Removed {
			return result, arm.ErrContainerMissing
		}
		config, err := r.decryptContainer(scope, record)
		if err != nil {
			return result, err
		}
		if config.Function == nil || config.Function.PublicHost != host {
			return result, arm.ErrContainerMissing
		}
		runtime := &config.Function.Runtime
		if current.Kind == deployFunctionZIP && current.Status != arm.OperationFailed &&
			runtime.Package != nil && *runtime.Package == reference {
			return projectZIPDeployment(current), nil
		}
		if current.Status == arm.OperationInProgress || record.Desired != workload.Running ||
			runtime.Request != nil && time.Now().Before(runtime.Request.ExpiresAt) {
			return result, arm.ErrContainerBusy
		}
		now := time.Now().UTC()
		job := arm.Operation{ID: operationID(), Kind: deployFunctionZIP, Group: address.Group,
			Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		previous := record.Config
		runtime.Package, runtime.Configuration, runtime.Request = &reference, job.ID, nil
		runtime.EmptySlot = false
		if err := r.sealFunctionConfig(scope, &record, config); err != nil {
			return result, err
		}
		record.Operation, record.Restart = job.ID, false
		projection := projectContainer(config, record, resource.CreatedAt, now, arm.OperationInProgress)
		opKey := r.operationKey(scope, job.ID)
		change, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.Version(opKey), "=", 0)).
			Then(putJSON(key, record), putJSON(opKey, job), putJSON(r.inventoryPrefix(scope)+address.Key(), projection),
				putJSON(functionDeploymentLatestKey(key), functionDeploymentPointer{Package: reference, Operation: job.ID, Fallback: previous}),
				r.containerAudit(scope, record, job, "write", now)).Commit()
		if err != nil {
			return result, err
		}
		if change.Succeeded {
			return projectZIPDeployment(&job), nil
		}
	}
	return result, arm.ErrContainerBusy
}

// finishZIPDeployment clears the rollback configuration after the worker
// confirms readiness, or atomically restores the prior configuration.
func (r *Region) finishZIPDeployment(ctx context.Context, scope arm.SubscriptionScope, record *containerRecord,
	config *workload.ContainerGroup, op arm.Operation, now time.Time) ([]clientv3.Cmp, []clientv3.Op, error) {
	key := functionDeploymentLatestKey(r.containerKey(scope, record.Address))
	found, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	if len(found.Kvs) != 1 {
		return nil, nil, errors.New("the ZIP deployment rollback record is missing")
	}
	item := found.Kvs[0]
	var latest functionDeploymentPointer
	if json.Unmarshal(item.Value, &latest) != nil || latest.Operation != op.ID || len(latest.Fallback) == 0 ||
		config.Function == nil || config.Function.Runtime.Package == nil || latest.Package != *config.Function.Runtime.Package {
		return nil, nil, errors.New("the ZIP deployment no longer matches its rollback record")
	}
	guards := []clientv3.Cmp{keyUnchanged(item)}
	var writes []clientv3.Op
	if op.Status == arm.OperationFailed {
		previous := *record
		previous.Config = latest.Fallback
		restored, err := r.decryptContainer(scope, previous)
		if err != nil {
			return nil, nil, err
		}
		if restored.Function == nil {
			return nil, nil, errors.New("the previous Function configuration is invalid")
		}
		recovery := arm.Operation{ID: operationID(), Kind: rollbackFunctionZIP, Group: record.Address.Group,
			Actor: op.Actor, Status: arm.OperationInProgress, StartedAt: now}
		restored.Function.Runtime.Configuration = recovery.ID
		restored.Function.Runtime.Request = nil
		if err := r.sealFunctionConfig(scope, record, restored); err != nil {
			return nil, nil, err
		}
		*config = restored
		record.Operation = recovery.ID
		recoveryKey := r.operationKey(scope, recovery.ID)
		guards = append(guards, clientv3.Compare(clientv3.Version(recoveryKey), "=", 0))
		writes = append(writes, putJSON(recoveryKey, recovery), r.containerAudit(scope, *record, recovery, "rollback", now))
	}
	latest.Fallback = nil
	writes = append(writes, putJSON(key, latest))
	return guards, writes, nil
}

func (r *Region) FunctionZIPStatus(ctx context.Context, scope arm.SubscriptionScope, host string) (functions.DeploymentStatus, error) {
	address, err := r.functionDeploymentSite(ctx, scope, host)
	if err != nil {
		return functions.DeploymentStatus{}, err
	}
	rows, err := r.client.Get(ctx, functionDeploymentLatestKey(r.containerKey(scope, address)))
	if err != nil {
		return functions.DeploymentStatus{}, err
	}
	var latest functionDeploymentPointer
	if len(rows.Kvs) != 1 {
		return functions.DeploymentStatus{}, arm.ErrContainerMissing
	}
	if json.Unmarshal(rows.Kvs[0].Value, &latest) != nil || !latest.Package.Valid() || !identifier.MatchString(latest.Operation) {
		return functions.DeploymentStatus{}, errors.New("invalid Functions ZIP deployment pointer")
	}
	operation, err := r.operationAt(ctx, scope, latest.Operation, rows.Header.Revision)
	if err != nil {
		return functions.DeploymentStatus{}, err
	}
	if operation == nil || operation.Kind != deployFunctionZIP || !strings.EqualFold(operation.Group, address.Group) {
		return functions.DeploymentStatus{}, errors.New("invalid Functions ZIP deployment operation")
	}
	return projectZIPDeployment(operation), nil
}

func (r *Region) functionDeploymentSite(ctx context.Context, scope arm.SubscriptionScope, host string) (arm.ResourceAddress, error) {
	rows, err := r.client.Get(ctx, r.functionNameKey(host))
	if err != nil {
		return arm.ResourceAddress{}, err
	}
	if len(rows.Kvs) != 1 {
		return arm.ResourceAddress{}, arm.ErrContainerMissing
	}
	key := string(rows.Kvs[0].Value)
	path, present := strings.CutPrefix(key, r.armPrefix(scope)+"containers/")
	group, resource, ok := strings.Cut(path, "/")
	address := arm.ResourceAddress{Group: group, Path: resource}
	if !present || !ok || !address.Valid() || r.containerKey(scope, address) != key {
		return arm.ResourceAddress{}, arm.ErrContainerMissing
	}
	current, err := r.GetInventoryResource(ctx, scope, "", address)
	if err != nil {
		return arm.ResourceAddress{}, err
	}
	if current == nil || current.Kind != functions.SiteKind {
		return arm.ResourceAddress{}, arm.ErrContainerMissing
	}
	return current.Address, nil
}

func projectZIPDeployment(operation *arm.Operation) functions.DeploymentStatus {
	switch operation.Status {
	case arm.OperationSucceeded:
		return functions.DeploymentStatus{ID: operation.ID, Status: functions.DeploymentSucceeded, Complete: true}
	case arm.OperationFailed:
		return functions.DeploymentStatus{ID: operation.ID, Status: functions.DeploymentFailed, Complete: true,
			Message: "The native Functions host did not activate the package."}
	default:
		return functions.DeploymentStatus{ID: operation.ID, Status: functions.DeploymentPending}
	}
}

func (r *Region) reconcileFunctionPackageStages(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := r.reapFunctionPackageStages(work)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("Functions package staging cleanup will retry", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
