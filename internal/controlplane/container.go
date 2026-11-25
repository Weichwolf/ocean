package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	createContainer  = "CreateContainerGroup"
	startContainer   = "StartContainerGroup"
	stopContainer    = "StopContainerGroup"
	restartContainer = "RestartContainerGroup"
	deleteContainer  = "DeleteContainerGroup"
)

type containerRecord struct {
	Address     arm.ResourceAddress `json:"address"`
	Reservation Reservation         `json:"reservation"`
	Volume      *volumeBinding      `json:"volume,omitempty"`
	PublicIP    netip.Addr          `json:"publicIp,omitzero"`
	Port        int                 `json:"port"`
	Config      []byte              `json:"config"`
	Desired     string              `json:"desired"`
	Observed    string              `json:"observed"`
	Operation   string              `json:"operation"`
	Restart     bool                `json:"restart,omitempty"`
}

func (c containerRecord) endpoint() netip.Addr {
	if c.Reservation.PrivateIPv4.IsValid() {
		return c.Reservation.PrivateIPv4
	}
	return c.PublicIP
}

func (r *Region) containerPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "containers/" + strings.ToLower(group) + "/"
}

func (r *Region) containerKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "containers/" + address.Key()
}

func (r *Region) hostContainerPrefix(host string) string {
	return r.hostKey("containers", host) + "/"
}

func (r *Region) hostContainerKey(scope arm.SubscriptionScope, host, id string) string {
	return r.hostContainerPrefix(host) + scope.TenantID + "/" + scope.SubscriptionID + "/" + id
}

func (r *Region) containerBinding(scope arm.SubscriptionScope, record containerRecord) []byte {
	return []byte(r.containerKey(scope, record.Address) + "/" + record.Reservation.Generation)
}

func (r *Region) decryptContainer(scope arm.SubscriptionScope, record containerRecord) (workload.ContainerGroup, error) {
	data, err := r.workloads.sealer.Open(nil, nil, record.Config, r.containerBinding(scope, record))
	if err != nil {
		return workload.ContainerGroup{}, errors.New("cannot decrypt workload configuration")
	}
	defer clear(data)
	var input workload.ContainerGroup
	if err := json.Unmarshal(data, &input); err != nil {
		return workload.ContainerGroup{}, errors.New("cannot decode workload configuration")
	}
	return input, nil
}

const replicaControllerActor = "ocean-replica-controller"

type replicaAdmission struct {
	spreadSet string
	key       string
	revision  int64
}

func (r *Region) CreateContainerGroup(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	wanted workload.ContainerGroup) (arm.InventoryResource, *arm.Operation, bool, error) {
	return r.createContainerGroup(ctx, scope, actor, address, wanted, replicaAdmission{})
}

func (r *Region) createContainerGroup(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	wanted workload.ContainerGroup, replica replicaAdmission) (arm.InventoryResource, *arm.Operation, bool, error) {
	key := r.containerKey(scope, address)
	if resource, op, found, err := r.retryContainerCreate(ctx, scope, address, wanted, replica.spreadSet); found || err != nil {
		return resource, op, false, err
	}
	cpu, memory, ok := wanted.Properties.Containers[0].Properties.Resources.Requests.Limits()
	if !ok {
		return arm.InventoryResource{}, nil, false, workload.ErrInvalidContainer
	}
	request := PlacementRequest{ID: fmt.Sprintf("%x", sha256.Sum256([]byte(key)))[:48], Cell: r.cell, Role: "compute", NeedsContainerNetwork: true,
		Resources: enrollment.Capacity{CPUMillis: cpu, MemoryMiB: memory}, SpreadSet: replica.spreadSet}
	if len(wanted.Properties.Volumes) != 0 {
		if r.storage == nil {
			return arm.InventoryResource{}, nil, false, arm.ErrStorageAccess
		}
		request.NeedsStorage = true
	}
	if len(wanted.Properties.SubnetIDs) == 1 {
		request.SubnetID = wanted.Properties.SubnetIDs[0].ID
	}
	var projection arm.InventoryResource
	var operation *arm.Operation
	data, err := json.Marshal(wanted)
	if err != nil {
		return projection, nil, false, err
	}
	defer clear(data)
	_, err = r.reservePlacement(ctx, scope, request, func(ctx context.Context, res Reservation) ([]clientv3.Cmp, []clientv3.Op, error) {
		groupKey := r.groupPrefix(scope) + strings.ToLower(address.Group)
		groups, err := r.client.Get(ctx, groupKey)
		if err != nil {
			return nil, nil, err
		}
		if len(groups.Kvs) != 1 {
			return nil, nil, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groups.Kvs[0].Value, strings.ToLower(address.Group))
		if err != nil {
			return nil, nil, err
		}
		if group.DeleteOperation != "" {
			return nil, nil, arm.ErrGroupInUse
		}
		address.Group = group.Name
		now := time.Now().UTC()
		op := arm.Operation{ID: operationID(), Kind: createContainer, Group: group.Name, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		record := containerRecord{Address: address, Reservation: res, Port: wanted.Properties.IPAddress.Ports[0].Port,
			Desired: workload.Running, Operation: op.ID}
		if replica.spreadSet != "" {
			record.Desired = workload.Stopped
		}
		record.Config = r.workloads.sealer.Seal(nil, nil, data, r.containerBinding(scope, record))
		invKey := r.inventoryPrefix(scope) + address.Key()
		hostKey := r.hostContainerKey(scope, res.HostID, res.ID)
		opKey := r.operationKey(scope, op.ID)
		checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(groupKey), "=", groups.Kvs[0].ModRevision),
			clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(invKey), "=", 0),
			clientv3.Compare(clientv3.Version(hostKey), "=", 0), clientv3.Compare(clientv3.Version(opKey), "=", 0)}
		if replica.key != "" {
			checks = append(checks, clientv3.Compare(clientv3.ModRevision(replica.key), "=", replica.revision))
		}
		var writes []clientv3.Op
		if res.SubnetID == "" {
			pool, revision, err := r.readPublicIPPool(ctx, 0)
			if err != nil {
				return nil, nil, err
			}
			record.PublicIP, err = takePublicIPv4(pool, key)
			if err != nil {
				return nil, nil, err
			}
			check, write := r.publicIPPoolUpdate(pool, revision)
			checks, writes = append(checks, check), append(writes, write)
		} else {
			conditions, updates, err := r.claimContainerNetwork(ctx, scope, key, res.SubnetID, workloadDelegation(wanted))
			if err != nil {
				return nil, nil, err
			}
			checks, writes = append(checks, conditions...), append(writes, updates...)
		}
		if request.NeedsStorage {
			volume, conditions, updates, err := r.claimVolume(ctx, scope, record, *wanted.Properties.Volumes[0].AzureFile)
			if err != nil {
				return nil, nil, err
			}
			record.Volume = &volume
			checks, writes = append(checks, conditions...), append(writes, updates...)
		}
		projection = projectContainer(wanted, record, now, now, arm.OperationInProgress)
		if wanted.Function != nil {
			nameKey := r.functionNameKey(wanted.Function.PublicHost)
			checks = append(checks, clientv3.Compare(clientv3.Version(nameKey), "=", 0))
			writes = append(writes, clientv3.OpPut(nameKey, key))
			conditions, updates, err := r.inventoryReferenceChanges(ctx, scope, address, nil, &projection, groups.Header.Revision, nil)
			if err != nil {
				return nil, nil, err
			}
			checks, writes = append(checks, conditions...), append(writes, updates...)
		}
		operation = &op
		writes = append(writes, putJSON(key, record), putJSON(invKey, projection), clientv3.OpPut(hostKey, key), putJSON(opKey, op),
			r.containerAudit(scope, record, op, "write", now))
		return checks, writes, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrQuotaExceeded):
			err = arm.ErrContainerQuota
		case errors.Is(err, ErrNoEligibleHost):
			err = arm.ErrContainerCapacity
		case errors.Is(err, ErrReservationChanged):
			err = arm.ErrContainerChanged
		case errors.Is(err, ErrPlacementSubnetUnavailable), errors.Is(err, ErrSubnetAddressExhausted):
			err = arm.ErrLinkedResourceMissing
		}
		return arm.InventoryResource{}, nil, false, err
	}
	// Load the committed revision, which may have been written by a replica
	// racing this request or completed by the worker during this request.
	resource, op, found, err := r.retryContainerCreate(ctx, scope, address, wanted, replica.spreadSet)
	if !found && err == nil {
		err = arm.ErrContainerMissing
	}
	return resource, op, operation != nil && op != nil && operation.ID == op.ID, err
}

func (r *Region) retryContainerCreate(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress,
	wanted workload.ContainerGroup, spreadSet string) (arm.InventoryResource, *arm.Operation, bool, error) {
	resource, record, op, _, err := r.readContainer(ctx, scope, address)
	if err != nil || op == nil {
		return resource, op, op != nil, err
	}
	if record.Reservation.SpreadSet != spreadSet {
		return resource, op, true, arm.ErrContainerChanged
	}
	prior, err := r.decryptContainer(scope, record)
	if err != nil {
		return resource, op, true, err
	}
	if prior.Function != nil && wanted.Function != nil {
		wanted.Function.Runtime.MasterKey = prior.Function.Runtime.MasterKey
		wanted.Function.Runtime.Configuration = prior.Function.Runtime.Configuration
		wanted.Function.Runtime.Request = prior.Function.Runtime.Request
	}
	if !reflect.DeepEqual(prior, wanted) {
		return resource, op, true, arm.ErrContainerChanged
	}
	if record.Desired == workload.Removed {
		return resource, op, true, arm.ErrContainerBusy
	}
	if op.Kind != createContainer || op.Status == arm.OperationSucceeded {
		op = nil
	}
	return resource, op, true, nil
}

func projectContainer(input workload.ContainerGroup, record containerRecord, created, changed time.Time, status string) arm.InventoryResource {
	if input.Function != nil {
		return projectFunction(input, record, created, changed, status)
	}
	p := input.Properties
	container := p.Containers[0]
	properties := container.Properties
	variables := make([]workload.Variable, 0, len(properties.EnvironmentVariables))
	for _, variable := range properties.EnvironmentVariables {
		variables = append(variables, workload.Variable{Name: variable.Name, Value: variable.Value})
	}
	properties.EnvironmentVariables = variables
	state := record.Observed
	if state == "" {
		state = "Pending"
	}
	volumes := make([]workload.Volume, 0, len(p.Volumes))
	for _, volume := range p.Volumes {
		public := *volume.AzureFile
		public.StorageAccountKey = ""
		volumes = append(volumes, workload.Volume{Name: volume.Name, AzureFile: &public})
	}
	data, _ := json.Marshal(map[string]any{"volumes": volumes, "osType": p.OSType, "restartPolicy": p.RestartPolicy, "sku": p.SKU, "priority": p.Priority,
		"provisioningState": status, "instanceView": map[string]string{"state": state},
		"ipAddress": map[string]any{"type": p.IPAddress.Type, "ip": record.endpoint().String(), "ports": p.IPAddress.Ports},
		"subnetIds": p.SubnetIDs, "containers": []any{map[string]any{"name": container.Name, "properties": struct {
			workload.ContainerProperties
			InstanceView map[string]any `json:"instanceView"`
		}{properties, map[string]any{"currentState": map[string]string{"state": state}}}}},
	})
	return arm.InventoryResource{Address: record.Address, APIVersion: workload.ContainerGroupAPIVersion, Location: input.Location,
		Tags: input.Tags, Properties: data, ProvisioningState: status, CreatedAt: created, ChangedAt: changed}
}

func (r *Region) readContainer(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress) (arm.InventoryResource, containerRecord, *arm.Operation, int64, error) {
	var inventory arm.InventoryResource
	var record containerRecord
	key := r.containerKey(scope, address)
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(key), clientv3.OpGet(r.inventoryPrefix(scope)+address.Key())).Commit()
	if err != nil || len(read.Responses[0].GetResponseRange().Kvs) == 0 {
		return inventory, record, nil, 0, err
	}
	item := read.Responses[0].GetResponseRange().Kvs[0]
	if err := json.Unmarshal(item.Value, &record); err != nil || record.Address.Key() != address.Key() {
		return inventory, record, nil, 0, errors.New("invalid workload record")
	}
	resources := read.Responses[1].GetResponseRange().Kvs
	if len(resources) != 1 {
		return inventory, record, nil, 0, errors.New("workload inventory record is missing")
	}
	inventory, err = decodeInventoryResource(resources[0].Value, address.Key())
	if err != nil {
		return inventory, record, nil, 0, err
	}
	op, err := r.operationAt(ctx, scope, record.Operation, read.Header.Revision)
	return inventory, record, op, item.ModRevision, err
}

func (r *Region) operationAt(ctx context.Context, scope arm.SubscriptionScope, operation string, revision int64) (*arm.Operation, error) {
	ops, err := r.client.Get(ctx, r.operationKey(scope, operation), clientv3.WithRev(revision))
	if err != nil {
		return nil, err
	}
	if len(ops.Kvs) != 1 {
		return nil, errors.New("operation record is missing")
	}
	return decodeOperation(ops.Kvs[0].Value, operation)
}

func (r *Region) MutateContainerGroup(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress, action string) (*arm.Operation, error) {
	return r.mutateContainerGroup(ctx, scope, actor, address, action, replicaAdmission{})
}

func (r *Region) mutateContainerGroup(ctx context.Context, scope arm.SubscriptionScope, actor string, address arm.ResourceAddress,
	action string, replica replicaAdmission) (*arm.Operation, error) {
	kind, desired := "", workload.Running
	switch action {
	case "start":
		kind = startContainer
	case "restart":
		kind = restartContainer
	case "stop":
		kind, desired = stopContainer, workload.Stopped
	case "delete":
		kind, desired = deleteContainer, workload.Removed
	default:
		return nil, workload.ErrInvalidContainer
	}
	key := r.containerKey(scope, address)
	for range 8 {
		prior, record, op, revision, err := r.readContainer(ctx, scope, address)
		if err != nil {
			return nil, err
		}
		if op == nil {
			if action == "delete" {
				return nil, nil
			}
			return nil, arm.ErrContainerMissing
		}
		if record.Reservation.SpreadSet != replica.spreadSet {
			return nil, arm.ErrContainerChanged
		}
		if op.Status == arm.OperationInProgress {
			if op.Kind == kind {
				return op, nil
			}
			if action != "delete" {
				return nil, arm.ErrContainerBusy
			}
		}
		if action != "restart" && desired == record.Observed && op.Status == arm.OperationSucceeded {
			return nil, nil
		}
		now := time.Now().UTC()
		job := arm.Operation{ID: operationID(), Kind: kind, Group: record.Address.Group, Actor: actor, Status: arm.OperationInProgress, StartedAt: now}
		record.Desired, record.Operation, record.Restart = desired, job.ID, action == "restart"
		input, err := r.decryptContainer(scope, record)
		if err != nil {
			return nil, err
		}
		if input.Function != nil && input.Function.Runtime.Request != nil && now.Before(input.Function.Runtime.Request.ExpiresAt) {
			return nil, arm.ErrContainerBusy
		}
		projection := projectContainer(input, record, prior.CreatedAt, now, arm.OperationInProgress)
		newKey := r.operationKey(scope, job.ID)
		writes := []clientv3.Op{putJSON(key, record), putJSON(newKey, job), putJSON(r.inventoryPrefix(scope)+address.Key(), projection),
			r.containerAudit(scope, record, job, action, now)}
		if op.Status == arm.OperationInProgress {
			op.Status, op.FinishedAt = arm.OperationFailed, &now
			writes = append(writes, putJSON(r.operationKey(scope, op.ID), op))
		}
		checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", revision),
			clientv3.Compare(clientv3.Version(newKey), "=", 0)}
		if replica.key != "" {
			checks = append(checks, clientv3.Compare(clientv3.ModRevision(replica.key), "=", replica.revision))
		}
		result, err := r.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return &job, err
		}
	}
	return nil, arm.ErrContainerBusy
}

func putJSON(key string, value any) clientv3.Op {
	data, _ := json.Marshal(value)
	return clientv3.OpPut(key, string(data))
}

func (r *Region) containerAudit(scope arm.SubscriptionScope, record containerRecord, op arm.Operation, action string, now time.Time) clientv3.Op {
	kind := record.Address.Path[:strings.LastIndexByte(record.Address.Path, '/')]
	return r.auditOp(scope, arm.AuditEvent{Time: now, Actor: op.Actor, Action: kind + "/" + action,
		Target: record.Address.ID(scope), Outcome: op.Status})
}

func (r *Region) ContainerLogs(ctx context.Context, scope arm.SubscriptionScope, address arm.ResourceAddress, reader string, tail int) (string, error) {
	read, err := r.readForGroup(ctx, scope, reader, address.Group, clientv3.OpGet(r.containerKey(scope, address)+"/logs"))
	if err != nil || len(read.Kvs) == 0 {
		return "", err
	}
	lines := strings.SplitAfter(string(read.Kvs[0].Value), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines[max(0, len(lines)-tail):], ""), nil
}
