package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) DeployVPNConnection(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.VPNConnectionDeployment, commit bool) (arm.VPNChangeResult, error) {
	var result arm.VPNChangeResult
	if r.ipsec == nil {
		return result, arm.ErrGatewayExecutionUnavailable
	}
	if len(desired.SharedKey) < 16 || len(desired.SharedKey) > 128 {
		return result, arm.InvalidDeployment{Cause: errors.New("the shared key must contain 16 to 128 bytes")}
	}
	groupName := strings.ToLower(desired.Address.Group)
	groupKey := r.groupPrefix(scope) + groupName
	inventory := r.inventoryPrefix(scope)
	recordKey := r.vpnKey(scope, desired.VirtualGateway)
	connectionKey, deploymentKey := inventory+desired.Address.Key(), inventory+desired.Deployment.Key()
	for range 8 {
		read, err := r.client.Txn(ctx).Then(clientv3.OpGet(groupKey), clientv3.OpGet(recordKey),
			clientv3.OpGet(inventory+desired.VirtualGateway.Key()), clientv3.OpGet(inventory+desired.LocalGateway.Key()),
			clientv3.OpGet(connectionKey), clientv3.OpGet(deploymentKey)).Commit()
		if err != nil {
			return result, err
		}
		groups, records := read.Responses[0].GetResponseRange().Kvs, read.Responses[1].GetResponseRange().Kvs
		virtual, local := read.Responses[2].GetResponseRange().Kvs, read.Responses[3].GetResponseRange().Kvs
		connections, deployments := read.Responses[4].GetResponseRange().Kvs, read.Responses[5].GetResponseRange().Kvs
		if len(groups) != 1 {
			return result, arm.ErrGroupMissing
		}
		group, err := decodeGroup(groups[0].Value, groupName)
		if err != nil {
			return result, err
		}
		if group.DeleteOperation != "" {
			return result, arm.ErrGroupDeleting
		}
		if len(records) != 1 || len(virtual) != 1 || len(local) != 1 {
			return result, arm.ErrLinkedResourceMissing
		}
		record, err := r.decodeIPsecGateway(records[0], recordKey)
		if err != nil {
			return result, err
		}
		desired.Address.Group, desired.Deployment.Group = group.Name, group.Name
		desired.VirtualGateway = record.Gateway
		vgw, err := decodeInventoryResource(virtual[0].Value, record.Gateway.Key())
		if err != nil {
			return result, err
		}
		if vgw.ProvisioningState != arm.OperationSucceeded || record.Kind == deleteIPsecGateway || record.Kind == deleteIPsecConnection {
			return result, arm.ErrGatewayExecutionUnavailable
		}
		localGateway, err := decodeInventoryResource(local[0].Value, desired.LocalGateway.Key())
		if err != nil {
			return result, err
		}
		desired.LocalGateway = localGateway.Address
		peer, err := ipsecInventoryPeer(localGateway)
		if err != nil {
			return result, err
		}
		for _, prefix := range record.VNetRanges {
			if prefix.Contains(peer.Endpoint) || slices.ContainsFunc(peer.Prefixes, prefix.Overlaps) {
				return result, arm.InvalidDeployment{Cause: errors.New("the IPsec peer overlaps the virtual network")}
			}
		}
		if err := network.ValidateIPsecNetworks(record.PublicIPv4, peer.Endpoint, []netip.Prefix{record.InsideIPv4.Masked()},
			peer.Prefixes, r.ipsec.protected); err != nil {
			return result, arm.InvalidDeployment{Cause: err}
		}
		if !commit {
			return arm.VPNChangeResult{Resource: ipsecDeploymentResource(scope, desired.Deployment, desired.Address,
				desired.Location, arm.OperationSucceeded, nil)}, nil
		}
		if len(deployments) != 0 {
			if err := verifyIPsecDeployment(scope, desired, deployments[0]); err != nil {
				return result, err
			}
		}
		guards := []clientv3.Cmp{keyUnchanged(groups[0]), keyUnchanged(records[0]), keyUnchanged(virtual[0]), keyUnchanged(local[0])}
		if record.Connection != nil {
			var completed bool
			result, completed, err = r.retryIPsecConnection(ctx, recordKey, record, actor, desired, connections, deployments, guards, read.Header.Revision)
			if err != nil || completed {
				return result, err
			}
			continue
		}
		if len(connections) != 0 {
			return result, arm.InvalidDeployment{Cause: errors.New("the IPsec connection name is already in use")}
		}
		hostGuards, err := r.ipsecHostAvailability(ctx, record.Host, read.Header.Revision)
		if err != nil {
			return result, err
		}
		op := newIPsecOperation(createIPsecConnection, group.Name, actor)
		connection := ipsecConnectionResource(scope, desired)
		deployment := ipsecDeploymentResource(scope, desired.Deployment, desired.Address, desired.Location, "Running", nil)
		refGuards, refWrites, err := r.inventoryReferenceChanges(ctx, scope, desired.Address, nil, &connection, read.Header.Revision, nil)
		if err != nil {
			return result, err
		}
		guards = append(guards, hostGuards...)
		guards = append(guards, refGuards...)
		guards = append(guards, clientv3.Compare(clientv3.Version(connectionKey), "=", 0))
		opKey := r.operationKey(scope, op.ID)
		guards = append(guards, clientv3.Compare(clientv3.Version(opKey), "=", 0))
		deploymentGuard, deploymentWrite, err := ipsecDeploymentWrite(deploymentKey, deployments, &deployment, op.StartedAt)
		if err != nil {
			return result, err
		}
		record.Generation, record.Kind = op.ID, op.Kind
		record.Connection = &vpnConnectionRecord{Resource: desired.Address, Local: desired.LocalGateway,
			Deployments: []arm.ResourceAddress{desired.Deployment}, Peer: peer,
			KeyEnvelope: r.ipsec.sealer.Seal(nil, nil, desired.SharedKey, ipsecEnvelopeContext(recordKey, desired.Address))}
		writes := append(refWrites, putIPsecRecord(recordKey, record), putIPsecOperation(opKey, op), deploymentWrite,
			inventoryPut(connectionKey, nil, &connection, op.StartedAt), clientv3.OpDelete(r.vpnObservationKey(record.Slot)),
			r.ipsecAudit(scope, op, desired.Address, "Accepted"))
		committed, err := r.client.Txn(ctx).If(append(guards, deploymentGuard)...).Then(writes...).Commit()
		if err != nil {
			return result, err
		}
		if committed.Succeeded {
			return arm.VPNChangeResult{Resource: deployment, Operation: &op, Created: len(deployments) == 0}, nil
		}
	}
	return result, arm.ErrGatewayExecutionUnavailable
}

func ipsecInventoryPeer(gateway arm.InventoryResource) (network.IPsecPeer, error) {
	var properties struct {
		Endpoint netip.Addr `json:"gatewayIpAddress"`
		Space    struct {
			Prefixes []netip.Prefix `json:"addressPrefixes"`
		} `json:"localNetworkAddressSpace"`
	}
	if gateway.APIVersion != arm.VPNLocalGatewayAPIVersion || gateway.ProvisioningState != arm.OperationSucceeded ||
		json.Unmarshal(gateway.Properties, &properties) != nil {
		return network.IPsecPeer{}, arm.ErrLinkedResourceMissing
	}
	peer := network.IPsecPeer{Endpoint: properties.Endpoint, Prefixes: properties.Space.Prefixes}
	return peer, peer.Validate()
}

func (r *Region) decodeIPsecGateway(entry *mvccpb.KeyValue, expectedKey string) (vpnGatewayRecord, error) {
	var record vpnGatewayRecord
	if err := json.Unmarshal(entry.Value, &record); err != nil || r.vpnKey(record.Scope, record.Gateway) != expectedKey ||
		string(entry.Key) != expectedKey || !identifier.MatchString(record.Generation) || len(record.VNetRanges) == 0 ||
		!slices.ContainsFunc(r.ipsec.slots, func(slot ipsecSlot) bool {
			return slot.Name == record.Slot && slot.Host == record.Host && slot.scope() == record.Scope &&
				slot.PublicIPv4 == record.PublicIPv4 && slot.InsideIPv4 == record.InsideIPv4
		}) {
		return vpnGatewayRecord{}, errors.New("invalid regional IPsec gateway reservation")
	}
	return record, nil
}

func ipsecEnvelopeContext(key string, connection arm.ResourceAddress) []byte {
	return []byte(key + "/connections/" + connection.Key())
}

func ipsecConnectionResource(scope arm.SubscriptionScope, desired arm.VPNConnectionDeployment) arm.InventoryResource {
	properties, _ := json.Marshal(map[string]any{
		"connectionType": "IPsec", "connectionProtocol": "IKEv2", "enableBgp": false, "routingWeight": 10,
		"usePolicyBasedTrafficSelectors": false, "provisioningState": "Updating", "connectionStatus": "NotConnected",
		"virtualNetworkGateway1": network.ResourceReference{ID: desired.VirtualGateway.ID(scope)},
		"localNetworkGateway2":   network.ResourceReference{ID: desired.LocalGateway.ID(scope)},
	})
	return arm.InventoryResource{Address: desired.Address, Location: desired.Location, APIVersion: arm.VPNGatewayAPIVersion,
		Tags: desired.Tags, Properties: properties, ProvisioningState: "Updating", References: []arm.ResourceAddress{desired.VirtualGateway, desired.LocalGateway}}
}

func ipsecDeploymentResource(scope arm.SubscriptionScope, deployment, connection arm.ResourceAddress,
	location, state string, output *arm.InventoryResource) arm.InventoryResource {
	properties := map[string]any{"provisioningState": state, "mode": "Incremental",
		"outputResources": []network.ResourceReference{{ID: connection.ID(scope)}}}
	if output != nil {
		model := map[string]any{"id": connection.ID(scope), "type": arm.VPNConnectionType, "location": output.Location,
			"name": connection.Path[strings.LastIndexByte(connection.Path, '/')+1:], "tags": output.Tags, "properties": output.Properties}
		properties["outputs"] = map[string]any{"resource": map[string]any{"type": "Object", "value": model}}
	}
	encoded, _ := json.Marshal(properties)
	return arm.InventoryResource{Address: deployment, Location: location, APIVersion: arm.ApplicationGatewayDeploymentVersion,
		ProvisioningState: state, Properties: encoded}
}

func verifyIPsecDeployment(scope arm.SubscriptionScope, desired arm.VPNConnectionDeployment, stored *mvccpb.KeyValue) error {
	resource, err := decodeInventoryResource(stored.Value, desired.Deployment.Key())
	if err != nil {
		return err
	}
	var properties struct {
		Outputs []network.ResourceReference `json:"outputResources"`
	}
	if resource.APIVersion != arm.ApplicationGatewayDeploymentVersion ||
		json.Unmarshal(resource.Properties, &properties) != nil || len(properties.Outputs) != 1 ||
		!strings.EqualFold(properties.Outputs[0].ID, desired.Address.ID(scope)) {
		return arm.InvalidDeployment{Cause: errors.New("the deployment name is already in use")}
	}
	return nil
}

func ipsecDeploymentWrite(key string, existing []*mvccpb.KeyValue, deployment *arm.InventoryResource, now time.Time) (clientv3.Cmp, clientv3.Op, error) {
	if len(existing) == 0 {
		return clientv3.Compare(clientv3.Version(key), "=", 0), inventoryPut(key, nil, deployment, now), nil
	}
	previous, err := decodeInventoryResource(existing[0].Value, deployment.Address.Key())
	if err != nil {
		return clientv3.Cmp{}, clientv3.Op{}, err
	}
	deployment.Address = previous.Address
	return keyUnchanged(existing[0]), inventoryPut(key, &previous, deployment, now), nil
}

func (r *Region) retryIPsecConnection(ctx context.Context, recordKey string, record vpnGatewayRecord, actor string,
	desired arm.VPNConnectionDeployment, connections, deployments []*mvccpb.KeyValue, guards []clientv3.Cmp, revision int64) (arm.VPNChangeResult, bool, error) {
	var result arm.VPNChangeResult
	entry := record.Connection
	if entry.Resource.Key() != desired.Address.Key() || entry.Local.Key() != desired.LocalGateway.Key() || len(connections) != 1 {
		return result, false, arm.InvalidDeployment{Cause: errors.New("the virtual gateway already has an IPsec connection")}
	}
	connection, err := decodeInventoryResource(connections[0].Value, entry.Resource.Key())
	if err != nil {
		return result, false, err
	}
	secret, err := r.ipsec.sealer.Open(nil, nil, entry.KeyEnvelope, ipsecEnvelopeContext(recordKey, entry.Resource))
	if err != nil {
		return result, false, errors.New("the IPsec shared key envelope could not be opened")
	}
	defer clear(secret)
	if subtle.ConstantTimeCompare(secret, desired.SharedKey) != 1 || !maps.Equal(connection.Tags, desired.Tags) {
		return result, false, arm.InvalidDeployment{Cause: errors.New("updating an existing IPsec connection is unsupported")}
	}
	operation, err := r.ipsecOperationAt(ctx, record.Scope, record.Generation, revision)
	if err != nil {
		return result, false, err
	}
	if len(deployments) != 0 {
		resource, err := decodeInventoryResource(deployments[0].Value, desired.Deployment.Key())
		if err != nil {
			return result, false, err
		}
		result.Resource = resource
		if operation.Status == arm.OperationInProgress {
			result.Operation = operation
		}
		return result, true, nil
	}
	writes := []clientv3.Op{}
	result.Created = true
	if operation.Status == arm.OperationInProgress {
		if len(entry.Deployments) >= 8 {
			return result, false, arm.ErrGatewayExecutionUnavailable
		}
		entry.Deployments = append(entry.Deployments, desired.Deployment)
		writes = append(writes, putIPsecRecord(recordKey, record))
		result.Operation = operation
		result.Resource = ipsecDeploymentResource(record.Scope, desired.Deployment, entry.Resource, desired.Location, "Running", nil)
	} else {
		result.Resource = ipsecDeploymentResource(record.Scope, desired.Deployment, entry.Resource, desired.Location, operation.Status, &connection)
	}
	key := r.inventoryPrefix(record.Scope) + desired.Deployment.Key()
	now := time.Now().UTC()
	guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0), keyUnchanged(connections[0]))
	writes = append(writes, inventoryPut(key, nil, &result.Resource, now), r.auditOp(record.Scope, arm.AuditEvent{
		Time: now, Actor: actor, Action: "Microsoft.Resources/deployments/write", Target: desired.Deployment.ID(record.Scope),
		Outcome: result.Resource.ProvisioningState}))
	committed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	return result, err == nil && committed.Succeeded, err
}
