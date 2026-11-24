package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const createApplicationGateway = "CreateApplicationGateway"
const deleteApplicationGateway = "DeleteApplicationGateway"

type gatewayRecord struct {
	Scope                arm.SubscriptionScope `json:"scope"`
	Resource             arm.ResourceAddress   `json:"resource"`
	Deployment           arm.ResourceAddress   `json:"deployment"`
	Subnet               arm.ResourceAddress   `json:"subnet"`
	PublicIP             arm.ResourceAddress   `json:"publicIp"`
	SubnetLock           string                `json:"subnetLock"`
	Slot                 string                `json:"slot"`
	Hosts                []string              `json:"hosts"`
	OperationID          string                `json:"operationId"`
	DeleteOperation      string                `json:"deleteOperation,omitempty"`
	RequestDigest        string                `json:"requestDigest"`
	Hostname             string                `json:"hostname"`
	PublicIPv4           netip.Addr            `json:"publicIPv4"`
	Backend              netip.AddrPort        `json:"backend"`
	BackendSubnet        netip.Prefix          `json:"backendSubnet"`
	EncryptedCertificate []byte                `json:"encryptedCertificate"`
	Site                 *wireGuardDesired     `json:"site,omitempty"`
}

type wireGuardDesired struct {
	Peers             []network.SitePeer `json:"peers"`
	LocalPrefixes     []netip.Prefix     `json:"localPrefixes"`
	CustomerPrefixes  []netip.Prefix     `json:"customerPrefixes"`
	ProtectedPrefixes []netip.Prefix     `json:"protectedPrefixes"`
}

func (record gatewayRecord) generation() string {
	if record.DeleteOperation != "" {
		return record.DeleteOperation
	}
	return record.OperationID
}

func (r *Region) gatewayRecordKey(scope arm.SubscriptionScope, address arm.ResourceAddress) string {
	return r.armPrefix(scope) + "application-gateways/" + address.Key()
}

func (r *Region) gatewaySlotKey(slot string) string {
	return r.root + "/application-gateways/slots/" + slot
}

func (r *Region) gatewayTaskKey(host, slot string) string {
	return r.root + "/application-gateways/hosts/" + host + "/" + slot
}

func (r *Region) beginApplicationGateway(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.ApplicationGatewayDeployment, target applicationGatewayNetwork) (arm.ApplicationGatewayDeploymentResult, error) {
	var result arm.ApplicationGatewayDeploymentResult
	if r.gatewayControl == nil {
		return result, arm.ErrGatewayExecutionUnavailable
	}
	recordKey := r.gatewayRecordKey(scope, desired.ResourceAddress)
	requestDigest, err := applicationGatewayDigest(desired)
	if err != nil {
		return result, err
	}
	existing, err := r.client.Get(ctx, recordKey, clientv3.WithRev(target.Revision))
	if err != nil {
		return result, err
	}
	if len(existing.Kvs) == 1 {
		var saved gatewayRecord
		if err := json.Unmarshal(existing.Kvs[0].Value, &saved); err != nil || saved.Scope != scope ||
			saved.Resource.Key() != desired.ResourceAddress.Key() {
			return result, errors.New("invalid Application Gateway desired state")
		}
		if saved.DeleteOperation != "" || saved.Deployment.Key() != desired.Deployment.Key() || saved.RequestDigest != requestDigest {
			return result, arm.ErrGatewayNameInUse
		}
		return r.retryApplicationGateway(ctx, scope, saved, target.Revision)
	}
	subnetLock, err := r.client.Get(ctx, target.SubnetLock, clientv3.WithCountOnly(), clientv3.WithRev(target.Revision))
	if err != nil {
		return result, err
	}
	if subnetLock.Count != 0 {
		return result, arm.ErrGatewaySubnetInUse
	}
	slot, slotGuards, err := r.availableGatewaySlot(ctx, target.Revision, r.gatewayControl.slots)
	if err != nil {
		return result, err
	}
	desired.ResourceAddress.Group, desired.Deployment.Group = target.Group, target.Group
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: createApplicationGateway, Actor: actor, Group: target.Group,
		Status: arm.OperationInProgress, StartedAt: now}
	record := gatewayRecord{
		Scope: scope, Resource: desired.ResourceAddress, Deployment: desired.Deployment, PublicIP: desired.PublicIP,
		Subnet: desired.Subnet, SubnetLock: target.SubnetLock, Slot: slot.Name, Hosts: slot.Hosts,
		OperationID: op.ID, RequestDigest: requestDigest, Hostname: desired.Certificate.Hostname,
		PublicIPv4: target.PublicIPv4, Backend: desired.Backend, BackendSubnet: target.Subnet,
		EncryptedCertificate: r.gatewayControl.sealer.Seal(nil, nil, desired.Certificate.Bundle, []byte(recordKey+"/"+op.ID)),
	}
	resource, deployment := buildApplicationGatewayResources(scope, desired, target)
	refGuards, refWrites, err := r.inventoryReferenceChanges(ctx, scope, resource.Address, nil, &resource, target.Revision, nil)
	if err != nil {
		return result, err
	}
	opKey := r.operationKey(scope, op.ID)
	resourceKey, deploymentKey := r.inventoryPrefix(scope)+resource.Address.Key(), r.inventoryPrefix(scope)+deployment.Address.Key()
	guards := append(target.Guards, slotGuards...)
	guards = append(guards, refGuards...)
	for _, key := range []string{recordKey, target.SubnetLock, opKey, resourceKey, deploymentKey} {
		guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
	}
	recordData, _ := json.Marshal(record)
	opData, _ := json.Marshal(op)
	writes := append(refWrites, clientv3.OpPut(recordKey, string(recordData)), clientv3.OpPut(target.SubnetLock, recordKey),
		clientv3.OpPut(r.gatewaySlotKey(slot.Name), recordKey), clientv3.OpPut(opKey, string(opData)),
		inventoryPut(resourceKey, nil, &resource, now), inventoryPut(deploymentKey, nil, &deployment, now),
		r.auditOp(scope, arm.AuditEvent{Time: now, Actor: actor, Action: "Microsoft.Network/applicationGateways/write",
			Target: resource.Address.ID(scope), Outcome: "Accepted"}))
	for _, host := range slot.Hosts {
		key := r.gatewayTaskKey(host, slot.Name)
		guards = append(guards, clientv3.Compare(clientv3.Version(key), "=", 0))
		writes = append(writes, clientv3.OpPut(key, recordKey))
	}
	committed, err := r.client.Txn(ctx).If(guards...).Then(writes...).Commit()
	if err != nil {
		return result, err
	}
	if !committed.Succeeded {
		return result, arm.ErrGatewayExecutionUnavailable
	}
	return arm.ApplicationGatewayDeploymentResult{Resource: deployment, Operation: &op, Created: true}, nil
}

func (r *Region) retryApplicationGateway(ctx context.Context, scope arm.SubscriptionScope, record gatewayRecord,
	revision int64) (arm.ApplicationGatewayDeploymentResult, error) {
	var result arm.ApplicationGatewayDeploymentResult
	deploymentKey := r.inventoryPrefix(scope) + record.Deployment.Key()
	opKey := r.operationKey(scope, record.OperationID)
	replay, err := r.client.Txn(ctx).Then(clientv3.OpGet(deploymentKey, clientv3.WithRev(revision)),
		clientv3.OpGet(opKey, clientv3.WithRev(revision))).Commit()
	if err != nil {
		return result, err
	}
	deployments, operations := replay.Responses[0].GetResponseRange().Kvs, replay.Responses[1].GetResponseRange().Kvs
	if len(deployments) != 1 || len(operations) != 1 {
		return result, errors.New("Application Gateway deployment has no resource or operation")
	}
	deployment, err := decodeInventoryResource(deployments[0].Value, record.Deployment.Key())
	if err != nil {
		return result, err
	}
	op, err := decodeOperation(operations[0].Value, record.OperationID)
	if err != nil {
		return result, err
	}
	result.Resource = deployment
	if op.Status == arm.OperationInProgress {
		result.Operation = op
	}
	return result, nil
}

func (r *Region) availableGatewaySlot(ctx context.Context, revision int64, slots []gatewaySlot) (gatewaySlot, []clientv3.Cmp, error) {
	for _, slot := range slots {
		key := r.gatewaySlotKey(slot.Name)
		reads := []clientv3.Op{clientv3.OpGet(key, clientv3.WithRev(revision), clientv3.WithCountOnly())}
		for _, host := range slot.Hosts {
			reads = append(reads, clientv3.OpGet(r.hostKey("registered", host), clientv3.WithRev(revision)),
				clientv3.OpGet(r.hostKey("live", host), clientv3.WithRev(revision)))
		}
		snapshot, err := r.client.Txn(ctx).Then(reads...).Commit()
		if err != nil {
			return gatewaySlot{}, nil, err
		}
		if snapshot.Responses[0].GetResponseRange().Count != 0 {
			continue
		}
		guards := []clientv3.Cmp{clientv3.Compare(clientv3.Version(key), "=", 0)}
		for index, host := range slot.Hosts {
			registered := snapshot.Responses[1+2*index].GetResponseRange().Kvs
			leased := snapshot.Responses[2+2*index].GetResponseRange().Kvs
			if len(registered) != 1 || len(leased) != 1 || leased[0].Lease == 0 {
				break
			}
			var identity enrollment.Host
			var live enrollment.Availability
			if err := json.Unmarshal(registered[0].Value, &identity); err != nil {
				return gatewaySlot{}, nil, err
			}
			if err := json.Unmarshal(leased[0].Value, &live); err != nil {
				return gatewaySlot{}, nil, err
			}
			if identity.HostID != host || identity.RevokedAt != nil || !slices.Contains(identity.Roles, "gateway") ||
				live.HostID != host || !slices.Contains(live.Roles, "gateway") {
				break
			}
			guards = append(guards, clientv3.Compare(clientv3.ModRevision(string(registered[0].Key)), "=", registered[0].ModRevision),
				clientv3.Compare(clientv3.ModRevision(string(leased[0].Key)), "=", leased[0].ModRevision))
		}
		if len(guards) == 1+2*len(slot.Hosts) {
			return slot, guards, nil
		}
	}
	return gatewaySlot{}, nil, arm.ErrGatewayExecutionUnavailable
}

func applicationGatewayDigest(desired arm.ApplicationGatewayDeployment) (string, error) {
	certificateDigest := sha256.Sum256(desired.Certificate.PublicCertificate)
	value := struct {
		Resource, Subnet, PublicIP, Certificate, Hostname string
		Backend                                           netip.AddrPort
		Tags                                              map[string]string
	}{
		desired.ResourceAddress.Key(), desired.Subnet.Key(), desired.PublicIP.Key(), fmt.Sprintf("%x", certificateDigest),
		desired.Certificate.Hostname, desired.Backend, desired.Tags,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded)), nil
}

func buildApplicationGatewayResources(scope arm.SubscriptionScope, desired arm.ApplicationGatewayDeployment,
	target applicationGatewayNetwork) (arm.InventoryResource, arm.InventoryResource) {
	properties, _ := json.Marshal(map[string]any{
		"provisioningState": "Updating", "operationalState": "Stopped", "hostname": desired.Certificate.Hostname,
		"sku": map[string]any{"name": "Standard_v2", "tier": "Standard_v2", "capacity": 2},
		"frontendIPConfigurations": []any{map[string]any{"name": "appGatewayFrontendIP", "properties": map[string]any{
			"publicIPAddress": map[string]string{"id": desired.PublicIP.ID(scope)}}}},
		"gatewayIPConfigurations": []any{map[string]any{"name": "appGatewayFrontendIP", "properties": map[string]any{
			"subnet": map[string]string{"id": desired.Subnet.ID(scope)}}}},
		"backendAddressPools": []any{map[string]any{"name": "appGatewayBackendPool", "properties": map[string]any{
			"backendAddresses": []any{map[string]string{"ipAddress": desired.Backend.Addr().String()}}}}},
		"sslCertificates": []any{map[string]any{"name": desired.CertificateName, "properties": map[string]any{
			"publicCertData": desired.Certificate.PublicCertificate}}},
	})
	deploying, _ := json.Marshal(map[string]any{
		"provisioningState": "Running", "mode": "Incremental", "outputResources": []map[string]string{
			{"id": desired.ResourceAddress.ID(scope)},
		},
	})
	return arm.InventoryResource{
		Address: desired.ResourceAddress, Location: desired.Location, APIVersion: arm.ApplicationGatewayResourceVersion,
		Tags: desired.Tags, Properties: properties, ProvisioningState: "Updating",
		References: []arm.ResourceAddress{desired.PublicIP, target.VNet},
	}, arm.InventoryResource{
		Address: desired.Deployment, Location: desired.Location, APIVersion: arm.ApplicationGatewayDeploymentVersion,
		Properties: deploying, ProvisioningState: "Running",
	}
}
