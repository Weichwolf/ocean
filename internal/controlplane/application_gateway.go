package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type applicationGatewayNetwork struct {
	PublicIPv4 netip.Addr
	Subnet     netip.Prefix
}

func (r *Region) DeployApplicationGateway(ctx context.Context, scope arm.SubscriptionScope, actor string,
	desired arm.ApplicationGatewayDeployment, commit bool) (arm.ApplicationGatewayDeploymentResult, error) {
	if _, err := r.readApplicationGatewayNetwork(ctx, scope, desired); err != nil {
		return arm.ApplicationGatewayDeploymentResult{}, err
	}
	if commit {
		return arm.ApplicationGatewayDeploymentResult{}, arm.ErrGatewayExecutionUnavailable
	}
	properties := json.RawMessage(`{"provisioningState":"Succeeded","mode":"Incremental"}`)
	return arm.ApplicationGatewayDeploymentResult{Resource: arm.InventoryResource{
		Address: desired.Deployment, APIVersion: arm.ApplicationGatewayDeploymentVersion, Location: desired.Location,
		Properties: properties, ProvisioningState: arm.OperationSucceeded,
	}}, nil
}

// readApplicationGatewayNetwork reads the network target, public address, and
// conflicting consumer from the same regional revision.
func (r *Region) readApplicationGatewayNetwork(ctx context.Context, scope arm.SubscriptionScope,
	desired arm.ApplicationGatewayDeployment) (applicationGatewayNetwork, error) {
	var result applicationGatewayNetwork
	group := strings.ToLower(desired.ResourceAddress.Group)
	groupKey := r.groupPrefix(scope) + group
	vnet, subnetName, ok := arm.SubnetParent(scope, desired.Subnet.ID(scope))
	if !ok {
		return result, arm.InvalidDeployment{Cause: errors.New("invalid gateway subnet identifier")}
	}
	inventory := r.inventoryPrefix(scope)
	ipKey, vnetKey := inventory+desired.PublicIP.Key(), inventory+vnet.Key()
	publicClaims := r.dependentsPrefix(scope, desired.PublicIP)
	read, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(groupKey),
		clientv3.OpGet(ipKey),
		clientv3.OpGet(vnetKey),
		clientv3.OpGet(publicClaims, clientv3.WithPrefix(), clientv3.WithKeysOnly(), clientv3.WithLimit(2)),
	).Commit()
	if err != nil {
		return result, err
	}
	groups := read.Responses[0].GetResponseRange().Kvs
	if len(groups) != 1 {
		return result, arm.ErrGroupMissing
	}
	current, err := decodeGroup(groups[0].Value, group)
	if err != nil {
		return result, err
	}
	if current.DeleteOperation != "" {
		return result, arm.ErrGroupDeleting
	}
	ipValues := read.Responses[1].GetResponseRange().Kvs
	vnetValues := read.Responses[2].GetResponseRange().Kvs
	if len(ipValues) != 1 || len(vnetValues) != 1 {
		return result, arm.ErrLinkedResourceMissing
	}
	claims := read.Responses[3].GetResponseRange().Kvs
	if len(claims) > 1 || len(claims) == 1 && string(claims[0].Key) != publicClaims+strings.ToLower(desired.ResourceAddress.Path) {
		return result, arm.ErrPublicIPInUse
	}
	address, err := decodeInventoryResource(ipValues[0].Value, desired.PublicIP.Key())
	if err != nil {
		return result, err
	}
	var public network.PublicIPAddressProperties
	if err := json.Unmarshal(address.Properties, &public); err != nil {
		return result, err
	}
	publicIPv4, err := netip.ParseAddr(public.Address)
	if err != nil || !publicIPv4.Is4() || !publicIPv4.IsGlobalUnicast() || public.ProvisioningState != arm.OperationSucceeded ||
		public.AllocationMethod != "Static" || public.IPVersion != "IPv4" {
		return result, arm.InvalidDeployment{Cause: errors.New("the selected public address has not been allocated")}
	}
	virtualNetwork, err := decodeInventoryResource(vnetValues[0].Value, vnet.Key())
	if err != nil {
		return result, err
	}
	var properties network.VNetProperties
	if err := json.Unmarshal(virtualNetwork.Properties, &properties); err != nil {
		return result, err
	}
	index := properties.SubnetIndex(subnetName)
	if index < 0 {
		return result, arm.ErrLinkedResourceMissing
	}
	prefixes, err := properties.Subnets[index].Properties.Prefixes()
	if err != nil {
		return result, err
	}
	for _, prefix := range prefixes {
		if network.IsUsableSubnetAddress(prefix, desired.Backend.Addr()) && !prefix.Contains(publicIPv4) {
			return applicationGatewayNetwork{PublicIPv4: publicIPv4, Subnet: prefix}, nil
		}
	}
	return result, arm.InvalidDeployment{Cause: errors.New("the private backend address is outside the selected subnet")}
}
