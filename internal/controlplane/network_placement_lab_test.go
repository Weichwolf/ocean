//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestNetworkPlacementFixture(t *testing.T) {
	stage := os.Getenv("OCEAN_E2E_NETWORK_PLACEMENT")
	if stage == "" {
		t.Skip("requires the regional network placement fixture")
	}
	r := openLabRegion(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scope := arm.SubscriptionScope{TenantID: os.Getenv("OCEAN_E2E_TENANT"), SubscriptionID: os.Getenv("OCEAN_E2E_SUBSCRIPTION")}
	group := os.Getenv("OCEAN_E2E_GROUP")
	if !identifier.MatchString(group) || !validScope(scope) {
		t.Fatal("the fixture requires a private test tenant and resource group")
	}
	regionPool := strings.Fields(os.Getenv("OCEAN_E2E_PUBLIC_POOL"))
	for _, value := range regionPool {
		r.publicIPv4 = append(r.publicIPv4, netip.MustParseAddr(value))
	}
	slices.SortFunc(r.publicIPv4, netip.Addr.Compare)
	vnet := arm.ResourceAddress{Group: group, Path: "Microsoft.Network/virtualNetworks/private"}
	nsg := arm.ResourceAddress{Group: group, Path: securityGroupType + "/workload"}
	nat := arm.ResourceAddress{Group: group, Path: network.NATGatewayType + "/outbound"}
	public := arm.ResourceAddress{Group: group, Path: network.PublicIPType + "/fixed"}
	subnet := vnet.ID(scope) + "/subnets/workloads"
	request := func(suffix string) PlacementRequest {
		return PlacementRequest{ID: group + "-" + suffix, Cell: "cell-1", Role: "compute",
			Resources: enrollment.Capacity{CPUMillis: 100, MemoryMiB: 32}, SubnetID: subnet}
	}
	put := func(address arm.ResourceAddress, version string, properties any, references ...arm.ResourceAddress) {
		t.Helper()
		data, _ := json.Marshal(properties)
		resource := arm.InventoryResource{Address: address, APIVersion: version, Location: "farm-1",
			ProvisioningState: "Succeeded", Properties: data, References: references}
		if err := r.PutInventoryResource(ctx, scope, resource); err != nil {
			t.Fatal(err)
		}
	}
	storeRule := func(access string) {
		put(nsg, network.SecurityGroupAPIVersion, network.SecurityGroupProperties{ProvisioningState: "Succeeded",
			SecurityRules: []network.SecurityRule{network.NewSecurityRule(nsg.ID(scope), "web", "securityRules", network.SecurityRuleProperties{
				Access: access, Priority: 110, Direction: "Inbound", Protocol: "Tcp", SourceAddressPrefix: "*",
				DestinationAddressPrefix: "*", SourcePortRange: "*", DestinationPortRange: "8080",
			})}})
	}
	reserve := func(suffix string) Reservation {
		t.Helper()
		result, err := r.ReservePlacement(ctx, scope, request(suffix))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	read := func(suffix string) (Reservation, bool) {
		t.Helper()
		saved, ok, err := r.placementRetry(ctx, r.armPrefix(scope)+"placement-requests/"+request(suffix).ID, request(suffix))
		if err != nil {
			t.Fatal(err)
		}
		return saved, ok
	}
	release := func(saved Reservation) {
		t.Helper()
		if err := r.ReleasePlacement(ctx, scope, saved.Cell, saved.ID, saved.Generation); err != nil {
			t.Fatal(err)
		}
	}
	switch stage {
	case "seed":
		if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: "farm-1", Tags: map[string]string{}}, "lab-test"); err != nil {
			t.Fatal(err)
		}
		storeRule("Allow")
		put(public, network.PublicIPAPIVersion, network.PublicIPAddressProperties{AllocationMethod: "Static", IPVersion: "IPv4",
			ProvisioningState: "Succeeded", IdleTimeout: 4})
		put(nat, network.NATAPIVersion, network.NATGatewayProperties{ProvisioningState: "Succeeded", IdleTimeout: 4,
			PublicIPAddresses: []network.ResourceReference{{ID: public.ID(scope)}}}, public)
		vnetProperties := network.VNetProperties{AddressSpace: network.AddressSpace{Prefixes: []string{"10.86.0.0/16"}},
			ProvisioningState: "Succeeded", Subnets: []network.Subnet{
				network.NewSubnet(vnet.ID(scope), "workloads", network.SubnetProperties{AddressPrefix: "10.86.1.0/29",
					NetworkSecurityGroup: &network.ResourceReference{ID: nsg.ID(scope)}, NATGateway: &network.ResourceReference{ID: nat.ID(scope)}}),
			}}
		put(vnet, network.VNetAPIVersion, vnetProperties, nat, nsg)
		if err := r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"lab-default"}, Quota: enrollment.Capacity{CPUMillis: 800, MemoryMiB: 512}}); err != nil {
			t.Fatal(err)
		}
		foreign := request("foreign")
		foreign.SubnetID = strings.Replace(subnet, scope.SubscriptionID, "00000000-0000-0000-0000-000000000000", 1)
		if _, err := r.ReservePlacement(ctx, scope, foreign); !errors.Is(err, ErrPlacementSubnetUnavailable) {
			t.Fatalf("a foreign subnet was not rejected: %v", err)
		}
		concurrent, errs := placementRace(ctx, r, scope, request("one"), request("two"))
		third := reserve("three")
		if errs[0] != nil || errs[1] != nil || concurrent[0].PrivateIPv4 == concurrent[1].PrivateIPv4 ||
			third.PrivateIPv4.String() != "10.86.1.6" || reserve("one") != concurrent[0] {
			t.Fatalf("unexpected private IPv4 reservations: %+v %+v %v", concurrent, third, errs)
		}
		if _, err := r.ReservePlacement(ctx, scope, request("full")); !errors.Is(err, ErrSubnetAddressExhausted) {
			t.Fatalf("the full subnet returned %v", err)
		}
		used, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
		if err != nil || used.used != (enrollment.Capacity{CPUMillis: 300, MemoryMiB: 96}) {
			t.Fatalf("failed allocations consumed capacity: %+v %v", used, err)
		}
		if _, err := r.DeleteGroup(ctx, scope, group, "lab-test"); !errors.Is(err, arm.ErrGroupInUse) {
			t.Fatalf("deleting an in-use group returned %v", err)
		}
		if _, _, err := r.ChangeInventoryResource(ctx, scope, vnet, "", "", "",
			func(_ *arm.InventoryResource, _ arm.ResourceAddress) (*arm.InventoryResource, error) { return nil, nil }); !errors.Is(err, arm.ErrSubnetInUse) {
			t.Fatalf("deleting an in-use VNet returned %v", err)
		}
		current, err := r.GetInventoryResource(ctx, scope, "", vnet)
		if err != nil || current == nil {
			t.Fatalf("could not load the VNet: %v", err)
		}
		vnetProperties.Subnets[0].Properties.AddressPrefix = "10.86.1.8/29"
		current.Properties, _ = json.Marshal(vnetProperties)
		if err := r.PutInventoryResource(ctx, scope, *current); !errors.Is(err, arm.ErrSubnetInUse) {
			t.Fatalf("renumbering an in-use subnet returned %v", err)
		}
	case "policy-change":
		storeRule("Deny")
	case "policy-allow":
		storeRule("Allow")
	case "invalidate-owner", "restore-owner":
		saved, exists := read("one")
		if !exists {
			t.Fatal("the address ownership fixture is missing")
		}
		key := r.subnetNetworkPlacements(scope, vnet, "workloads") + saved.PrivateIPv4.String()
		current, update := saved.Generation, "fixture-unrecognized-generation"
		if stage == "restore-owner" {
			current, update = update, current
		}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Value(key), "=", current)).
			Then(clientv3.OpPut(key, update)).Commit()
		if err != nil || !result.Succeeded {
			t.Fatalf("could not change the disposable address ownership fixture: %v", err)
		}
	case "recycle":
		saved, exists := read("one")
		if !exists {
			t.Fatal("the original placement is missing")
		}
		release(saved)
		newer := reserve("one")
		if newer.PrivateIPv4 != saved.PrivateIPv4 || newer.Generation == saved.Generation {
			t.Fatalf("the released address did not return to its subnet: %+v %+v", saved, newer)
		}
		if err := r.ReleasePlacement(ctx, scope, saved.Cell, saved.ID, saved.Generation); !errors.Is(err, ErrReservationChanged) {
			t.Fatalf("stale cleanup did not reject the replacement: %v", err)
		}
	case "cleanup":
		for _, suffix := range []string{"one", "two", "three"} {
			if saved, exists := read(suffix); exists {
				release(saved)
			}
		}
		if _, err := r.DeleteGroup(ctx, scope, group, "lab-test"); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown network placement stage %q", stage)
	}
}
