//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestManagedDirectoryReservation(t *testing.T) {
	endpoint := os.Getenv("OCEAN_E2E_DIRECTORY_ETCD")
	if endpoint == "" {
		t.Skip("requires a disposable etcd endpoint")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	region := &Region{client: client, name: "farm-1", root: "/ocean/tests/directory/" + operationID()}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := client.Delete(cleanup, region.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	}()
	seed := func(publish bool) (identity.TenantReservation, identity.DirectorySpec) {
		t.Helper()
		tenant := identity.TenantReservation{TenantID: operationID(), Administrator: operationID(),
			SubscriptionID: operationID(), Fingerprint: operationID()}
		if _, err := region.ReserveTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		sub := identity.Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
			DisplayName: "Directory Lab", Members: []string{tenant.Administrator}}
		if publish {
			if _, err := region.PublishSubscription(ctx, tenant, sub); err != nil {
				t.Fatal(err)
			}
		}
		scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
		if _, _, err := region.PutGroup(ctx, scope, arm.Group{Name: "lab", Location: region.name, Tags: map[string]string{}}, tenant.Administrator); err != nil {
			t.Fatal(err)
		}
		vnet := arm.ResourceAddress{Group: "lab", Path: "Microsoft.Network/virtualNetworks/directory"}
		properties, err := json.Marshal(network.VNetProperties{
			AddressSpace: network.AddressSpace{Prefixes: []string{"10.86.0.0/24"}}, ProvisioningState: "Succeeded",
			Subnets: []network.Subnet{network.NewSubnet(vnet.ID(scope), "office", network.SubnetProperties{AddressPrefix: "10.86.0.0/28"})},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := region.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: vnet, APIVersion: network.VNetAPIVersion,
			Location: region.name, ProvisioningState: "Succeeded", Properties: properties}); err != nil {
			t.Fatal(err)
		}
		return tenant, identity.DirectorySpec{DNSName: "ad.example.test", NetBIOSName: "OFFICE", SubnetID: vnet.ID(scope) + "/subnets/office"}
	}
	first, spec := seed(true)
	second, foreign := seed(true)
	unpublished, pending := seed(false)
	if _, err := region.RequestManagedDirectory(ctx, unpublished, pending); !errors.Is(err, identity.ErrDirectoryTenant) {
		t.Fatalf("unpublished tenant request returned %v", err)
	}
	if _, err := region.RequestManagedDirectory(ctx, first, foreign); !errors.Is(err, identity.ErrDirectorySubnet) {
		t.Fatalf("foreign subnet request returned %v", err)
	}
	missing := spec
	missing.SubnetID += "-missing"
	if _, err := region.RequestManagedDirectory(ctx, first, missing); !errors.Is(err, identity.ErrDirectorySubnet) {
		t.Fatalf("missing subnet request returned %v", err)
	}
	var requested [12]identity.ManagedDirectory
	var errs [12]error
	var writers sync.WaitGroup
	for i := range requested {
		writers.Go(func() { requested[i], errs[i] = region.RequestManagedDirectory(ctx, first, spec) })
	}
	writers.Wait()
	for i, directory := range requested {
		if errs[i] != nil || !directory.Valid(first) || directory != requested[0] {
			t.Fatalf("writer %d returned %+v (error %v)", i, directory, errs[i])
		}
	}
	spec.DNSName, spec.SubnetID = strings.ToUpper(spec.DNSName), strings.ToUpper(spec.SubnetID)
	if replay, err := region.RequestManagedDirectory(ctx, first, spec); err != nil || replay != requested[0] {
		t.Fatalf("the equivalent request did not replay: %+v %v", replay, err)
	}
	spec.NetBIOSName = "OTHER"
	if _, err := region.RequestManagedDirectory(ctx, first, spec); !errors.Is(err, identity.ErrDirectoryConflict) {
		t.Fatalf("conflicting directory request returned %v", err)
	}
	if directory, err := region.LookupManagedDirectory(ctx, second); err != nil || directory != nil {
		t.Fatalf("a second tenant could see the existing reservation: %+v %v", directory, err)
	}
	if directory, err := region.RequestManagedDirectory(ctx, second, foreign); err != nil || !directory.Valid(second) || directory.ID == requested[0].ID {
		t.Fatalf("an independent tenant could not request its own directory: %+v %v", directory, err)
	}
	if read, err := region.LookupManagedDirectory(ctx, first); err != nil || read == nil || *read != requested[0] {
		t.Fatalf("the accepted directory was not persisted: %+v %v", read, err)
	}
	forged := first
	forged.Administrator = second.Administrator
	if _, err := region.LookupManagedDirectory(ctx, forged); !errors.Is(err, identity.ErrDirectoryTenant) {
		t.Fatalf("forged registration lookup returned %v", err)
	}
	scope := arm.SubscriptionScope{TenantID: first.TenantID, SubscriptionID: first.SubscriptionID}
	events, err := client.Get(ctx, region.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	var changes int
	for _, item := range events.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(item.Value, &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == "Ocean.Identity/directories/write" {
			changes++
			if event.Actor != first.Administrator || event.Target != requested[0].ID || event.Outcome != "Accepted" {
				t.Fatalf("unexpected managed directory audit event %+v", event)
			}
		}
	}
	if changes != 1 {
		t.Fatalf("concurrent directory requests produced %d audit events", changes)
	}
}
