//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type desktopBrowserLabSettings struct {
	Identity         identity.Config                `json:"identity"`
	Registration     identity.TenantReservation     `json:"registration"`
	DirectoryID      string                         `json:"directoryId"`
	DomainSID        string                         `json:"domainSid"`
	MachineID        string                         `json:"machineId"`
	UserID           string                         `json:"userId"`
	WorkloadKey      string                         `json:"workloadKey"`
	GatewayDER       string                         `json:"gatewayDer"`
	StandbyDER       string                         `json:"standbyDer,omitempty"`
	WriterDER        string                         `json:"writerDer"`
	WriterGeneration string                         `json:"writerGeneration"`
	Application      identity.DesktopBrowserFixture `json:"application"`
}

func setupDesktopBrowserLab(t *testing.T, ctx context.Context, r *Region, api *arm.Server, cfg desktopBrowserLabSettings) http.Handler {
	t.Helper()
	r.name, r.cell = "farm-1", "cell-1"
	r.directoryCapacity = enrollment.Capacity{CPUMillis: 400, MemoryMiB: 384}
	var err error
	r.workloads, err = openWorkloadControl(&workloadConfig{SecretsKeyFile: cfg.WorkloadKey,
		DefaultPlacement: PlacementPolicy{Pools: []string{"approved"}, Quota: r.directoryCapacity}})
	if err != nil {
		t.Fatal(err)
	}
	tenant := cfg.Registration
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DisplayName: "Desktop browser lab", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	compat, err := cfg.Identity.OpenCompatibility()
	if err != nil || cfg.Identity.Onboarding == nil {
		t.Fatalf("configure the desktop browser identity: %v", err)
	}
	compat.EnableSubscriptions(r.name, r.lookupSubscription)
	if err := compat.EnableOnboarding(*cfg.Identity.Onboarding, r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := compat.DeleteDesktopBrowserFixture(cleanup, tenant); err != nil {
			t.Error(err)
		}
	})
	vnet := arm.ResourceAddress{Group: "workplace", Path: "Microsoft.Network/virtualNetworks/office"}
	subnet := vnet.ID(scope) + "/subnets/personal"
	directory := identity.ManagedDirectory{ID: cfg.DirectoryID, TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		RequestedAt: time.Now().Add(-time.Minute), ProvisionedAt: time.Now(), DomainSID: cfg.DomainSID,
		Spec: identity.DirectorySpec{DNSName: "ad.ocean.test", NetBIOSName: "OCEANLAB", SubnetID: strings.ToLower(subnet)}}
	writer := Reservation{ID: operationID(), HostID: "desktop-lab-writer", Generation: cfg.WriterGeneration, PrivateIPv4: netip.MustParseAddr("10.232.1.11")}
	standby := Reservation{ID: operationID(), HostID: "desktop-lab-standby", Generation: operationID(), PrivateIPv4: netip.MustParseAddr("10.232.1.13")}
	placement := directoryPlacement{DirectoryID: directory.ID, Controllers: [2]Reservation{writer, standby}}
	lease, err := r.client.Grant(ctx, 125)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	writerCert := get(cfg.WriterDER)
	ops := []clientv3.Op{putJSON(r.managedDirectoryKey(tenant.TenantID), directory),
		putJSON(r.managedDirectoryPlacementKey(tenant.TenantID), placement)}
	type fixtureHost struct {
		id, role      string
		certificate   []byte
		directory, vm bool
	}
	hosts := []fixtureHost{
		{writer.HostID, "compute", writerCert, true, false},
		{"gateway-fixture", "gateway", get(cfg.GatewayDER), false, false},
		{desktopLabHost, "compute", nil, false, true},
	}
	if cfg.StandbyDER != "" {
		hosts = append(hosts, fixtureHost{"gateway-b", "gateway", get(cfg.StandbyDER), false, false})
	}
	for _, host := range hosts {
		roles := []string{host.role}
		entry := enrollment.Host{HostID: host.id, Cell: r.cell, Pool: "approved", Roles: roles, Certificate: host.certificate}
		live, err := json.Marshal(enrollment.Availability{HostID: host.id, Cell: r.cell, Pool: "approved", Roles: roles,
			DirectoryRuntime: host.directory, VMRuntime: host.vm})
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, putJSON(r.hostKey("registered", host.id), entry),
			clientv3.OpPut(r.hostKey("live", host.id), string(live), clientv3.WithLease(lease.ID)))
	}
	assigned := enrollment.Assignment{ID: writer.ID, Generation: writer.Generation, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, PrivateIPv4: writer.PrivateIPv4, Directory: &enrollment.DirectoryAssignment{
			DirectoryID: directory.ID, DNSName: directory.Spec.DNSName, NetBIOSName: directory.Spec.NetBIOSName,
			ControllerIndex: 1, ControllerIPv4: [2]netip.Addr{writer.PrivateIPv4, standby.PrivateIPv4}}}
	ops = append(ops, putJSON(r.hostReservationKey(scope, writer.HostID, writer.ID), assigned))
	ops = append(ops, seedDesktopBrowserVM(t, r, scope, cfg, directory, subnet, vnet)...)
	if _, err := r.client.Txn(ctx).Then(ops...).Commit(); err != nil {
		t.Fatal(err)
	}
	if err := compat.PrepareDesktopBrowserFixture(ctx, tenant, directory, cfg.Application); err != nil {
		t.Fatal(err)
	}
	api.Desktops, api.DesktopLaunch, api.AuthenticateDesktop = r, r, compat.AuthenticateDesktop
	return desktopLabDirectoryWorker(r, tenant, writer, directory.DomainSID)
}

func seedDesktopBrowserVM(t *testing.T, r *Region, scope arm.SubscriptionScope, cfg desktopBrowserLabSettings,
	directory identity.ManagedDirectory, subnet string, vnet arm.ResourceAddress) []clientv3.Op {
	t.Helper()
	group := vnet.Group
	vm := arm.ResourceAddress{Group: group, Path: arm.VirtualMachineType + "/personal"}
	nic := arm.ResourceAddress{Group: group, Path: arm.VMNetworkInterfaceType + "/personal"}
	addr := arm.ResourceAddress{Group: group, Path: arm.DesktopType + "/personal"}
	record := vmRecord{Address: vm, MachineID: cfg.MachineID, Desired: workload.Running, Observed: workload.Running, Prepared: true,
		OSType: workload.VMLinux, Operation: operationID(), Creation: operationID(),
		Image: arm.ResourceAddress{Group: group, Path: arm.VMImageType + "/personal"}, NIC: nic,
		DiskAddress: arm.ResourceAddress{Group: group, Path: arm.VMDiskType + "/personal"}}
	record.Request.Location = r.name
	record.Reservation.NeedsVMRuntime = true
	record.Reservation.HostID, record.Reservation.Cell, record.Reservation.Generation = desktopLabHost, r.cell, operationID()
	record.Disk = storage.VMDisk{ID: "vm-" + cfg.MachineID, SizeGiB: 8,
		ImageSHA256: strings.Repeat("a", 64), FirmwareSHA256: strings.Repeat("b", 64)}
	binding := vmNIC{Address: nic, IP: netip.MustParseAddr("10.232.1.12"), VMID: cfg.MachineID, VM: &vm,
		Lease: operationID(), SubnetID: subnet}
	binding.Config.Properties.IPConfigurations = []arm.VMIPConfiguration{{Name: "workforce"}}
	properties, err := json.Marshal(desktopAssignment{DesktopPolicy: arm.DesktopPolicy{VirtualMachineID: vm.ID(scope),
		PrincipalType: "User", PrincipalID: cfg.UserID}, MachineID: cfg.MachineID, DirectoryID: directory.ID,
		AssignmentID: operationID(), ProvisioningState: vmSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	desktop := arm.InventoryResource{Address: addr, Location: r.name, APIVersion: arm.DesktopAPIVersion,
		Properties: properties, ProvisioningState: vmSucceeded, References: []arm.ResourceAddress{vm},
		CreatedAt: time.Now(), ChangedAt: time.Now()}
	return []clientv3.Op{putJSON(r.vmKey(scope, vm), record), putJSON(r.vmNICKey(scope, nic), binding),
		clientv3.OpPut(r.subnetNetworkPlacements(scope, vnet, "personal")+binding.IP.String(), binding.Lease),
		putJSON(r.inventoryPrefix(scope)+addr.Key(), desktop)}
}

func desktopLabDirectoryWorker(r *Region, tenant identity.TenantReservation, writer Reservation, sid string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/fixture/writer/{action}", func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
			http.Error(w, "writer certificate required", http.StatusForbidden)
			return
		}
		cert := req.TLS.PeerCertificates[0].Raw
		ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
		defer cancel()
		var err error
		switch {
		case req.Method == http.MethodPost && req.PathValue("action") == "health":
			err = r.ReportDirectoryHealth(ctx, writer.HostID, cert, tenant.TenantID, writer.Generation, enrollment.DirectoryHealth{Ready: true, DomainSID: sid})
		case req.Method == http.MethodGet && req.PathValue("action") == "graph":
			var task *enrollment.DirectoryGraphTask
			task, err = r.HostDirectoryGraphTask(ctx, writer.HostID, cert, tenant.TenantID, writer.Generation)
			if err == nil && task != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(task)
				return
			}
		case req.Method == http.MethodPost && req.PathValue("action") == "graph":
			result, decodeErr := config.Decode(http.MaxBytesReader(w, req.Body, 256<<10), enrollment.DirectoryGraphResult{})
			if decodeErr != nil {
				http.Error(w, "invalid writer result", http.StatusBadRequest)
				return
			}
			err = r.FinishDirectoryGraphTask(ctx, writer.HostID, cert, tenant.TenantID, writer.Generation, result)
		default:
			http.NotFound(w, req)
			return
		}
		if err != nil {
			http.Error(w, "writer request failed", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
