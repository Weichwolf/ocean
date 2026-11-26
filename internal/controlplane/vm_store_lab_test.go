//go:build e2e

package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalVirtualMachineStore(t *testing.T) {
	endpoint := os.Getenv("OCEAN_E2E_VM_ETCD")
	if endpoint == "" {
		t.Skip("requires a disposable loopback etcd for the VM store probe")
	}
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("the VM store probe requires a disposable loopback etcd")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	r, fencer := vmStoreFixture(t, client)
	if err := r.bootstrapVirtualMachines(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapVirtualMachines(ctx); err != nil {
		t.Fatal(err)
	}
	const actor = "operator"
	worker := "b-kvm"
	scope := arm.SubscriptionScope{TenantID: "tenant-1", SubscriptionID: "subscription-1"}
	foreign := arm.SubscriptionScope{TenantID: "tenant-2", SubscriptionID: "subscription-1"}
	group := "vm-test"
	address := func(kind, name string) arm.ResourceAddress {
		return arm.ResourceAddress{Group: group, Path: kind + "/" + name}
	}
	image := address(arm.VMImageType, "core-image")
	nic, secondNIC := address(arm.VMNetworkInterfaceType, "primary"), address(arm.VMNetworkInterfaceType, "quota-test")
	vm := address(arm.VirtualMachineType, "server-core")
	disk := address(arm.VMDiskType, "core-disk")
	seedVMScope(t, ctx, r, scope, group)
	seedVMScope(t, ctx, r, foreign, group)
	var imageRequest arm.VMImageRequest
	decodeVMFixture(t, `{"location":"local","properties":{"hyperVGeneration":"V2","storageProfile":{"osDisk":{"osType":"Windows","osState":"Specialized","blobUri":"https://images.ocean.test/core.vhd"}}}}`, &imageRequest)
	if _, _, err := r.PutVMImage(ctx, foreign, actor, image, imageRequest); !errors.Is(err, arm.ErrVMImageUnavailable) {
		t.Fatalf("foreign tenant admitted a private image: %v", err)
	}
	mislabeled := imageRequest
	mislabeled.Properties.StorageProfile.OSDisk.OSType = workload.VMLinux
	if _, _, err := r.PutVMImage(ctx, scope, actor, image, mislabeled); !errors.Is(err, arm.ErrVMImageUnavailable) {
		t.Fatalf("VM image accepted a different operating system from the catalog: %v", err)
	}
	imageView, created, err := r.PutVMImage(ctx, scope, actor, image, imageRequest)
	if err != nil || !created || imageView.Address != image {
		t.Fatalf("image creation failed: %v", err)
	}
	if _, created, err := r.PutVMImage(ctx, scope, actor, image, imageRequest); err != nil || created {
		t.Fatalf("image retry failed: %v", err)
	}

	subnetPath := "Microsoft.Network/virtualNetworks/private/subnets/workload"
	nicRequest := func(tenant arm.SubscriptionScope) (input arm.VMNetworkInterfaceRequest) {
		id := (arm.ResourceAddress{Group: group, Path: subnetPath}).ID(tenant)
		decodeVMFixture(t, fmt.Sprintf(`{"location":"local","properties":{"ipConfigurations":[{"name":"interface","properties":{"subnet":{"id":%q},"privateIPAllocationMethod":"Dynamic"}}]}}`, id), &input)
		return input
	}
	request := nicRequest(scope)
	var contenders sync.WaitGroup
	answers := make(chan error, 4)
	for range cap(answers) {
		contenders.Go(func() {
			view, _, err := r.PutVMNetworkInterface(ctx, scope, actor, nic, request)
			if err == nil && !strings.Contains(string(view.Properties), `"privateIPAddress":"10.73.1.4"`) {
				err = fmt.Errorf("unexpected NIC projection: %s", view.Properties)
			}
			answers <- err
		})
	}
	contenders.Wait()
	close(answers)
	for err := range answers {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.PutVMNetworkInterface(ctx, foreign, actor, nic, nicRequest(foreign)); !errors.Is(err, arm.ErrLinkedResourceInUse) {
		t.Fatalf("foreign tenant could claim an overlapping routed subnet: %v", err)
	}
	if _, _, err := r.PutVMNetworkInterface(ctx, scope, actor, secondNIC, request); err != nil {
		t.Fatal(err)
	}
	var vmRequest arm.VirtualMachineRequest
	decodeVMFixture(t, fmt.Sprintf(`{"location":"local","properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},"storageProfile":{"imageReference":{"id":%q},"osDisk":{"name":"core-disk","createOption":"FromImage","deleteOption":"Delete","managedDisk":{"storageAccountType":"Standard_LRS"}}},"networkProfile":{"networkInterfaces":[{"id":%q}]}}}`,
		image.ID(scope), nic.ID(scope)), &vmRequest)
	tooSmall := vmRequest
	tooSmall.Properties.HardwareProfile.VMSize = "Standard_B1s"
	if _, _, _, err := r.CreateVirtualMachine(ctx, scope, actor, vm, tooSmall); !errors.Is(err, arm.ErrVMSizeUnsupported) {
		t.Fatalf("Windows VM accepted a Linux-only size: %v", err)
	}
	createdVM, createOp, created, err := r.CreateVirtualMachine(ctx, scope, actor, vm, vmRequest)
	if err != nil || !created || createOp == nil || createOp.Status != arm.OperationInProgress {
		t.Fatalf("VM reservation failed: %+v %v", createOp, err)
	}
	replay, retryOp, created, err := r.CreateVirtualMachine(ctx, scope, actor, vm, vmRequest)
	if err != nil || created || retryOp == nil || retryOp.ID != createOp.ID || !strings.EqualFold(string(replay.Properties), string(createdVM.Properties)) {
		t.Fatalf("VM reservation replay changed the accepted resource: %+v %v", retryOp, err)
	}
	vmRequest.Properties.StorageProfile.OSDisk.Name = "quota-disk"
	vmRequest.Properties.NetworkProfile.NetworkInterfaces[0].ID = secondNIC.ID(scope)
	if _, _, _, err := r.CreateVirtualMachine(ctx, scope, actor, address(arm.VirtualMachineType, "quota-test"), vmRequest); !errors.Is(err, arm.ErrVMQuotaExceeded) {
		t.Fatalf("expected the live VM to consume CPU and memory quota: %v", err)
	}
	r.workloads.defaultPlacement.Quota = enrollment.Capacity{CPUMillis: 4000, MemoryMiB: 8192}
	if _, _, _, err := r.CreateVirtualMachine(ctx, scope, actor, address(arm.VirtualMachineType, "quota-test"), vmRequest); !errors.Is(err, arm.ErrVMQuotaExceeded) {
		t.Fatalf("expected the live VM to consume its OS disk quota even with available CPU and RAM: %v", err)
	}
	for _, target := range []arm.ResourceAddress{image, nic} {
		if err := r.DeleteVMDependency(ctx, scope, actor, target); !errors.Is(err, arm.ErrLinkedResourceInUse) {
			t.Fatalf("deleting an attached dependency returned %v", err)
		}
	}
	if _, err := r.DeleteGroup(ctx, scope, group, actor); !errors.Is(err, arm.ErrGroupInUse) {
		t.Fatalf("deleting a group with a VM returned %v", err)
	}
	for _, target := range []arm.ResourceAddress{vm, disk, nic, image} {
		if view, err := r.GetInventoryResource(ctx, foreign, "", target); view != nil || err != nil {
			t.Fatalf("foreign tenant could read %s: %+v %v", target.Path, view, err)
		}
	}
	if page, err := r.HostVirtualMachineTasks(ctx, "a-no-kvm", []byte("a-no-kvm"), ""); len(page.Tasks) != 0 || !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("unqualified worker could read a VM task: %v", err)
	}
	if _, err := r.HostVirtualMachineTasks(ctx, worker, []byte("wrong certificate"), ""); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("incorrect certificate could read a VM task: %v", err)
	}
	first := readVMStoreTask(t, ctx, r, worker)
	if first.Network == nil || first.Network.Address.Addr().String() != "10.73.1.4" || len(first.VolumeKey) != 32 || first.Prepared || first.Revision != createOp.ID {
		t.Fatal("the verified writer did not receive the expected private VM assignment")
	}
	clear(first.VolumeKey)
	ack := workload.VMReport{AssignmentID: first.AssignmentID, State: workload.Running}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), ack); err != nil {
		t.Fatal(err)
	}
	if operation, err := r.GetOperation(ctx, scope, createOp.ID); err != nil || operation == nil || operation.Status != arm.OperationSucceeded {
		t.Fatalf("the observed running VM did not complete creation: %+v %v", operation, err)
	}
	if instance, err := r.GetVirtualMachineInstanceView(ctx, scope, "", vm); err != nil || instance == nil || instance.Statuses[1].Code != "PowerState/running" {
		t.Fatalf("unexpected observed VM power state: %+v %v", instance, err)
	}
	probeVMWithCLI(t, ctx, r, scope, vm)

	if _, err := r.MutateVirtualMachine(ctx, scope, actor, vm, arm.VMAction{Name: "poweroff"}); err != nil {
		t.Fatal(err)
	}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), ack); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("stale running report affected a later power action: %v", err)
	}
	stopping := readVMStoreTask(t, ctx, r, worker)
	if stopping.State != workload.Stopped || len(stopping.VolumeKey) != 0 || stopping.Force {
		t.Fatal("power-off task must be graceful and need no disk key")
	}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), workload.VMReport{AssignmentID: stopping.AssignmentID, State: workload.Stopped}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.MutateVirtualMachine(ctx, scope, actor, vm, arm.VMAction{Name: "start"}); err != nil {
		t.Fatal(err)
	}
	starting := readVMStoreTask(t, ctx, r, worker)
	defer clear(starting.VolumeKey)
	if !starting.Prepared || starting.MachineID != first.MachineID || starting.Disk.ID != first.Disk.ID || starting.Generation != first.Generation {
		t.Fatal("start changed prepared disk, machine identity or writer generation")
	}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), workload.VMReport{AssignmentID: starting.AssignmentID, State: workload.Running}); err != nil {
		t.Fatal(err)
	}
	worker = probeVMFence(t, ctx, r, fencer, scope, vm, worker, starting)
	deletion, err := r.MutateVirtualMachine(ctx, scope, actor, vm, arm.VMAction{Name: "delete"})
	if err != nil || deletion == nil {
		t.Fatalf("deletion request failed: %v", err)
	}
	removing := readVMStoreTask(t, ctx, r, worker)
	removed := workload.VMReport{AssignmentID: removing.AssignmentID, State: workload.Removed}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), removed); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("deletion without a disk release receipt was accepted: %v", err)
	}
	if usage, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage"); err != nil || usage.used.CPUMillis != 2000 || usage.used.MemoryMiB != 4096 {
		t.Fatalf("quota changed before release confirmation: %+v %v", usage, err)
	}
	removed.DiskReleased = true
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), removed); err != nil {
		t.Fatal(err)
	}
	for _, target := range []arm.ResourceAddress{vm, disk} {
		if view, err := r.GetInventoryResource(ctx, scope, "", target); err != nil || view != nil {
			t.Fatalf("deleted VM resource remains visible: %+v %v", view, err)
		}
	}
	if usage, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage"); err != nil || usage.used != (enrollment.Capacity{}) {
		t.Fatalf("confirmed deletion did not release VM quota: %+v %v", usage, err)
	}
	if usage, err := r.client.Get(ctx, r.armPrefix(scope)+"vm-disk-usage-gib"); err != nil || len(usage.Kvs) != 1 || string(usage.Kvs[0].Value) != "0" {
		t.Fatalf("confirmed deletion did not release VM disk quota: %v", err)
	}
	if err := r.DeleteVMDependency(ctx, scope, actor, nic); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteVMDependency(ctx, scope, actor, image); err != nil {
		t.Fatal(err)
	}
	if reassigned, _, err := r.PutVMNetworkInterface(ctx, scope, actor, nic, request); err != nil || !strings.Contains(string(reassigned.Properties), `"privateIPAddress":"10.73.1.4"`) {
		t.Fatalf("NIC deletion did not release the original address: %s %v", reassigned.Properties, err)
	}
	t.Log("image, scoped NIC, CPU and RAM reservation, writer credentials and VM lifecycle were verified against live etcd")
}

func readVMStoreTask(t *testing.T, ctx context.Context, r *Region, worker string) workload.VMTask {
	t.Helper()
	page, err := r.HostVirtualMachineTasks(ctx, worker, []byte(worker), "")
	if err != nil || len(page.Tasks) != 1 {
		t.Fatalf("expected one reconciler task, got %d: %v", len(page.Tasks), err)
	}
	return page.Tasks[0]
}

func vmStoreFixture(t *testing.T, client *clientv3.Client) (*Region, ed25519.PrivateKey) {
	t.Helper()
	ctx := t.Context()
	pool := "kvm"
	quota := enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 4096}
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, fencer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &Region{client: client, root: "/test/vm-store/" + operationID(), name: "local", cell: "cell-1",
		workloads: &workloadControl{defaultPlacement: PlacementPolicy{Pools: []string{pool}, Quota: quota}},
		storage:   &storageControl{sealer: sealer, workers: []string{"a-no-kvm", "b-kvm", "c-kvm"}, fencer: publicKey}}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	r.vms, err = openVMControl(&vmConfig{DiskQuotaGiB: 64, Images: []vmCatalogImage{{TenantID: "tenant-1", SubscriptionID: "subscription-1",
		URI: "https://images.ocean.test/core.vhd", SizeGiB: 64, ImageSHA256: strings.Repeat("a", 64), FirmwareSHA256: strings.Repeat("b", 64)}}}, r.workloads, r.storage)
	if err != nil {
		t.Fatal(err)
	}
	seedVMWorker(t, ctx, r, "a-no-kvm", false)
	seedVMWorker(t, ctx, r, "b-kvm", true)
	return r, fencer
}

func seedVMScope(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, group string) {
	t.Helper()
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: r.name, Tags: map[string]string{}}, "operator"); err != nil {
		t.Fatal(err)
	}
	address := arm.ResourceAddress{Group: group, Path: "Microsoft.Network/virtualNetworks/private"}
	subnet := arm.ResourceAddress{Group: group, Path: address.Path + "/subnets/workload"}
	properties := fmt.Sprintf(`{"addressSpace":{"addressPrefixes":["10.73.1.0/24"]},"subnets":[{"name":"workload","id":%q,"properties":{"addressPrefix":"10.73.1.0/24"}}]}`, subnet.ID(scope))
	if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: address, Location: r.name, APIVersion: "2025-07-01", Properties: json.RawMessage(properties)}); err != nil {
		t.Fatal(err)
	}
}

func decodeVMFixture(t *testing.T, source string, target any) {
	t.Helper()
	if err := json.Unmarshal([]byte(source), target); err != nil {
		t.Fatal(err)
	}
}

func probeVMWithCLI(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, vm arm.ResourceAddress) {
	t.Helper()
	az := os.Getenv("OCEAN_E2E_VM_AZ")
	if az == "" {
		return
	}
	server := httptest.NewUnstartedServer(nil)
	configuration := arm.Server{Origin: "https://" + server.Listener.Addr().String(), Location: r.name,
		Inventory: r, Operations: r, Roles: r, VirtualMachines: r,
		Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			if request.Header.Get("Authorization") != "Bearer regional-vm-fixture" {
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Members: []string{"operator"},
			}}, nil
		}}
	server.Config.Handler = configuration.Handler(http.NotFoundHandler())
	server.StartTLS()
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, az, "rest", "--method", "get", "--skip-authorization-header", "--headers",
		"Authorization=Bearer regional-vm-fixture", "--url", server.URL+vm.ID(scope)+"/instanceView?api-version="+arm.VirtualMachineAPIVersion,
		"--only-show-errors", "--output", "json")
	command.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+t.TempDir(), "REQUESTS_CA_BUNDLE="+ca, "AZURE_CORE_COLLECT_TELEMETRY=no")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("stock az rest failed to read the regional VM: %v: %s", err, output)
	}
	var view arm.VMInstanceView
	if json.Unmarshal(output, &view) != nil || len(view.Statuses) != 2 || view.Statuses[1].Code != "PowerState/running" {
		t.Fatalf("unexpected stock CLI VM instance view: %s", output)
	}
	t.Log("stock az rest read the observed VM power state over TLS using test authentication")
}
