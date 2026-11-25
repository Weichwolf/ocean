package arm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/workload"
)

type vmRouteStore struct {
	VirtualMachineStore
	created bool
	read    string
	action  VMAction
}

func (s *vmRouteStore) CreateVirtualMachine(_ context.Context, _ SubscriptionScope, _ string, a ResourceAddress, input VirtualMachineRequest) (InventoryResource, *Operation, bool, error) {
	s.created = true
	return InventoryResource{Address: a, Location: input.Location}, &Operation{ID: "d229fc9a-259c-4669-91ab-e8448ff88610", Status: OperationInProgress}, true, nil
}

func (s *vmRouteStore) MutateVirtualMachine(_ context.Context, _ SubscriptionScope, _ string, _ ResourceAddress, action VMAction) (*Operation, error) {
	s.action = action
	return &Operation{ID: "d229fc9a-259c-4669-91ab-e8448ff88610", Status: OperationInProgress}, nil
}

func (s *vmRouteStore) GetVirtualMachineInstanceView(_ context.Context, _ SubscriptionScope, reader string, _ ResourceAddress) (*VMInstanceView, error) {
	s.read = reader
	return &VMInstanceView{Statuses: []VMInstanceStatus{{Code: "PowerState/running", DisplayStatus: "VM running"}}}, nil
}

func TestVirtualMachineARMProfile(t *testing.T) {
	const (
		origin  = "https://arm.ocean.test"
		scope   = "/subscriptions/0cc93d5e-a937-4627-a255-10e43ad58b89/resourceGroups/test-group/providers/"
		vm      = scope + VirtualMachineType + "/vm-001"
		version = "?api-version=" + VirtualMachineAPIVersion
	)
	put := `{"location":"lab","properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},` +
		`"storageProfile":{"imageReference":{"id":"` + scope + VMImageType + `/image-001"},` +
		`"osDisk":{"name":"os-001","createOption":"FromImage","deleteOption":"Delete","managedDisk":{"storageAccountType":"Standard_LRS"}}},` +
		`"networkProfile":{"networkInterfaces":[{"id":"` + scope + VMNetworkInterfaceType + `/nic-001"}]}}}`
	storage := &vmRouteStore{}
	server := Server{Origin: origin, Location: "lab", VirtualMachines: storage,
		Authenticate: func(_ context.Context, r *http.Request) (identity.ARMPrincipal, error) {
			principal := identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: "tenant", SubscriptionID: "0cc93d5e-a937-4627-a255-10e43ad58b89", Members: []string{"operator"},
			}}
			if r.Header.Get("Test-Principal") == "reader" {
				principal.Subject = "reader"
			}
			return principal, nil
		}}
	for _, tc := range []struct {
		name, method, path, body, principal string
		status                              int
		create                              bool
		action                              VMAction
		reader                              string
	}{
		{name: "create", method: "PUT", path: vm + version, body: put, status: 201, create: true},
		{name: "outside API version", method: "PUT", path: vm + "?api-version=2025-04-01", body: put, status: 400},
		{name: "foreign image", method: "PUT", path: vm + version, body: strings.Replace(put, "0cc93d5e-a937-4627-a255-10e43ad58b89", "56d82b15-ed70-4b54-82a9-f3b4aef38e26", 1), status: 400},
		{name: "foreign NIC", method: "PUT", path: vm + version, body: strings.Replace(put, "/test-group/providers/"+VMNetworkInterfaceType, "/other-group/providers/"+VMNetworkInterfaceType, 1), status: 400},
		{name: "unsupported resize", method: "PUT", path: vm + version, body: strings.Replace(put, "Standard_B2s", "Standard_B16ms", 1), status: 400},
		{name: "unknown profile field", method: "PUT", path: vm + version, body: strings.Replace(put, `"hardwareProfile"`, `"osProfile":{},"hardwareProfile"`, 1), status: 400},
		{name: "start", method: "POST", path: vm + "/start" + version, status: 202, action: VMAction{Name: "start"}},
		{name: "graceful power off", method: "POST", path: vm + "/powerOff" + version, status: 202, action: VMAction{Name: "poweroff"}},
		{name: "explicit forced power off", method: "POST", path: vm + "/powerOff" + version + "&skipShutdown=true", status: 202, action: VMAction{Name: "poweroff", Force: true}},
		{name: "duplicate flags", method: "POST", path: vm + "/powerOff" + version + "&skipShutdown=true&skipShutdown=false", status: 400},
		{name: "nonempty action body", method: "POST", path: vm + "/powerOff" + version, body: `{}`, status: 400},
		{name: "scoped instance view", method: "GET", path: vm + "/instanceView" + version, principal: "reader", status: 200, reader: "reader"},
		{name: "reader cannot mutate", method: "POST", path: vm + "/powerOff" + version, principal: "reader", status: 403},
		{name: "disk cannot be created separately", method: "PUT", path: scope + VMDiskType + "/disk-001?api-version=" + VMDiskAPIVersion, status: 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*storage = vmRouteStore{}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tc.method, origin+tc.path, strings.NewReader(tc.body))
			request.Header.Set("Test-Principal", tc.principal)
			server.Handler(http.NotFoundHandler()).ServeHTTP(recorder, request)
			if recorder.Code != tc.status || storage.created != tc.create || storage.action != tc.action || storage.read != tc.reader {
				t.Fatalf("unexpected route result: HTTP %d, created %v, action %+v, reader %q: %s", recorder.Code, storage.created, storage.action, storage.read, recorder.Body)
			}
			if tc.create || tc.action.Name != "" {
				if target := recorder.Header().Get("Azure-AsyncOperation"); !strings.HasPrefix(target, origin+"/subscriptions/") {
					t.Fatalf("the operation did not publish its regional poll URL: %q", target)
				}
			}
		})
	}
}

func TestVMImageDiskProfile(t *testing.T) {
	image := VMImageRequest{Location: "lab"}
	image.Properties.HyperVGeneration = "V2"
	disk := &image.Properties.StorageProfile.OSDisk
	disk.OSState, disk.BlobURI = "Specialized", "https://images.ocean.test/boot.raw"
	for _, tc := range []struct {
		osType string
		size   int64
		valid  bool
	}{
		{workload.VMLinux, 0, true},
		{workload.VMLinux, 7, false},
		{workload.VMLinux, 8, true},
		{workload.VMLinux, 129, false},
		{workload.VMWindows, 0, true},
		{workload.VMWindows, 8, false},
		{workload.VMWindows, 32, true},
		{"Other", 32, false},
	} {
		disk.OSType, disk.DiskSizeGB = tc.osType, tc.size
		if image.valid("lab") != tc.valid {
			t.Errorf("image OS %q with %d GiB did not match expected validity %t", tc.osType, tc.size, tc.valid)
		}
	}
}
