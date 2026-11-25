package arm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/workload"
)

const (
	VirtualMachineType       = "Microsoft.Compute/virtualMachines"
	VMImageType              = "Microsoft.Compute/images"
	VMDiskType               = "Microsoft.Compute/disks"
	VMNetworkInterfaceType   = "Microsoft.Network/networkInterfaces"
	VirtualMachineAPIVersion = "2024-03-01"
	VMImageAPIVersion        = "2024-07-01"
	VMDiskAPIVersion         = "2024-03-02"
	VMNetworkAPIVersion      = "2024-05-01"
)

var (
	ErrVMImageUnavailable     = errors.New("the VM image source is unavailable in this subscription")
	ErrVirtualMachineNotFound = errors.New("the virtual machine could not be found")
	ErrVMResourceChanged      = errors.New("updates to an existing VM resource are unsupported")
	ErrVMOperationBusy        = errors.New("the VM has a different operation in progress")
	ErrVMQuotaExceeded        = errors.New("the subscription has insufficient VM capacity")
	ErrVMHostUnavailable      = errors.New("no eligible KVM host has sufficient capacity")
	vmResourceName            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$`)
)

type VirtualMachineStore interface {
	PutVMImage(context.Context, SubscriptionScope, string, ResourceAddress, VMImageRequest) (InventoryResource, bool, error)
	PutVMNetworkInterface(context.Context, SubscriptionScope, string, ResourceAddress, VMNetworkInterfaceRequest) (InventoryResource, bool, error)
	DeleteVMDependency(context.Context, SubscriptionScope, string, ResourceAddress) error
	CreateVirtualMachine(context.Context, SubscriptionScope, string, ResourceAddress, VirtualMachineRequest) (InventoryResource, *Operation, bool, error)
	MutateVirtualMachine(context.Context, SubscriptionScope, string, ResourceAddress, VMAction) (*Operation, error)
	GetVirtualMachineInstanceView(context.Context, SubscriptionScope, string, ResourceAddress) (*VMInstanceView, error)
}

type VMAction struct {
	Name  string
	Force bool
}

type VMInstanceView struct {
	Statuses []VMInstanceStatus `json:"statuses"`
}

type VMInstanceStatus struct {
	Code          string `json:"code"`
	Level         string `json:"level,omitempty"`
	DisplayStatus string `json:"displayStatus"`
}

type VMImageRequest struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties struct {
		HyperVGeneration string `json:"hyperVGeneration"`
		StorageProfile   struct {
			OSDisk struct {
				OSType     string `json:"osType"`
				OSState    string `json:"osState"`
				BlobURI    string `json:"blobUri"`
				DiskSizeGB int64  `json:"diskSizeGB,omitempty"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
	} `json:"properties"`
}

// ValidVMImageURI recognizes the catalog URI used as the image source. It
// carries no access token and never authorizes a worker to fetch arbitrary URLs.
func ValidVMImageURI(raw string) bool {
	value, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && value.String() == raw && value.Scheme == "https" && value.Hostname() != "" &&
		value.User == nil && value.Path != "" && value.Path != "/" && value.RawQuery == "" && !value.ForceQuery && value.Fragment == ""
}

func (p VMImageRequest) valid(location string) bool {
	disk := p.Properties.StorageProfile.OSDisk
	return p.Location == location && validTags(p.Tags) && p.Properties.HyperVGeneration == "V2" && disk.OSType == "Windows" &&
		disk.OSState == "Specialized" && ValidVMImageURI(disk.BlobURI) && (disk.DiskSizeGB == 0 || disk.DiskSizeGB >= 32 && disk.DiskSizeGB <= 128)
}

type VMNetworkInterfaceRequest struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties struct {
		IPConfigurations []VMIPConfiguration `json:"ipConfigurations"`
	} `json:"properties"`
}

type VMIPConfiguration struct {
	Name       string `json:"name"`
	Properties struct {
		Subnet                    network.ResourceReference `json:"subnet"`
		PrivateIPAllocationMethod string                    `json:"privateIPAllocationMethod"`
		PrivateIPAddressVersion   string                    `json:"privateIPAddressVersion,omitempty"`
		Primary                   *bool                     `json:"primary,omitempty"`
	} `json:"properties"`
}

func (p VMNetworkInterfaceRequest) valid(scope SubscriptionScope, location, group string) bool {
	if p.Location != location || !validTags(p.Tags) || len(p.Properties.IPConfigurations) != 1 {
		return false
	}
	assignment := p.Properties.IPConfigurations[0]
	props := assignment.Properties
	parent, _, ok := SubnetParent(scope, props.Subnet.ID)
	return ok && strings.EqualFold(parent.Group, group) && vmResourceName.MatchString(assignment.Name) &&
		props.PrivateIPAllocationMethod == "Dynamic" && (props.PrivateIPAddressVersion == "" || props.PrivateIPAddressVersion == "IPv4") &&
		(props.Primary == nil || *props.Primary)
}

type VirtualMachineRequest struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties struct {
		HardwareProfile struct {
			VMSize string `json:"vmSize"`
		} `json:"hardwareProfile"`
		StorageProfile struct {
			ImageReference network.ResourceReference `json:"imageReference"`
			OSDisk         VMOSDisk                  `json:"osDisk"`
		} `json:"storageProfile"`
		NetworkProfile struct {
			NetworkInterfaces []VMNetworkInterfaceReference `json:"networkInterfaces"`
		} `json:"networkProfile"`
	} `json:"properties"`
}

type VMOSDisk struct {
	Name         string `json:"name"`
	CreateOption string `json:"createOption"`
	DeleteOption string `json:"deleteOption"`
	ManagedDisk  struct {
		StorageAccountType string `json:"storageAccountType"`
	} `json:"managedDisk"`
}

type VMNetworkInterfaceReference struct {
	ID         string `json:"id"`
	Properties struct {
		DeleteOption string `json:"deleteOption,omitempty"`
		Primary      *bool  `json:"primary,omitempty"`
	} `json:"properties,omitempty"`
}

func (p VirtualMachineRequest) valid(scope SubscriptionScope, location, group string) bool {
	if p.Location != location || !validTags(p.Tags) || len(p.Properties.NetworkProfile.NetworkInterfaces) != 1 {
		return false
	}
	if _, ok := workload.VirtualMachineSize(p.Properties.HardwareProfile.VMSize); !ok {
		return false
	}
	disk := p.Properties.StorageProfile.OSDisk
	if !vmResourceName.MatchString(disk.Name) || disk.CreateOption != "FromImage" || disk.DeleteOption != "Delete" ||
		disk.ManagedDisk.StorageAccountType != "Standard_LRS" {
		return false
	}
	image, imageOK := NetworkResourceAddress(scope, p.Properties.StorageProfile.ImageReference.ID, VMImageType)
	link := p.Properties.NetworkProfile.NetworkInterfaces[0]
	nic, nicOK := NetworkResourceAddress(scope, link.ID, VMNetworkInterfaceType)
	return imageOK && nicOK && strings.EqualFold(image.Group, group) && strings.EqualFold(nic.Group, group) &&
		(link.Properties.DeleteOption == "" || link.Properties.DeleteOption == "Detach") && (link.Properties.Primary == nil || *link.Properties.Primary)
}

func virtualMachineRoute(group string, path []string) (armRoute, bool) {
	if len(path) < 2 || group == "" {
		return armRoute{}, false
	}
	for _, kind := range []string{VirtualMachineType, VMImageType, VMDiskType, VMNetworkInterfaceType} {
		if strings.EqualFold(strings.Join(path[:2], "/"), kind) {
			return armRoute{collection: "virtualMachine", group: group, name: strings.Join(append([]string{kind}, path[2:]...), "/")}, true
		}
	}
	return armRoute{}, false
}

func (s Server) virtualMachineResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, path string) {
	if s.VirtualMachines == nil {
		writeError(w, http.StatusNotFound, "InvalidResourceType", "The virtual machine profile is unavailable in this region.")
		return
	}
	if r.Header.Get("If-Match") != "" || r.Header.Get("If-None-Match") != "" {
		writeError(w, http.StatusBadRequest, "UnsupportedRequestHeader", "The virtual machine profile does not support conditional request headers.")
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) < 3 || len(parts) > 4 || !vmResourceName.MatchString(parts[2]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "Specify a supported virtual machine resource identifier.")
		return
	}
	kind := strings.Join(parts[:2], "/")
	address := ResourceAddress{Group: group, Path: strings.Join(parts[:3], "/")}
	version := VirtualMachineAPIVersion
	switch kind {
	case VMImageType:
		version = VMImageAPIVersion
	case VMDiskType:
		version = VMDiskAPIVersion
	case VMNetworkInterfaceType:
		version = VMNetworkAPIVersion
	}
	action := len(parts) == 4 && kind == VirtualMachineType
	query, ok := readQuery(w, r, version, func(key, value string) bool {
		return action && r.Method == http.MethodPost && strings.EqualFold(parts[3], "powerOff") &&
			key == "skipShutdown" && (value == "true" || value == "false")
	})
	if !ok {
		return
	}
	if len(parts) == 4 {
		if action {
			s.virtualMachineAction(ctx, w, r, scope, actor, reader, address, strings.ToLower(parts[3]), query.Get("skipShutdown") == "true")
		} else {
			writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The virtual machine resource operation is unsupported.")
		}
		return
	}
	if r.Method == http.MethodGet {
		s.showResource(ctx, w, r, scope, reader, address)
		return
	}
	if kind == VMDiskType {
		methodNotAllowed(w, "GET")
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.putVirtualMachineResource(ctx, w, r, scope, actor, address, kind)
	case http.MethodDelete:
		if kind == VirtualMachineType {
			s.requestVMAction(ctx, w, scope, actor, address, VMAction{Name: "delete"})
			return
		}
		if err := s.VirtualMachines.DeleteVMDependency(ctx, scope, actor, address); err != nil {
			vmError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) putVirtualMachineResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor string, address ResourceAddress, kind string) {
	body := http.MaxBytesReader(w, r.Body, 24<<10)
	invalid := func() {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The request is outside the supported virtual machine profile.")
	}
	var view InventoryResource
	var operation *Operation
	var created bool
	var err error
	switch kind {
	case VMImageType:
		var input VMImageRequest
		if strictJSON(body, &input) != nil || !input.valid(s.Location) {
			invalid()
			return
		}
		view, created, err = s.VirtualMachines.PutVMImage(ctx, scope, actor, address, input)
	case VMNetworkInterfaceType:
		var input VMNetworkInterfaceRequest
		if strictJSON(body, &input) != nil || !input.valid(scope, s.Location, address.Group) {
			invalid()
			return
		}
		view, created, err = s.VirtualMachines.PutVMNetworkInterface(ctx, scope, actor, address, input)
	case VirtualMachineType:
		var input VirtualMachineRequest
		if strictJSON(body, &input) != nil || !input.valid(scope, s.Location, address.Group) {
			invalid()
			return
		}
		view, operation, created, err = s.VirtualMachines.CreateVirtualMachine(ctx, scope, actor, address, input)
	default:
		methodNotAllowed(w, "GET")
		return
	}
	if err != nil {
		vmError(w, err)
		return
	}
	if operation != nil && operation.Status == OperationInProgress {
		w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+"?api-version="+resourceAPIVersion)
		w.Header().Set("Location", s.Origin+view.Address.ID(scope)+"?api-version="+VirtualMachineAPIVersion)
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, createdStatus(created), view.view(scope))
}

func (s Server) virtualMachineAction(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader string, address ResourceAddress, action string, force bool) {
	switch action {
	case "instanceview":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		view, err := s.VirtualMachines.GetVirtualMachineInstanceView(ctx, scope, reader, address)
		if err != nil {
			vmError(w, err)
		} else if view == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The virtual machine could not be found.")
		} else {
			writeJSON(w, http.StatusOK, view)
		}
	case "start", "poweroff":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		if r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The power operation takes an empty request body.")
				return
			}
		}
		s.requestVMAction(ctx, w, scope, actor, address, VMAction{Name: action, Force: force})
	default:
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The virtual machine operation is unsupported.")
	}
}

func (s Server) requestVMAction(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string, address ResourceAddress, action VMAction) {
	operation, err := s.VirtualMachines.MutateVirtualMachine(ctx, scope, actor, address, action)
	if err != nil {
		vmError(w, err)
		return
	}
	if operation != nil && operation.Status == OperationInProgress {
		s.acceptOperation(w, scope, *operation)
		return
	}
	if operation != nil && operation.Status == OperationFailed {
		vmError(w, ErrVMOperationBusy)
		return
	}
	if action.Name == "delete" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func vmError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrVMResourceChanged), errors.Is(err, ErrVMOperationBusy):
		writeError(w, http.StatusConflict, "OperationNotAllowed", err.Error())
	case errors.Is(err, ErrVMImageUnavailable):
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The virtual machine image source could not be found.")
	case errors.Is(err, ErrVirtualMachineNotFound), errors.Is(err, ErrLinkedResourceMissing):
		writeError(w, http.StatusNotFound, "ResourceNotFound", err.Error())
	case errors.Is(err, ErrLinkedResourceInUse), errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceInUse", err.Error())
	case errors.Is(err, ErrVMQuotaExceeded):
		writeError(w, http.StatusConflict, "QuotaExceeded", err.Error())
	case errors.Is(err, ErrVMHostUnavailable):
		writeError(w, http.StatusConflict, "AllocationFailed", err.Error())
	default:
		inventoryError(w, err)
	}
}
