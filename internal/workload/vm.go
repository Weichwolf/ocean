package workload

const (
	VMWindows = "Windows"
	VMLinux   = "Linux"
)

func ValidVMImageDiskSize(osType string, sizeGiB int64) bool {
	switch osType {
	case VMWindows:
		return sizeGiB >= 32 && sizeGiB <= 128
	case VMLinux:
		return sizeGiB >= 8 && sizeGiB <= 128
	default:
		return false
	}
}

// VMSize describes the CPU and memory reserved while a tenant VM exists.
type VMSize struct {
	VCPUs      int
	MemoryMiB  int
	RequiredOS string
}

func VirtualMachineSize(name string) (VMSize, bool) {
	switch name {
	case "Standard_B1s":
		return VMSize{VCPUs: 1, MemoryMiB: 1024, RequiredOS: VMLinux}, true
	case "Standard_B1ms":
		return VMSize{VCPUs: 1, MemoryMiB: 2048}, true
	case "Standard_B2s":
		return VMSize{VCPUs: 2, MemoryMiB: 4096}, true
	default:
		return VMSize{}, false
	}
}
