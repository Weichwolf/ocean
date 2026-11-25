package workload

// VMSize describes the CPU and memory reserved while a tenant VM exists.
type VMSize struct {
	VCPUs     int
	MemoryMiB int
}

func VirtualMachineSize(name string) (VMSize, bool) {
	switch name {
	case "Standard_B1ms":
		return VMSize{VCPUs: 1, MemoryMiB: 2048}, true
	case "Standard_B2s":
		return VMSize{VCPUs: 2, MemoryMiB: 4096}, true
	default:
		return VMSize{}, false
	}
}
