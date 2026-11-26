package workload

import (
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/storage"
)

const VMSuspensionHeader = "Ocean-VM-Suspension"

type VMTask struct {
	AssignmentID
	MachineID string                `json:"machineId"`
	Size      string                `json:"size"`
	State     string                `json:"state"`
	Prepared  bool                  `json:"prepared"`
	Force     bool                  `json:"force,omitempty"`
	Disk      storage.VMDisk        `json:"disk"`
	VolumeKey []byte                `json:"volumeKey,omitempty"`
	Network   *network.SubnetPolicy `json:"network,omitempty"`
}

type VMTaskPage struct {
	Tasks []VMTask `json:"tasks"`
	Next  string   `json:"continuation,omitempty"`
}

type VMReport struct {
	AssignmentID
	State        string `json:"state"`
	DiskReleased bool   `json:"diskReleased,omitempty"`
}

func (r VMReport) ValidState() bool {
	switch r.State {
	case Running, Stopped:
		return !r.DiskReleased
	case Removed, Suspended:
		return r.DiskReleased
	default:
		return false
	}
}
