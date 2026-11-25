package workload

import (
	"net/netip"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/network"
)

const (
	Running = "Running"
	Stopped = "Stopped"
	Removed = "Removed"
	Failed  = "Failed"
)

type AssignmentID struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	ID             string `json:"id"`
	Generation     string `json:"generation"`
	Revision       string `json:"revision"`
}

type Task struct {
	AssignmentID
	State              string                `json:"state"`
	Start              bool                  `json:"start,omitempty"`
	Restart            bool                  `json:"restart,omitempty"`
	Address            netip.Addr            `json:"address"`
	Policy             *network.SubnetPolicy `json:"policy,omitempty"`
	VolumeID           string                `json:"volumeId,omitempty"`
	Port               int                   `json:"port"`
	BlockPublicIngress bool                  `json:"blockPublicIngress,omitempty"`
	RestartPolicy      string                `json:"restartPolicy,omitempty"`
	Container          *ContainerProperties  `json:"container,omitempty"`
	Function           *functions.Runtime    `json:"function,omitempty"`
}

type Page struct {
	Tasks []Task `json:"tasks"`
	Next  string `json:"continuation,omitempty"`
}

type Report struct {
	AssignmentID
	State         string                 `json:"state"`
	Logs          string                 `json:"logs,omitempty"`
	Function      *functions.AdminResult `json:"function,omitempty"`
	FunctionReady bool                   `json:"functionReady,omitempty"`
}
