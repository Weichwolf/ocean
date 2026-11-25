package workload

import (
	"errors"
	"math"
	"regexp"
)

const (
	ReplicaSetType       = "Ocean.Compute/replicaSets"
	ReplicaSetAPIVersion = "2026-11-01"

	AvailabilityNone  = "NonRedundant"
	AvailabilityLocal = "LocallyRedundant"
	ScalingFixed      = "Fixed"
	ScalingLocal      = "Local"

	MaximumReplicaSlots = 4
)

var (
	ErrInvalidReplicaSet = errors.New("the replica set specification is outside the supported contract")
	replicaSetName       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
)

type ReplicaSetSpec struct {
	Location   string               `json:"location"`
	Properties ReplicaSetProperties `json:"properties"`
}

type ReplicaSetProperties struct {
	AvailabilityTier string              `json:"availabilityTier"`
	SubnetID         string              `json:"subnetId"`
	Container        ContainerProperties `json:"container"`
	Policy           ReplicaPolicy       `json:"policy"`
}

type ReplicaPolicy struct {
	Mode    string     `json:"mode"`
	Desired int        `json:"desired"`
	Minimum int        `json:"minimum"`
	Maximum int        `json:"maximum"`
	CPU     *CPUPolicy `json:"cpu,omitempty"`
}

type CPUPolicy struct {
	ScaleOutAbove   float64 `json:"scaleOutAbove"`
	ScaleInBelow    float64 `json:"scaleInBelow"`
	WindowSeconds   int     `json:"windowSeconds"`
	CooldownSeconds int     `json:"cooldownSeconds"`
}

func ValidReplicaSetName(name string) bool { return replicaSetName.MatchString(name) }

func (properties ReplicaSetProperties) Slots() int {
	if properties.AvailabilityTier == AvailabilityLocal {
		return properties.Policy.Maximum + 1
	}
	return properties.Policy.Maximum
}

func (spec ReplicaSetSpec) Validate(location string) error {
	properties := spec.Properties
	minimum := 1
	switch properties.AvailabilityTier {
	case AvailabilityLocal:
		minimum = 2
	case AvailabilityNone:
	default:
		return ErrInvalidReplicaSet
	}
	policy := properties.Policy
	if spec.Location != location || properties.SubnetID == "" || policy.Minimum < minimum ||
		policy.Minimum > policy.Desired || policy.Desired > policy.Maximum || policy.Maximum > MaximumReplicaSlots || properties.Slots() > MaximumReplicaSlots ||
		policy.Mode != ScalingFixed && policy.Mode != ScalingLocal || policy.Mode == ScalingFixed && policy.CPU != nil ||
		policy.Mode == ScalingLocal && !policy.CPU.valid() || len(properties.Container.Ports) != 1 {
		return ErrInvalidReplicaSet
	}
	// The managed profile reserves interchangeable stateless children.
	if len(properties.Container.VolumeMounts) != 0 {
		return ErrInvalidReplicaSet
	}
	group := spec.ContainerGroup("ocean-replica")
	return group.Validate("ocean-replica")
}

func (policy *CPUPolicy) valid() bool {
	return policy != nil && !math.IsNaN(policy.ScaleOutAbove) && !math.IsNaN(policy.ScaleInBelow) &&
		policy.ScaleInBelow > 0 && policy.ScaleInBelow < policy.ScaleOutAbove && policy.ScaleOutAbove <= 100 &&
		policy.WindowSeconds >= 8 && policy.WindowSeconds <= 300 &&
		policy.CooldownSeconds >= policy.WindowSeconds && policy.CooldownSeconds <= 600
}

func (spec ReplicaSetSpec) ContainerGroup(name string) ContainerGroup {
	container := spec.Properties.Container
	return ContainerGroup{Location: spec.Location, Properties: ContainerGroupProperties{
		OSType: "Linux", RestartPolicy: "Always",
		IPAddress:  &Endpoint{Type: "Private", Ports: container.Ports},
		Containers: []Container{{Name: name, Properties: container}},
		SubnetIDs:  []Subnet{{ID: spec.Properties.SubnetID}},
	}}
}
