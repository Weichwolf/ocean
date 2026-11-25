package storage

import "time"

// FenceAttestation is signed by the authority that can power off a worker.
// The complete placement generation binds a proof to one retired writer.
type FenceAttestation struct {
	TenantID       string    `json:"tenantId"`
	SubscriptionID string    `json:"subscriptionId"`
	VolumeID       string    `json:"volumeId"`
	HostID         string    `json:"hostId"`
	PlacementID    string    `json:"placementId"`
	Generation     string    `json:"generation"`
	Observation    string    `json:"observation"`
	ObservedAt     time.Time `json:"observedAt"`
}

const PoweredOff = "PoweredOff"

type SignedFence struct {
	Attestation []byte `json:"attestation"`
	Signature   []byte `json:"signature"`
}
