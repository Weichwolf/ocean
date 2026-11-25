package storage

// MountTask is an authorization for one placement generation on a worker.
type MountTask struct {
	VolumeID       string `json:"volumeId"`
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	PlacementID    string `json:"placementId"`
	Generation     string `json:"generation"`
	Revision       string `json:"revision"`
	VolumeKey      []byte `json:"volumeKey,omitempty"`
	Remove         bool   `json:"remove,omitempty"`
}

// UnmountReceipt identifies the removed mount and lifecycle revision.
type UnmountReceipt struct {
	VolumeID       string `json:"volumeId"`
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	PlacementID    string `json:"placementId"`
	Generation     string `json:"generation"`
	Revision       string `json:"revision"`
}
