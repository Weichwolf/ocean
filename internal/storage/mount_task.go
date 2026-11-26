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
	Suspend        bool   `json:"suspend,omitempty"`
}

// UnmountReceipt identifies the detached mount and lifecycle revision.
// A suspension receipt leaves the regional writer grant in place.
type UnmountReceipt struct {
	VolumeID       string `json:"volumeId"`
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	PlacementID    string `json:"placementId"`
	Generation     string `json:"generation"`
	Revision       string `json:"revision"`
	Suspend        bool   `json:"suspend,omitempty"`
}
