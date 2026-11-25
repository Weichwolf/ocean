package storage

// Job describes a file share operation assigned to one registered worker.
type Job struct {
	ID        string `json:"id"`
	Volume    Volume `json:"volume"`
	Delete    bool   `json:"delete"`
	VolumeKey []byte `json:"volumeKey,omitempty"`
}
