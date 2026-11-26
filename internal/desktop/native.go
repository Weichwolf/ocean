package desktop

import (
	"regexp"
	"time"
)

const (
	NativeAdmissionPath = "/ocean/desktops/native-admission"
	NativeLeaseLifetime = 12 * time.Second
)

type NativeAdmissionRequest struct {
	User  string `json:"user"`
	Lease bool   `json:"lease,omitempty"`
}

type NativeLease struct {
	AssignmentID string    `json:"assignmentId"`
	MachineID    string    `json:"machineId"`
	UserID       string    `json:"userId"`
	Generation   string    `json:"generation"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

var nativeAccount = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,19}@[a-z0-9][a-z0-9.-]*$`)

// ValidNativeAccount matches the canonical UPN of a managed workforce account.
func ValidNativeAccount(user string) bool {
	return len(user) <= 128 && nativeAccount.MatchString(user)
}
