package desktop

import "regexp"

const NativeAdmissionPath = "/ocean/desktops/native-admission"

type NativeAdmissionRequest struct {
	User string `json:"user"`
}

var nativeAccount = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,19}@[a-z0-9][a-z0-9.-]*$`)

// ValidNativeAccount matches the canonical UPN of a managed workforce account.
func ValidNativeAccount(user string) bool {
	return len(user) <= 128 && nativeAccount.MatchString(user)
}
