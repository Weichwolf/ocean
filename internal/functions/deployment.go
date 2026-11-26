package functions

import "strings"

const (
	DeploymentPending   = 0
	DeploymentFailed    = 3
	DeploymentSucceeded = 4
)

type DeploymentStatus struct {
	ID       string `json:"id"`
	Status   int    `json:"status"`
	Complete bool   `json:"complete"`
	Message  string `json:"message,omitempty"`
}

func ValidSCMDomain(domain string) bool {
	if len(domain) > 189 || !strings.Contains(domain, ".") {
		return false
	}
	for label := range strings.SplitSeq(domain, ".") {
		if !ValidName(label) {
			return false
		}
	}
	return true
}
