//go:build e2e

package e2e

import "github.com/Weichwolf/ocean/tests/e2e/internal/harness"

func identitySteps(options labOptions) []harness.Step {
	return []harness.Step{
		regional(options, "tenant-directory", "verify_onboarding.py", []string{"IDENTITY-01", "IDENTITY-03"},
			[]string{"tenant-directory.json"}, "--directory-users", "--directory-apps"),
		regional(options, "oauth-and-database-failover", "verify_identity.py", []string{"IDENTITY-02", "IDENTITY-05", "HA-01"},
			[]string{"identity-failover.json"}),
		regional(options, "tenant-rbac", "verify_arm.py", []string{"IDENTITY-04"}, []string{"arm-rbac.json"}, "--rbac"),
	}
}
