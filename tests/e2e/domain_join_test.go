//go:build e2e

package e2e

import (
	"path/filepath"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func domainJoinSteps(options labOptions) []harness.Step {
	const stateVariable = "OCEAN_E2E_DOMAIN_STATE"
	const script = "verify_domain_join.py"
	debian := probe("debian-domain-join", options.domain, stateVariable, script, []string{"WORKPLACE-01"},
		[]string{"debian-domain-join.json"}, "--debian-image", options.domainImage)
	steps := []harness.Step{requireFile(debian, options.domainImage, "OCEAN_E2E_DEBIAN_IMAGE")}
	for _, fixture := range []struct{ profile, id string }{
		{"server-core", "WORKPLACE-02"},
		{"windows-11", "WORKPLACE-03"},
	} {
		name := fixture.profile + "-domain-join"
		step := probe(name, options.domain, stateVariable, script, []string{fixture.id},
			[]string{name + ".json"}, "--windows-profile", fixture.profile)
		for _, file := range []string{"media.json", "join.json", "machine.json", "identity.json"} {
			step = requireFile(step, filepath.Join(options.domain, fixture.profile, file), fixture.profile+" "+file)
		}
		steps = append(steps, step)
	}
	return steps
}
