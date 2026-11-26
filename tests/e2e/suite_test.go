//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

type labOptions struct {
	evidence    string
	regional    string
	small       string
	scale       string
	domain      string
	domainImage string
	ipsec       string
	sambaImage  string
	adcliImage  string
	packageDeb  string
	backup      string
	phaseOne    bool
}

func TestAcceptanceMatrix(t *testing.T) {
	catalog, _ := readAcceptanceMatrices(t, "../..")
	covered := checkProbePlan(t, catalog, planSteps(labOptions{phaseOne: true}))
	for _, c := range catalog {
		if c.Gate == "required" && !covered[c.ID] {
			t.Errorf("required acceptance case %s has no local probe", c.ID)
		}
	}
}

func readAcceptanceMatrices(t *testing.T, root string) ([]harness.Case, []harness.CommandContract) {
	t.Helper()
	catalog, err := harness.ReadCatalog(filepath.Join(root, "acceptance.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := harness.ReadContract(filepath.Join(root, "tests", "e2e", "testdata", "arm-contract.tsv"), catalog)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, contract
}

func TestAcceptance(t *testing.T) {
	profile := os.Getenv("OCEAN_E2E_PROFILE")
	if profile == "" {
		t.Skip("Set OCEAN_E2E_PROFILE to select a local acceptance profile.")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	catalog, contract := readAcceptanceMatrices(t, root)
	contractFile := filepath.Join(root, "tests", "e2e", "testdata", "arm-contract.tsv")
	selected := selectCases(t, profile, catalog, os.Getenv("OCEAN_E2E_CASES"))
	now := time.Now().UTC()
	id := os.Getenv("OCEAN_E2E_RUN_ID")
	if id == "" {
		id = fmt.Sprintf("%s-%d", now.Format("20060102T150405.000000000Z"), os.Getpid())
	}
	destination := localPath(root, envOr("OCEAN_E2E_ARTIFACTS", filepath.Join("artifacts", "e2e")))
	runner, err := harness.Start(root, destination, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Acceptance artifacts in %s", runner.Directory)
	azVersions, extensions := []string{}, []string{}
	apiVersions := map[string]bool{}
	for _, row := range contract {
		if !slices.Contains(azVersions, row.CLI) {
			azVersions = append(azVersions, row.CLI)
		}
		if !slices.Contains(extensions, row.Extensions) {
			extensions = append(extensions, row.Extensions)
		}
		for _, api := range strings.Split(row.APIVersion, "+") {
			apiVersions[api] = true
		}
	}
	apis := make([]string, 0, len(apiVersions))
	for api := range apiVersions {
		apis = append(apis, api)
	}
	slices.Sort(apis)
	options := configureLab(root, profile)
	options.evidence = runner.Evidence
	meta := harness.RunMetadata{ID: id, Profile: profile, Revision: revision(root), StartedAt: now,
		Inputs: map[string]string{
			"Host":                  fmt.Sprintf("%s/%s with %d visible CPUs", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()),
			"CLI contract versions": strings.Join(azVersions, ", "), "Pinned CLI extensions": strings.Join(extensions, ", "),
			"API contract versions":     strings.Join(apis, ", "),
			"Acceptance matrix SHA-256": digest(filepath.Join(root, "acceptance.tsv")), "CLI contract SHA-256": digest(contractFile),
			"Image lock SHA-256": digest(filepath.Join(root, "tests", "e2e", "testdata", "images.lock.yaml")),
		}}
	for name, location := range map[string]string{"Regional lab state": options.regional, "Small lab state": options.small,
		"Scale lab state": options.scale, "Domain join lab state": options.domain, "IPsec lab state": options.ipsec} {
		if location != "" {
			meta.Inputs[name] = location
		}
	}
	if file := options.packageDeb; file != "" {
		meta.Inputs["Agent package SHA-256"] = digest(file)
	}
	if image := options.sambaImage; image != "" {
		meta.Inputs["Samba controller image"] = image
	}
	if image := options.adcliImage; image != "" {
		meta.Inputs["Debian directory client image"] = image
	}
	if profile == "vm-worker" {
		for name, input := range map[string]string{"VM lab state": "OCEAN_E2E_VM_WORKER_STATE", "VM disk SHA-256": "OCEAN_E2E_VM_DISK_PIN",
			"VM firmware variables SHA-256": "OCEAN_E2E_VM_VARS_PIN"} {
			if value := os.Getenv(input); value != "" {
				meta.Inputs[name] = value
			}
		}
	}
	if profile == "vm-worker-linux" || profile == "vm-worker-linux-fence" || profile == "vm-worker-desktop-pair" || profile == "vm-worker-desktop-windows" {
		for name, input := range map[string]string{"VM lab state": "OCEAN_E2E_VM_LINUX_STATE", "VM disk SHA-256": "OCEAN_E2E_VM_LINUX_DISK_PIN",
			"VM firmware variables SHA-256": "OCEAN_E2E_VM_LINUX_VARS_PIN"} {
			if value := os.Getenv(input); value != "" {
				meta.Inputs[name] = value
			}
		}
	}
	for _, file := range []string{filepath.Join(root, "acceptance.tsv"), contractFile,
		filepath.Join(root, "tests", "e2e", "testdata", "images.lock.yaml")} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("record acceptance input: %v", err)
		}
		if err := os.WriteFile(filepath.Join(runner.Evidence, filepath.Base(file)), data, 0o600); err != nil {
			t.Fatalf("record acceptance input: %v", err)
		}
	}
	outcomes := []harness.Outcome{}
	t.Cleanup(func() {
		meta.FinishedAt = time.Now().UTC()
		results := harness.Aggregate(selected, outcomes)
		if err := runner.WriteReports(meta, results); err != nil {
			t.Errorf("write acceptance artifacts: %v", err)
		}
		for _, result := range results {
			if result.Status != harness.Pass {
				t.Errorf("%s %s — %s", result.Case.ID, result.Status, result.Detail)
			}
		}
	})

	steps := planSteps(options)
	checkProbePlan(t, catalog, steps)
	keys := make([]string, 0, len(selected))
	for _, c := range selected {
		keys = append(keys, c.ID)
	}
	preflight := runner.Execute(t.Context(), harness.Step{Name: "local-build", Cases: keys,
		Command: []string{"make", "build"}, Timeout: 3 * time.Minute})
	if preflight.Status != harness.Pass {
		outcomes = append(outcomes, preflight)
		return
	}
	selectedID := make(map[string]bool, len(selected))
	for _, c := range selected {
		selectedID[c.ID] = true
	}
	var sessions *labSessions
	if profile == "phase-one" {
		var err error
		steps = orderLabSteps(steps)
		sessions, err = prepareLabSessions(t.Context(), root, steps, selectedID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := sessions.restore(); err != nil {
				outcomes = append(outcomes, harness.Outcome{Name: "restore-lab", Cases: keys, Status: harness.Fail, Detail: err.Error()})
			}
		})
	}
	for _, step := range steps {
		var applicable []string
		for _, id := range step.Cases {
			if selectedID[id] {
				applicable = append(applicable, id)
			}
		}
		if len(applicable) == 0 {
			continue
		}
		step.Cases = applicable
		executed := false
		t.Run(step.Name, func(t *testing.T) {
			executed = true
			if sessions != nil && step.BlockedReason == "" && step.LabState != "" {
				starting, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
				err := sessions.use(starting, step.LabState)
				cancel()
				if err != nil {
					step.BlockedReason = err.Error()
				}
			}
			outcome := runner.Execute(t.Context(), step)
			outcomes = append(outcomes, outcome)
			if outcome.Status != harness.Pass {
				t.Errorf("%s %s — %s", strings.Join(applicable, ", "), outcome.Status, outcome.Detail)
				return
			}
			t.Logf("%s %s — %s", strings.Join(applicable, ", "), outcome.Status, outcome.Detail)
		})
		if !executed {
			outcomes = append(outcomes, harness.Outcome{Name: step.Name, Cases: applicable, Status: harness.Blocked,
				Detail: "The Go subtest filter excluded a required probe."})
		}
	}
}

func checkProbePlan(t *testing.T, catalog []harness.Case, steps []harness.Step) map[string]bool {
	t.Helper()
	known := make(map[string]bool, len(catalog))
	for _, c := range catalog {
		known[c.ID] = true
	}
	names, covered := make(map[string]bool), make(map[string]bool)
	for _, step := range steps {
		if step.Name == "" || names[step.Name] || len(step.Cases) == 0 {
			t.Fatalf("invalid or duplicate local probe %q", step.Name)
		}
		names[step.Name] = true
		for i, id := range step.Cases {
			if !known[id] || slices.Contains(step.Cases[:i], id) {
				t.Fatalf("local probe %q maps an unknown or repeated case %q", step.Name, id)
			}
			covered[id] = true
		}
	}
	return covered
}

func configureLab(root, profile string) labOptions {
	options := labOptions{
		regional: localPath(root, envOr("OCEAN_E2E_STATE", os.Getenv("LAB_STATE"))),
		small:    localPath(root, os.Getenv("OCEAN_E2E_SMALL_STATE")), scale: localPath(root, os.Getenv("OCEAN_E2E_SCALE_STATE")),
		packageDeb: localPath(root, os.Getenv("OCEAN_E2E_PACKAGE")), backup: localPath(root, os.Getenv("OCEAN_E2E_ETCD_ARCHIVE")),
		domain: localPath(root, os.Getenv("OCEAN_E2E_DOMAIN_STATE")), domainImage: localPath(root, os.Getenv("OCEAN_E2E_DEBIAN_IMAGE")),
		ipsec:      localPath(root, os.Getenv("OCEAN_E2E_IPSEC_LAB_STATE")),
		sambaImage: os.Getenv("OCEAN_E2E_SAMBA_IMAGE"),
		adcliImage: os.Getenv("OCEAN_E2E_ADCLI_IMAGE"),
		phaseOne:   profile == "phase-one",
	}
	switch profile {
	case "single-farm-3":
		if options.small == "" {
			options.small = options.regional
		}
	case "scale-16":
		if options.scale == "" {
			options.scale = options.regional
		}
	}
	return options
}

func selectCases(t *testing.T, profile string, catalog []harness.Case, explicit string) []harness.Case {
	t.Helper()
	small := []string{"HOST-01", "LAB-01"}
	var available func(harness.Case) bool
	switch profile {
	case "phase-one":
		available = func(c harness.Case) bool { return c.Gate == "required" }
	case "storage-ha":
		available = func(c harness.Case) bool {
			return c.Gate == "required" && c.ID != "LAB-02" && !slices.Contains(small, c.ID)
		}
	case "single-farm-3":
		available = func(c harness.Case) bool { return slices.Contains(small, c.ID) }
	case "scale-16":
		available = func(c harness.Case) bool { return c.ID == "LAB-02" }
	case "geo-4x3", "geo-4x4":
		available = func(c harness.Case) bool { return c.ID == "PROFILE-04" || c.ID == "PROFILE-06" }
	case "farm-pairing":
		available = func(c harness.Case) bool { return c.ID == "FED-01" }
	case "farm-routing":
		available = func(c harness.Case) bool { return c.ID == "FED-02" }
	case "geo-ingress":
		available = func(c harness.Case) bool { return c.ID == "FED-03" }
	case "ipsec-gateway":
		available = func(c harness.Case) bool { return c.ID == "IPSEC-01" }
	case "ipsec-control":
		available = func(c harness.Case) bool { return c.ID == "IPSEC-02" }
	case "ipsec-profile":
		available = func(c harness.Case) bool { return c.ID == "PROFILE-01" }
	case "functions-zip-foundation":
		available = func(c harness.Case) bool { return strings.HasPrefix(c.ID, "ZIP-") }
	case "functions-zip-slots":
		available = func(c harness.Case) bool { return c.ID == "PROFILE-02" }
	case "cost-management-foundation":
		available = func(c harness.Case) bool { return c.ID == "COST-01" }
	case "cost-management":
		available = func(c harness.Case) bool { return c.ID == "PROFILE-03" }
	case "domain-join":
		available = func(c harness.Case) bool {
			return slices.Contains([]string{"WORKPLACE-01", "WORKPLACE-02", "WORKPLACE-03"}, c.ID)
		}
	case "managed-directory":
		available = func(c harness.Case) bool { return c.ID == "WORKPLACE-04" || c.ID == "WORKPLACE-05" }
	case "vm-worker":
		available = func(c harness.Case) bool { return c.ID == "VM-01" || c.ID == "VM-02" }
	case "vm-worker-linux":
		available = func(c harness.Case) bool { return c.ID == "VM-03" }
	case "vm-worker-linux-fence":
		available = func(c harness.Case) bool { return c.ID == "WORKPLACE-37" }
	case "vm-worker-desktop-pair":
		available = func(c harness.Case) bool { return c.ID == "WORKPLACE-40" }
	case "vm-worker-desktop-windows":
		available = func(c harness.Case) bool { return c.ID == "WORKPLACE-41" }
	default:
		t.Fatalf("unknown acceptance profile %q", profile)
	}
	var requested []string
	if explicit != "" {
		for _, value := range strings.Split(explicit, ",") {
			id := strings.TrimSpace(value)
			if id == "" || slices.Contains(requested, id) {
				t.Fatalf("invalid or repeated selected case %q", id)
			}
			requested = append(requested, id)
		}
	}
	var selected []harness.Case
	for _, c := range catalog {
		if len(requested) > 0 && slices.Contains(requested, c.ID) || len(requested) == 0 && available(c) {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 || len(requested) > 0 && len(selected) != len(requested) {
		t.Fatal("one or more selected cases are absent from the matrix")
	}
	return selected
}

func planSteps(options labOptions) []harness.Step {
	return slices.Concat(provisioningSteps(options), identitySteps(options), workloadSteps(options), networkSteps(options), resilienceSteps(options), domainJoinSteps(options), virtualMachineSteps())
}

func localPath(root, path string) string {
	if path == "" {
		return path
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func digest(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	return fmt.Sprintf("%x", sha256.Sum256(value))
}

func revision(root string) string {
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = root
	result, err := command.Output()
	if err != nil {
		return "unavailable"
	}
	head := strings.TrimSpace(string(result))
	command = exec.Command("git", "status", "--porcelain")
	command.Dir = root
	if dirty, err := command.Output(); err == nil && len(dirty) > 0 {
		head += " (working tree changes)"
	}
	return head
}

func probe(name, state, variable, script string, cases, proof []string, args ...string) harness.Step {
	step := harness.Step{Name: name, Cases: cases, Timeout: 12 * time.Minute}
	if state == "" {
		step.BlockedReason = "Provide " + variable + " for the prepared lab topology."
		return step
	}
	if info, err := os.Stat(state); err != nil || !info.IsDir() {
		step.BlockedReason = "The configured lab state directory is unavailable."
		return step
	}
	profiles := map[string]string{"OCEAN_E2E_STATE": "storage-ha", "OCEAN_E2E_SMALL_STATE": "single-farm-3", "OCEAN_E2E_SCALE_STATE": "scale-16",
		"OCEAN_E2E_DOMAIN_STATE": "domain-join", "OCEAN_E2E_IPSEC_LAB_STATE": "single-farm-3"}
	step.LabState, step.LabProfile = state, profiles[variable]
	step.Command = append([]string{"python3", "-B", filepath.Join("lab", script), "--state", state}, args...)
	for _, filename := range proof {
		step.Evidence = append(step.Evidence, harness.EvidenceSource{Name: filename, Path: filepath.Join(state, "evidence", filename)})
	}
	return step
}

func regional(options labOptions, name, script string, cases, proof []string, args ...string) harness.Step {
	return probe(name, options.regional, "OCEAN_E2E_STATE", script, cases, proof, args...)
}

func requireFile(step harness.Step, path, variable string) harness.Step {
	if step.BlockedReason != "" {
		return step
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		step.BlockedReason = "Provide " + variable + " for this probe."
	}
	return step
}
