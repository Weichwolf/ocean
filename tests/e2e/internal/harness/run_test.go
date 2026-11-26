package harness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOldEvidenceCannotPass(t *testing.T) {
	root := t.TempDir()
	runner, err := Start(root, root, "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "previous.json")
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := time.Now().Add(-time.Hour)
	if err := os.Chtimes(source, previous, previous); err != nil {
		t.Fatal(err)
	}
	outcome := runner.Execute(context.Background(), Step{Name: "probe", Timeout: time.Second,
		Command:  []string{"sh", "-c", "printf '%s\\n' 'Authorization: Bearer opaque-token'"},
		Evidence: []EvidenceSource{{Path: source, Name: "probe.json"}}})
	if outcome.Status != Fail || !strings.Contains(outcome.Detail, "fresh") {
		t.Fatalf("an old evidence file passed acceptance: %#v", outcome)
	}
	data, err := os.ReadFile(filepath.Join(runner.Evidence, "probe.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "opaque-token") || !strings.Contains(string(data), "[redacted]") {
		t.Fatalf("probe output did not redact its Authorization header: %s", data)
	}
}

func TestAggregatePreservesGroupedFailuresAndMissingSteps(t *testing.T) {
	cases := []Case{{ID: "LAB-01", Gate: "required"}, {ID: "LAB-02", Gate: "required"}, {ID: "LAB-03", Gate: "required"}}
	outcomes := []Outcome{
		{Name: "required-topology", Cases: []string{"LAB-01", "LAB-02"}, Status: Pass, Duration: time.Second,
			Evidence: []string{"evidence/topology.json"}},
		{Name: "required-capacity", Cases: []string{"LAB-02"}, Status: Fail, Duration: 2 * time.Second, Detail: "capacity disagreed"},
	}
	result := Aggregate(cases, outcomes)
	if len(result) != 3 || result[0].Status != Pass || result[1].Status != Fail || result[1].Duration != 3*time.Second ||
		result[2].Status != Blocked || !strings.Contains(result[1].Detail, "capacity disagreed") {
		t.Fatalf("unexpected required case results: %#v", result)
	}
}

func TestGoProbeRequiresAnActualTestPass(t *testing.T) {
	root := t.TempDir()
	fixture := `package probe
import "testing"
func TestPass(t *testing.T) { t.Log("fixture ran") }
func TestSkip(t *testing.T) { t.Skip("fixture unavailable") }
func TestPartial(t *testing.T) {
	t.Run("checked", func(t *testing.T) {})
	t.Run("missing", func(t *testing.T) { t.Skip("fixture unavailable") })
}
func TestFail(t *testing.T) { t.Fatal("fixture assertion failed") }
`
	for name, contents := range map[string]string{"go.mod": "module example.test/probe\n", "probe_test.go": fixture} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := Start(root, root, "acceptance")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ test, status, detail, output string }{
		{"TestPass", Pass, "", "fixture ran"},
		{"TestSkip", Blocked, "was skipped", "fixture unavailable"},
		{"TestPartial", Blocked, "was skipped", "fixture unavailable"},
		{"TestMissing", Blocked, "did not run any matching tests", "no tests to run"},
		{"TestFail", Fail, "Probe failed", "fixture assertion failed"},
	} {
		t.Run(tc.test, func(t *testing.T) {
			outcome := runner.Execute(t.Context(), Step{Name: tc.test, Timeout: time.Minute,
				Command: []string{"go", "test", "-run", "^" + tc.test + "$", "."}})
			if outcome.Status != tc.status || !strings.Contains(outcome.Detail, tc.detail) {
				t.Errorf("unexpected outcome: %#v", outcome)
			}
			data, err := os.ReadFile(filepath.Join(runner.Evidence, tc.test+".log"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.output) {
				t.Errorf("probe log missing %q: %s", tc.output, data)
			}
		})
	}
}
