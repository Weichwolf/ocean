package harness

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Case     Case
	Status   string
	Duration time.Duration
	Evidence []string
	Detail   string
}

type RunMetadata struct {
	ID         string
	Profile    string
	Revision   string
	StartedAt  time.Time
	FinishedAt time.Time
	Inputs     map[string]string
}

func Aggregate(selected []Case, outcomes []Outcome) []Result {
	results := make([]Result, 0, len(selected))
	weight := map[string]int{Pass: 0, Skip: 1, Blocked: 2, Fail: 3}
	byCase := make(map[string][]Outcome)
	for _, outcome := range outcomes {
		for _, id := range outcome.Cases {
			byCase[id] = append(byCase[id], outcome)
		}
	}
	for _, c := range selected {
		result := Result{Case: c, Status: Pass}
		probes := byCase[c.ID]
		if len(probes) == 0 {
			result.Status, result.Detail = Blocked, "This profile has no local probe for the selected case."
		}
		var notes []string
		for _, probe := range probes {
			rank, known := weight[probe.Status]
			if !known {
				probe.Status, probe.Detail, rank = Fail, "Probe returned an invalid result status.", weight[Fail]
			}
			if rank > weight[result.Status] {
				result.Status = probe.Status
			}
			result.Duration += probe.Duration
			result.Evidence = append(result.Evidence, probe.Evidence...)
			if probe.Status != Pass {
				notes = append(notes, probe.Name+" — "+probe.Detail)
			}
		}
		if len(notes) > 0 {
			result.Detail = strings.Join(notes, " ")
		}
		if result.Detail == "" {
			result.Detail = fmt.Sprintf("%d local probe(s) passed.", len(probes))
		}
		results = append(results, result)
	}
	return results
}

func (runner Runner) WriteReports(meta RunMetadata, results []Result) error {
	return errors.Join(runner.writeTSV(results), runner.writeMarkdown(meta, results))
}

func (runner Runner) writeTSV(results []Result) error {
	var body bytes.Buffer
	file := csv.NewWriter(&body)
	file.Comma = '\t'
	if err := file.Write([]string{"case_id", "status", "duration_ms", "evidence", "detail"}); err != nil {
		return err
	}
	for _, result := range results {
		if err := file.Write([]string{result.Case.ID, result.Status, strconv.FormatInt(result.Duration.Milliseconds(), 10),
			strings.Join(result.Evidence, ","), result.Detail}); err != nil {
			return err
		}
	}
	file.Flush()
	if err := file.Error(); err != nil {
		return err
	}
	return saveReport(filepath.Join(runner.Directory, "results.tsv"), body.Bytes())
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.Join(strings.Fields(value), " ")
}

func (runner Runner) writeMarkdown(meta RunMetadata, results []Result) error {
	var report strings.Builder
	fmt.Fprintf(&report, "# Ocean end-to-end run %s\n\n", meta.ID)
	fmt.Fprintf(&report, "- Profile **%s**\n- Revision `%s`\n- Started %s\n- Finished %s\n",
		markdownCell(meta.Profile), markdownCell(meta.Revision), meta.StartedAt.UTC().Format(time.RFC3339), meta.FinishedAt.UTC().Format(time.RFC3339))
	keys := make([]string, 0, len(meta.Inputs))
	for name := range meta.Inputs {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(&report, "- %s %s\n", markdownCell(name), markdownCell(meta.Inputs[name]))
	}
	counts := make(map[string]int)
	required := 0
	for _, result := range results {
		counts[result.Status]++
		if result.Case.Gate == "required" {
			required++
		}
	}
	fmt.Fprintf(&report, "\n%d selected cases, including %d required cases. **%d passed, %d failed, %d blocked, %d skipped.**\n\n",
		len(results), required, counts[Pass], counts[Fail], counts[Blocked], counts[Skip])
	report.WriteString("[Machine-readable results](results.tsv)\n\n")
	report.WriteString("| Case | Scenario | Gate | Result | Duration (ms) | Evidence | Detail |\n| --- | --- | --- | --- | ---: | --- | --- |\n")
	for _, result := range results {
		links := make([]string, 0, len(result.Evidence))
		for _, path := range result.Evidence {
			links = append(links, fmt.Sprintf("[%s](%s)", filepath.Base(path), path))
		}
		fmt.Fprintf(&report, "| %s | %s | %s | %s | %d | %s | %s |\n",
			result.Case.ID, markdownCell(result.Case.Scenario), result.Case.Gate, result.Status, result.Duration.Milliseconds(),
			strings.Join(links, ", "), markdownCell(result.Detail))
	}
	return saveReport(filepath.Join(runner.Directory, "report.md"), []byte(report.String()))
}

func saveReport(path string, content []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, writeError := file.Write(content)
	if err := errors.Join(writeError, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
