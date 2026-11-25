package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	Pass    = "PASS"
	Fail    = "FAIL"
	Blocked = "BLOCKED"
	Skip    = "SKIP"
)

const maxLogBytes = 4 << 20
const maxEvidenceBytes = 32 << 20

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$`)

type Step struct {
	Name          string
	Cases         []string
	Command       []string
	Timeout       time.Duration
	Evidence      []EvidenceSource
	BlockedReason string
	LabState      string
	LabProfile    string
}

type EvidenceSource struct {
	Path string
	Name string
}

type Outcome struct {
	Name     string
	Cases    []string
	Status   string
	Duration time.Duration
	Evidence []string
	Detail   string
}

type Runner struct {
	Root      string
	Directory string
	Evidence  string
}

func Start(root, resultRoot, id string) (Runner, error) {
	if !identifier.MatchString(id) {
		return Runner{}, errors.New("the acceptance run ID must be a safe directory name")
	}
	if err := os.MkdirAll(resultRoot, 0o755); err != nil {
		return Runner{}, err
	}
	dir := filepath.Join(resultRoot, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Runner{}, err
	}
	evidence := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		return Runner{}, err
	}
	return Runner{Root: root, Directory: dir, Evidence: evidence}, nil
}

type cappedLog struct {
	bytes.Buffer
	discarded int
}

func (log *cappedLog) Write(data []byte) (int, error) {
	length := min(len(data), maxLogBytes-log.Len())
	_, err := log.Buffer.Write(data[:length])
	log.discarded += len(data) - length
	return len(data), err
}

var credentialText = regexp.MustCompile(`(?i)(bearer\s+|--(?:cert-password|password|client-secret)(?:\s+|=|['"]\s*,\s*['"])|(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|x-functions-key|accountkey|machinekey_decryptionkey)['"]?\s*[:=]\s*["']?)[^'"\s,;\]}]+`)

func redact(value string) string {
	return credentialText.ReplaceAllString(value, "${1}[redacted]")
}

func (runner Runner) Execute(ctx context.Context, step Step) Outcome {
	out := Outcome{Name: step.Name, Cases: step.Cases, Status: Blocked}
	if step.BlockedReason != "" {
		out.Detail = step.BlockedReason
		return out
	}
	if len(step.Command) == 0 || !identifier.MatchString(step.Name) || step.Timeout <= 0 {
		out.Detail = "Invalid local probe definition."
		return out
	}
	deadline, cancel := context.WithTimeout(ctx, step.Timeout)
	defer cancel()
	command := exec.CommandContext(deadline, step.Command[0], step.Command[1:]...)
	command.Dir = runner.Root
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "AZURE_CORE_COLLECT_TELEMETRY=0")
	var log cappedLog
	command.Stdout, command.Stderr = &log, &log
	started := time.Now()
	runErr := command.Run()
	out.Duration = time.Since(started)
	name := step.Name + ".log"
	logs := redact(fmt.Sprintf("Command %q\n\n", step.Command)) + redact(log.String())
	if log.discarded > 0 {
		logs += fmt.Sprintf("\n[Omitted %d bytes after the log limit.]\n", log.discarded)
	}
	if err := os.WriteFile(filepath.Join(runner.Evidence, name), []byte(logs), 0o600); err != nil {
		out.Status, out.Detail = Fail, err.Error()
		return out
	}
	out.Evidence = append(out.Evidence, filepath.ToSlash(filepath.Join("evidence", name)))
	if runErr != nil {
		out.Status = Fail
		if errors.Is(deadline.Err(), context.DeadlineExceeded) {
			out.Detail = fmt.Sprintf("Probe exceeded its %s deadline.", step.Timeout)
		} else {
			out.Detail = "Probe failed. See the captured output."
		}
		return out
	}
	for _, source := range step.Evidence {
		if !identifier.MatchString(source.Name) {
			out.Status, out.Detail = Fail, "Invalid evidence file name."
			return out
		}
		artifact := step.Name + "-" + source.Name
		if err := copyEvidence(source.Path, filepath.Join(runner.Evidence, artifact), started); err != nil {
			out.Status, out.Detail = Fail, fmt.Sprintf("Evidence %s is invalid: %v", source.Name, err)
			return out
		}
		out.Evidence = append(out.Evidence, filepath.ToSlash(filepath.Join("evidence", artifact)))
	}
	out.Status = Pass
	out.Detail = "Local probe passed."
	return out
}

func copyEvidence(source, destination string, started time.Time) error {
	read, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = read.Close() }()
	info, err := read.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.ModTime().Before(started) || info.Size() > maxEvidenceBytes || info.Size() == 0 {
		return errors.New("expected a fresh bounded non-empty regular file")
	}
	data, err := io.ReadAll(io.LimitReader(read, maxEvidenceBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxEvidenceBytes {
		return errors.New("evidence exceeds its size limit")
	}
	if ext := strings.ToLower(filepath.Ext(destination)); ext == ".log" || ext == ".txt" {
		data = []byte(redact(string(data)))
	}
	return os.WriteFile(destination, data, 0o600)
}
