package nodeagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
)

type telemetryOutbox struct {
	Pending   []telemetry.Observation `json:"pending"`
	Losses    []telemetry.Observation `json:"losses,omitempty"`
	Dropped   int64                   `json:"dropped"`
	Oversized int64                   `json:"oversized,omitempty"`
}

type cgroupUsage struct {
	pid     int
	at      time.Time
	cpuUsec uint64
	memory  int64
}

func sampleID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

func cgroupSample(process containerProcess) (cgroupUsage, error) {
	var usage cgroupUsage
	contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", process.Pid))
	if err != nil {
		return usage, err
	}
	name, ok := strings.CutPrefix(strings.TrimSpace(string(contents)), "0::/")
	if !ok || name == "" || !filepath.IsLocal(name) {
		return usage, errors.New("workload has no dedicated cgroup v2 path")
	}
	root := filepath.Join("/sys/fs/cgroup", name)
	cpu, err := readUsageMicroseconds(root)
	if err != nil {
		return usage, err
	}
	memory, err := os.ReadFile(filepath.Join(root, "memory.current"))
	if err != nil {
		return usage, err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(memory)), 10, 64)
	if err != nil || size < 0 {
		return usage, errors.New("invalid memory cgroup measurement")
	}
	return cgroupUsage{pid: process.Pid, at: time.Now(), cpuUsec: cpu, memory: size}, nil
}

func readUsageMicroseconds(root string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(root, "cpu.stat"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if usec, ok := strings.CutPrefix(line, "usage_usec "); ok {
			return strconv.ParseUint(usec, 10, 64)
		}
	}
	return 0, errors.New("CPU cgroup usage counter is missing")
}

func telemetryAssignmentID(id workload.AssignmentID) telemetry.Assignment {
	return telemetry.Assignment{TenantID: id.TenantID, SubscriptionID: id.SubscriptionID, ID: id.ID, Generation: id.Generation}
}

func (j *joinClient) measureWorkloads(ctx context.Context, previous map[telemetry.Assignment]cgroupUsage,
	running map[telemetryTarget]int) []telemetry.Observation {
	targets := j.telemetryTargets.Load()
	if targets == nil {
		return nil
	}
	results := make([]telemetry.Observation, 0, len(*targets))
	seen := make(map[telemetry.Assignment]bool)
	for _, target := range *targets {
		id := telemetryAssignmentID(target.assignment)
		seen[id] = true
		process, _, err := inspectContainer(ctx, containerName(target.assignment), localPodman)
		if err != nil || !process.Running {
			running[target] = 0
			continue
		}
		running[target] = process.Pid
		current, err := cgroupSample(process)
		if err != nil {
			continue
		}
		prior, exists := previous[id]
		previous[id] = current
		elapsed := current.at.Sub(prior.at)
		if !exists || current.pid != prior.pid || current.cpuUsec < prior.cpuUsec || elapsed < 100*time.Millisecond {
			continue
		}
		millicores := float64(current.cpuUsec-prior.cpuUsec) / float64(elapsed.Milliseconds())
		sample := telemetry.Sample{ID: sampleID(), Time: current.at.UTC(), Usage: &telemetry.Usage{CPUMillis: millicores, MemoryBytes: current.memory}}
		if sample.Valid(current.at) {
			results = append(results, telemetry.Observation{Assignment: id, Sample: sample})
		}
	}
	for id := range previous {
		if !seen[id] {
			delete(previous, id)
		}
	}
	return results
}

func loadTelemetryOutbox(path string) (telemetryOutbox, error) {
	var queue telemetryOutbox
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return queue, nil
	}
	if err != nil {
		return queue, err
	}
	defer func() { _ = file.Close() }()
	const maximum = 4 << 20
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) > maximum || json.Unmarshal(data, &queue) != nil || queue.Dropped < 0 || queue.Oversized < 0 {
		return telemetryOutbox{}, errors.New("invalid persistent telemetry buffer")
	}
	for _, entry := range queue.Losses {
		if entry.Sample.Gap == nil {
			return telemetryOutbox{}, errors.New("invalid persisted telemetry gap")
		}
	}
	return queue, nil
}

func (queue *telemetryOutbox) lose(entry telemetry.Observation, now time.Time) {
	queue.Dropped++
	for index := range queue.Losses {
		current := &queue.Losses[index]
		if current.Assignment != entry.Assignment || current.Sample.Gap == nil {
			continue
		}
		gap := current.Sample.Gap
		gap.Dropped++
		if entry.Sample.Time.Before(gap.From) {
			gap.From = entry.Sample.Time
		}
		if entry.Sample.Time.After(gap.To) {
			gap.To = entry.Sample.Time
		}
		return
	}
	queue.Losses = append(queue.Losses, telemetry.Observation{Assignment: entry.Assignment,
		Sample: telemetry.Sample{ID: sampleID(), Time: now, Gap: &telemetry.Gap{Dropped: 1, From: entry.Sample.Time, To: entry.Sample.Time}}})
}

func (queue *telemetryOutbox) checkpoint(path string, budget int) error {
	now := time.Now().UTC()
	for {
		data, err := json.Marshal(queue)
		if err != nil {
			return err
		}
		if len(data) <= budget {
			if err := replaceRuntimeFile(path, data); err != nil {
				return err
			}
			directory, err := os.Open(filepath.Dir(path))
			if err != nil {
				return err
			}
			return errors.Join(directory.Sync(), directory.Close())
		}
		if len(queue.Pending) != 0 {
			queue.lose(queue.Pending[0], now)
			queue.Pending = queue.Pending[1:]
		} else if len(queue.Losses) != 0 {
			queue.Oversized += queue.Losses[0].Sample.Gap.Dropped
			queue.Losses = queue.Losses[1:]
		} else {
			return errors.New("telemetry buffer budget is too small")
		}
	}
}

func (queue *telemetryOutbox) expire(now time.Time) {
	losses := queue.Losses[:0]
	for _, entry := range queue.Losses {
		if entry.Sample.Valid(now) {
			losses = append(losses, entry)
		} else {
			queue.Oversized += entry.Sample.Gap.Dropped
		}
	}
	queue.Losses = losses
	pending := queue.Pending[:0]
	for _, entry := range queue.Pending {
		if entry.Sample.Valid(now) {
			pending = append(pending, entry)
		} else {
			queue.lose(entry, now)
		}
	}
	queue.Pending = pending
}

func (j *joinClient) flushTelemetry(ctx context.Context, queue *telemetryOutbox) error {
	losses := min(telemetry.MaxBatch, len(queue.Losses))
	pending := min(telemetry.MaxBatch-losses, len(queue.Pending))
	if losses+pending == 0 {
		return nil
	}
	observations := append(append([]telemetry.Observation{}, queue.Losses[:losses]...), queue.Pending[:pending]...)
	data, err := json.Marshal(telemetry.Batch{Observations: observations})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/telemetry", bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	reply, err := j.client.Do(request)
	if err != nil {
		return err
	}
	_ = reply.Body.Close()
	if reply.StatusCode != http.StatusNoContent {
		return fmt.Errorf("telemetry ingestion returned HTTP %d", reply.StatusCode)
	}
	queue.Losses, queue.Pending = queue.Losses[losses:], queue.Pending[pending:]
	return nil
}

func (j *joinClient) runTelemetry(ctx context.Context, logger *slog.Logger) {
	budget := j.config.TelemetryBufferBytes
	if budget == 0 {
		return
	}
	path := filepath.Join(j.config.StateDirectory, "telemetry-outbox.json")
	queue, err := loadTelemetryOutbox(path)
	if err != nil {
		logger.Error("load the telemetry buffer", "error", err)
		return
	}
	previous := make(map[telemetry.Assignment]cgroupUsage)
	relays := make(map[string]*functionRelay)
	defer func() {
		for _, relay := range relays {
			relay.close()
		}
	}()
	submissions := make(chan telemetrySubmission, 8)
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	var unavailable bool
	for {
		select {
		case <-ctx.Done():
			return
		case submission := <-submissions:
			queue.Pending = append(queue.Pending, submission.observations...)
			submission.persisted <- queue.checkpoint(path, budget)
			continue
		case <-ticker.C:
		}
		round, cancel := context.WithTimeout(ctx, 3*time.Second)
		running := make(map[telemetryTarget]int)
		queue.Pending = append(queue.Pending, j.measureWorkloads(round, previous, running)...)
		cancel()
		j.reconcileTelemetryRelays(ctx, logger, running, relays, submissions)
		queue.expire(time.Now().UTC())
		if err := queue.checkpoint(path, budget); err != nil {
			logger.Warn("persist telemetry buffer", "error", err)
			continue
		}
		send, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		err = j.flushTelemetry(send, &queue)
		cancel()
		if err != nil && !unavailable {
			logger.Warn("telemetry ingestion will retry", "error", err)
		}
		if err == nil && unavailable {
			logger.Info("telemetry ingestion recovered")
		}
		unavailable = err != nil
		if err == nil {
			_ = queue.checkpoint(path, budget)
		}
	}
}
