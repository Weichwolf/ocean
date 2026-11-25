package nodeagent

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
)

func TestBoundedTelemetryCheckpointPersistsGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.json")
	now := time.Now().Add(-time.Minute).UTC()
	var queue telemetryOutbox
	const budget = 4096
	for i := range 50 {
		queue.Pending = append(queue.Pending, telemetry.Observation{
			Assignment: telemetry.Assignment{TenantID: "tenant", SubscriptionID: "subscription", ID: "workload", Generation: "generation"},
			Sample: telemetry.Sample{ID: fmt.Sprintf("%032x", i), Time: now.Add(time.Duration(i) * time.Second),
				Usage: &telemetry.Usage{CPUMillis: 450, MemoryBytes: 8 << 20}},
		})
	}
	if err := queue.checkpoint(path, budget); err != nil {
		t.Fatal(err)
	}
	recovered, err := loadTelemetryOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Losses) != 1 || recovered.Dropped == 0 || int(recovered.Dropped)+len(recovered.Pending) != 50 ||
		info.Size() > budget || recovered.Oversized != 0 {
		t.Fatalf("invalid bounded checkpoint: size=%d pending=%d losses=%d dropped=%d", info.Size(), len(recovered.Pending),
			len(recovered.Losses), recovered.Dropped)
	}
	observed := recovered.Losses[0].Sample
	if observed.Gap.Dropped != recovered.Dropped || !observed.Gap.From.Equal(now) || !observed.Valid(time.Now()) {
		t.Fatal("the persisted loss interval does not cover the evicted samples")
	}
	recovered.lose(recovered.Pending[0], time.Now().UTC())
	if sample := recovered.Losses[0].Sample; sample.ID != observed.ID || !sample.Time.Equal(observed.Time) {
		t.Fatal("extending a pending gap must retain its idempotency key")
	}
}
