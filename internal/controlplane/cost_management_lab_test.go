//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/costmanagement"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalCostLedger(t *testing.T) {
	if os.Getenv("OCEAN_E2E_COST_LEDGER") != "1" {
		t.Skip("requires the disposable regional etcd cluster")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	r := openLabRegion(t)
	r.root = "/ocean/v1/regions/cost-lab-" + operationID()
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := r.client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	r.telemetry = &telemetryControl{client: r.client, retention: 300}
	config := &costmanagement.RateConfig{Currency: "CHF", CPUPerHour: "0.018", MemoryPerGiBHour: "0.036"}
	var err error
	r.cost, err = openCostManagement(config)
	if err != nil {
		t.Fatal(err)
	}
	const hostID = "cost-worker"
	cert := []byte("fixture host certificate")
	host := enrollment.Host{HostID: hostID, Cell: "ledger", Pool: "lab", Roles: []string{"compute"}, Certificate: cert}
	live := enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles}
	lease, err := r.client.Grant(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	liveJSON, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.hostKey("registered", hostID), host),
		clientv3.OpPut(r.hostKey("live", hostID), string(liveJSON), clientv3.WithLease(lease.ID))).Commit(); err != nil {
		t.Fatal(err)
	}

	owner := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	foreign := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	site := arm.ResourceAddress{Group: "one", Path: workload.ContainerGroupType + "/main"}
	next := arm.ResourceAddress{Group: "two", Path: workload.ContainerGroupType + "/main"}
	a := seedCostAssignment(t, ctx, r, owner, site, hostID)
	b := seedCostAssignment(t, ctx, r, owner, next, hostID)
	c := seedCostAssignment(t, ctx, r, foreign, site, hostID)
	today := costmanagement.Day(time.Now())
	yesterday := today.AddDate(0, 0, -1)
	tomorrow := today.AddDate(0, 0, 1)
	const gib = 1 << 30
	first := costProbeSample(a, today.Add(500*time.Millisecond), 1_000_001, gib)
	second := costProbeSample(a, today.Add(1500*time.Millisecond), 500_000, 2*gib)
	oldFormat := costProbeSample(a, today.Add(2500*time.Millisecond), 800_000, gib)
	oldFormat.Sample.Usage.Interval = nil
	stale := costProbeSample(a, today.Add(2500*time.Millisecond), 800_000, gib)
	stale.Assignment.Generation = operationID()
	batch := telemetry.Batch{Observations: []telemetry.Observation{second, first, oldFormat, stale, first,
		costProbeSample(b, today.Add(1000*time.Millisecond), 250_000, 4*gib),
		costProbeSample(c, today.Add(1000*time.Millisecond), 900_000, 8*gib)}}
	replica := *r
	replica.cost, err = openCostManagement(config)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 2)
	for _, server := range []*Region{r, &replica} {
		go func() { accepted <- server.ReportTelemetry(ctx, hostID, cert, batch) }()
	}
	for range 2 {
		if err := <-accepted; err != nil {
			t.Fatal(err)
		}
	}
	replayed := telemetry.Batch{Observations: []telemetry.Observation{costProbeSample(a, today.Add(-time.Second), 120_000, gib)}}
	if err := r.ReportTelemetry(ctx, hostID, cert, replayed); err != nil {
		t.Fatal(err)
	}
	read := func(scope arm.SubscriptionScope, group string) []costmanagement.Record {
		t.Helper()
		rates, rows, err := r.CostRecords(ctx, scope, group, yesterday, tomorrow)
		if err != nil || rates.Currency != "CHF" {
			t.Fatalf("could not read Swiss-franc usage records: %v", err)
		}
		return rows
	}
	site.Path = strings.ToLower(site.Path)
	next.Path = strings.ToLower(next.Path)
	want := []costmanagement.Record{
		{ResourceID: site.ID(owner), Day: yesterday, Totals: costmanagement.Totals{CPUTimeMicros: 500_000, MemoryByteMillis: 500 * gib}},
		{ResourceID: site.ID(owner), Day: today, Totals: costmanagement.Totals{CPUTimeMicros: 1_000_001, MemoryByteMillis: 2500 * gib}},
		{ResourceID: next.ID(owner), Day: today, Totals: costmanagement.Totals{CPUTimeMicros: 250_000, MemoryByteMillis: 4000 * gib}},
	}
	if got := read(owner, ""); !slices.Equal(got, want) {
		t.Fatalf("unexpected midnight split, scope, or retry totals: %+v, expected %+v", got, want)
	}
	if rows := read(foreign, ""); len(rows) != 1 || rows[0].ResourceID != site.ID(foreign) || rows[0].Totals.CPUTimeMicros != 900_000 {
		t.Fatalf("the foreign ledger did not stay in its subscription: %+v", rows)
	}
	if _, err := r.client.Txn(ctx).Then(clientv3.OpDelete(r.armPrefix(owner)+"telemetry/", clientv3.WithPrefix()),
		clientv3.OpDelete(r.containerKey(owner, site))).Commit(); err != nil {
		t.Fatal(err)
	}
	if got := read(owner, "one"); !slices.Equal(got, want[:2]) {
		t.Fatalf("raw telemetry expiry or deletion discarded historical costs: %+v", got)
	}
	replica.cost, err = openCostManagement(&costmanagement.RateConfig{Currency: "CHF", CPUPerHour: "0.02", MemoryPerGiBHour: "0.036"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := replica.CostRecords(ctx, owner, "", yesterday, tomorrow); !errors.Is(err, costmanagement.ErrUnavailable) {
		t.Fatalf("a mismatched replica could reprice committed usage: %v", err)
	}
	t.Log("The live ledger conserved the measured midnight split, deduplicated concurrent delivery, preserved deleted-resource history, and held the recorded rates and tenant scope.")
}

func seedCostAssignment(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope,
	address arm.ResourceAddress, host string) telemetry.Assignment {
	t.Helper()
	assignment := telemetry.Assignment{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, ID: operationID(), Generation: operationID()}
	record := containerRecord{Address: address, Reservation: Reservation{PlacementRequest: PlacementRequest{ID: assignment.ID},
		HostID: host, Generation: assignment.Generation}}
	key := r.containerKey(scope, address)
	if _, err := r.client.Txn(ctx).Then(putJSON(key, record), clientv3.OpPut(r.hostContainerKey(scope, host, assignment.ID), key)).Commit(); err != nil {
		t.Fatal(err)
	}
	return assignment
}

func costProbeSample(assignment telemetry.Assignment, end time.Time, cpu, memory int64) telemetry.Observation {
	return telemetry.Observation{Assignment: assignment, Sample: telemetry.Sample{ID: strings.ReplaceAll(operationID(), "-", ""), Time: end,
		Usage: &telemetry.Usage{CPUMillis: float64(cpu) / 1000, MemoryBytes: memory,
			Interval: &telemetry.UsageInterval{Milliseconds: 1000, CPUTimeMicros: cpu}}}}
}
