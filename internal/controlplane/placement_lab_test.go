//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalPlacement(t *testing.T) {
	stage := os.Getenv("OCEAN_E2E_PLACEMENT")
	if stage == "" {
		t.Skip("requires registered lab hosts")
	}
	region := openLabRegion(t)
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	scope := arm.SubscriptionScope{TenantID: os.Getenv("OCEAN_E2E_TENANT"), SubscriptionID: os.Getenv("OCEAN_E2E_SUBSCRIPTION")}
	small, large := os.Getenv("OCEAN_E2E_SMALL_HOST"), os.Getenv("OCEAN_E2E_LARGE_HOST")
	capacity := func(cpu, memory int64) enrollment.Capacity {
		return enrollment.Capacity{CPUMillis: cpu, MemoryMiB: memory}
	}
	request := func(id string, cpu, memory int64) PlacementRequest {
		return PlacementRequest{ID: id, Cell: "cell-1", Role: "compute", Resources: capacity(cpu, memory)}
	}
	policy := func(pool string, quota enrollment.Capacity) {
		t.Helper()
		if err := region.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{pool}, Quota: quota}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, _ = region.client.Delete(cleanup, region.armPrefix(scope)+"placement-policy")
	})
	reserve := func(wanted PlacementRequest) Reservation {
		t.Helper()
		result, err := region.ReservePlacement(ctx, scope, wanted)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	release := func(result Reservation) {
		t.Helper()
		if err := region.ReleasePlacement(ctx, scope, result.Cell, result.ID, result.Generation); err != nil {
			t.Fatal(err)
		}
	}
	denied := func(wanted PlacementRequest, expected error) {
		t.Helper()
		if _, err := region.ReservePlacement(ctx, scope, wanted); !errors.Is(err, expected) {
			t.Fatalf("placement returned %v, want %v", err, expected)
		}
	}
	available := func(id string, cpu int64) enrollment.Capacity {
		t.Helper()
		value, err := region.client.Get(ctx, region.hostKey("live", id))
		var entry enrollment.Availability
		if err != nil || len(value.Kvs) != 1 || value.Kvs[0].Lease == 0 || json.Unmarshal(value.Kvs[0].Value, &entry) != nil ||
			entry.HostID != id || entry.Capacity.CPUMillis != cpu || entry.Capacity.MemoryMiB <= 0 {
			t.Fatalf("unexpected leased capacity for %s: %+v, %v", id, entry, err)
		}
		return entry.Capacity
	}
	available(small, 900)
	_, largerIdentity, _, err := region.Enrollment(ctx, large)
	if err != nil || largerIdentity == nil {
		t.Fatalf("cannot read the larger host's registered identity: %v", err)
	}
	if stage == "disconnected" {
		value, err := region.client.Get(ctx, region.hostKey("live", large), clientv3.WithCountOnly())
		if err != nil || value.Count != 0 {
			t.Fatalf("the stopped host still advertises capacity: %v", err)
		}
		policy("lab-default", capacity(3000, 3000))
		denied(request("disconnected-host", 1200, 512), ErrNoEligibleHost)
		if _, err := region.HostAssignments(ctx, large, largerIdentity.Certificate, ""); !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatalf("a disconnected host received assignments: %v", err)
		}
		return
	}
	if stage != "active" {
		t.Fatalf("unsupported lab placement stage %q", stage)
	}
	largeCapacity := available(large, 1900)
	policy("forbidden-pool", capacity(5000, 5000))
	denied(request("no-pool", 100, 128), ErrNoEligibleHost)
	policy("lab-default", capacity(5000, 5000))
	denied(request("oversized", largeCapacity.CPUMillis+1, 512), ErrNoEligibleHost)
	fit := reserve(request("large-only", 1200, 512))
	if fit.HostID != large || fit.Pool != "lab-default" {
		t.Fatalf("the larger placement landed on %s", fit.HostID)
	}
	release(fit)

	policy("lab-default", capacity(700, 384))
	wanted := request("same-request", 700, 384)
	results, errs := placementRace(ctx, region, scope, wanted, wanted)
	if errs[0] != nil || errs[1] != nil || results[0] != results[1] || results[0].HostID != small {
		t.Fatalf("a concurrent retry did not preserve its sole allocation: %v %v", results, errs)
	}
	_, smallerIdentity, _, err := region.Enrollment(ctx, small)
	if err != nil || smallerIdentity == nil {
		t.Fatalf("cannot read the smaller host's registered identity: %v", err)
	}
	assignments, err := region.HostAssignments(ctx, small, smallerIdentity.Certificate, "")
	if err != nil || len(assignments.Assignments) != 1 || assignments.Assignments[0].ID != wanted.ID ||
		assignments.Assignments[0].Generation != results[0].Generation || assignments.Assignments[0].SubscriptionID != scope.SubscriptionID {
		t.Fatalf("the host did not receive its committed assignment: %+v %v", assignments, err)
	}
	if _, err := region.HostAssignments(ctx, small, largerIdentity.Certificate, ""); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("a different host acquired the assignment: %v", err)
	}
	otherCell := wanted
	otherCell.Cell = "other-cell"
	denied(otherCell, ErrReservationChanged)
	release(results[0])
	release(results[0])
	assignments, err = region.HostAssignments(ctx, small, smallerIdentity.Certificate, "")
	if err != nil || len(assignments.Assignments) != 0 {
		t.Fatalf("the released assignment remained visible: %+v %v", assignments, err)
	}

	requests := []PlacementRequest{request("quota-race-a", 700, 384), request("quota-race-b", 700, 384)}
	results, errs = placementRace(ctx, region, scope, requests[0], requests[1])
	accepted, rejected := -1, -1
	for index, err := range errs {
		switch {
		case err == nil:
			accepted = index
		case errors.Is(err, ErrQuotaExceeded):
			rejected = index
		default:
			t.Fatal(err)
		}
	}
	if accepted == -1 || rejected == -1 {
		t.Fatalf("the regional quota admitted the wrong number of requests: %v", errs)
	}
	used, err := region.counter(ctx, region.armPrefix(scope)+"placement-usage")
	if err != nil || used.used != requests[accepted].Resources {
		t.Fatalf("quota accounting after concurrent reservations: %+v %v", used, err)
	}
	release(results[accepted])
	release(reserve(requests[rejected]))

	policy("lab-default", capacity(3000, 3000))
	base := request("drain-preserved", 200, 128)
	prior := reserve(base)
	if prior.HostID != small || region.SetHostDraining(ctx, small, true) != nil {
		t.Fatal("could not drain the initial placement host")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = region.SetHostDraining(cleanup, small, false)
	})
	if retry := reserve(base); retry != prior {
		t.Fatal("drain moved an acknowledged reservation")
	}
	relocated := reserve(request("drain-new", 200, 128))
	if relocated.HostID != large {
		t.Fatalf("a new placement used draining host %s", relocated.HostID)
	}
	release(relocated)
	release(prior)
	newReservation := reserve(base)
	if err := region.ReleasePlacement(ctx, scope, prior.Cell, prior.ID, prior.Generation); !errors.Is(err, ErrReservationChanged) {
		t.Fatalf("stale cleanup did not reject a newer reservation: %v", err)
	}
	release(newReservation)
	used, err = region.counter(ctx, region.armPrefix(scope)+"placement-usage")
	if err != nil || used.used != (enrollment.Capacity{}) {
		t.Fatalf("cleanup left a reservation charged against the tenant: %+v %v", used, err)
	}
}

func placementRace(ctx context.Context, region *Region, scope arm.SubscriptionScope, first, second PlacementRequest) ([2]Reservation, [2]error) {
	var results [2]Reservation
	var failures [2]error
	var wg sync.WaitGroup
	start := make(chan struct{})
	wanted := [2]PlacementRequest{first, second}
	for index := range wanted {
		wg.Go(func() {
			<-start
			results[index], failures[index] = region.ReservePlacement(ctx, scope, wanted[index])
		})
	}
	close(start)
	wg.Wait()
	return results, failures
}
