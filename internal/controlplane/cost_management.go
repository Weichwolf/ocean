package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/costmanagement"
	"github.com/Weichwolf/ocean/internal/telemetry"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type costManagementControl struct {
	ratesJSON string
	rates     costmanagement.Rates
	mu        sync.Mutex
	lease     clientv3.LeaseID
	leasedAt  time.Time
}

func openCostManagement(config *costmanagement.RateConfig) (*costManagementControl, error) {
	if config == nil {
		return nil, nil
	}
	rates, err := config.Rates()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rates)
	if err != nil {
		return nil, err
	}
	return &costManagementControl{rates: rates, ratesJSON: string(encoded)}, nil
}

func (r *Region) costRatesKey() string { return r.root + "/cost-management/rates" }

func (r *Region) ensureCostRates(ctx context.Context) error {
	key := r.costRatesKey()
	result, err := r.telemetry.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.cost.ratesJSON)).Else(clientv3.OpGet(key)).Commit()
	if err != nil {
		return err
	}
	if result.Succeeded {
		return nil
	}
	rows := result.Responses[0].GetResponseRange().Kvs
	if len(rows) != 1 || string(rows[0].Value) != r.cost.ratesJSON {
		return errors.New("cost management rates differ from the rates recorded in the usage ledger")
	}
	return nil
}

func (r *Region) costLease(ctx context.Context) (clientv3.LeaseID, error) {
	r.cost.mu.Lock()
	defer r.cost.mu.Unlock()
	now := time.Now()
	if r.cost.lease != 0 && now.Sub(r.cost.leasedAt) < time.Hour {
		return r.cost.lease, nil
	}
	// The additional day covers hourly lease reuse and whole-day queries.
	duration := int64((costmanagement.HistoryDays + 1) * 24 * 60 * 60)
	granted, err := r.telemetry.client.Grant(ctx, duration)
	if err != nil {
		return 0, err
	}
	r.cost.lease, r.cost.leasedAt = granted.ID, now
	return granted.ID, nil
}

func (r *Region) costDayPrefix(scope arm.SubscriptionScope, day time.Time) string {
	return r.armPrefix(scope) + "cost-management/days/" + day.Format(time.DateOnly) + "/"
}

type costMeasurement struct {
	start, end time.Time
	cpuMicros  int64
	memory     int64
}

func measureCost(sample telemetry.Sample) costMeasurement {
	usage, end := sample.Usage, sample.Time.UTC().Truncate(time.Millisecond)
	return costMeasurement{start: end.Add(-time.Duration(usage.Interval.Milliseconds) * time.Millisecond),
		end: end, cpuMicros: usage.Interval.CPUTimeMicros, memory: usage.MemoryBytes}
}

func addCostMeasurement(totals map[time.Time]costmanagement.Totals, sample costMeasurement) {
	firstDay := costmanagement.Day(sample.start)
	boundary := firstDay.AddDate(0, 0, 1)
	milliseconds := sample.end.Sub(sample.start).Milliseconds()
	if !sample.end.After(boundary) {
		accumulateCost(totals, firstDay, sample.cpuMicros, milliseconds*sample.memory)
		return
	}
	firstMilliseconds := boundary.Sub(sample.start).Milliseconds()
	firstCPU := sample.cpuMicros * firstMilliseconds / milliseconds
	accumulateCost(totals, firstDay, firstCPU, firstMilliseconds*sample.memory)
	accumulateCost(totals, boundary, sample.cpuMicros-firstCPU, (milliseconds-firstMilliseconds)*sample.memory)
}

func accumulateCost(totals map[time.Time]costmanagement.Totals, day time.Time, cpu, memory int64) {
	row := totals[day]
	row.CPUTimeMicros += cpu
	row.MemoryByteMillis += memory
	totals[day] = row
}

func (r *Region) recordCostMeasurements(ctx context.Context, batches map[telemetryBinding][]costMeasurement) error {
	if len(batches) == 0 {
		return nil
	}
	if err := r.ensureCostRates(ctx); err != nil {
		return err
	}
	lease, err := r.costLease(ctx)
	if err != nil {
		return err
	}
	for target, samples := range batches {
		if err := r.recordCostResource(ctx, target, samples, lease); err != nil {
			return err
		}
	}
	return nil
}

func (r *Region) recordCostResource(ctx context.Context, target telemetryBinding, samples []costMeasurement, lease clientv3.LeaseID) error {
	slices.SortFunc(samples, func(a, b costMeasurement) int {
		if cmp := a.end.Compare(b.end); cmp != 0 {
			return cmp
		}
		return a.start.Compare(b.start)
	})
	watermark := r.armPrefix(target.scope) + "cost-management/observed/" + target.address.Key()
	for range 8 {
		previous, err := r.telemetry.client.Get(ctx, watermark)
		if err != nil {
			return err
		}
		var last time.Time
		var revision int64
		if len(previous.Kvs) != 0 {
			item := previous.Kvs[0]
			if json.Unmarshal(item.Value, &last) != nil || last.IsZero() {
				return errors.New("invalid cost measurement watermark")
			}
			revision = item.ModRevision
		}
		daily := make(map[time.Time]costmanagement.Totals)
		for _, sample := range samples {
			// Any duplicate, overlapping interval, or late interval behind
			// the committed endpoint has already been passed by the ledger.
			if !sample.start.Before(last) {
				addCostMeasurement(daily, sample)
				last = sample.end
			}
		}
		if len(daily) == 0 {
			return nil
		}
		checks := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(watermark), "=", revision),
			clientv3.Compare(clientv3.Value(r.costRatesKey()), "=", r.cost.ratesJSON)}
		stamp, err := json.Marshal(last)
		if err != nil {
			return err
		}
		writes := []clientv3.Op{clientv3.OpPut(watermark, string(stamp), clientv3.WithLease(lease))}
		for day, delta := range daily {
			key := r.costDayPrefix(target.scope, day) + target.address.Key()
			row, err := r.telemetry.client.Get(ctx, key, clientv3.WithRev(previous.Header.Revision))
			if err != nil {
				return err
			}
			var stored costmanagement.Totals
			var revision int64
			if len(row.Kvs) != 0 {
				item := row.Kvs[0]
				if json.Unmarshal(item.Value, &stored) != nil || !stored.Valid() {
					return errors.New("invalid stored daily cost measurements")
				}
				revision = item.ModRevision
			}
			stored.CPUTimeMicros += delta.CPUTimeMicros
			stored.MemoryByteMillis += delta.MemoryByteMillis
			if !stored.Valid() {
				return errors.New("daily costs exceed the supported measurement bounds")
			}
			data, err := json.Marshal(stored)
			if err != nil {
				return err
			}
			checks = append(checks, clientv3.Compare(clientv3.ModRevision(key), "=", revision))
			writes = append(writes, clientv3.OpPut(key, string(data), clientv3.WithLease(lease)))
		}
		result, err := r.telemetry.client.Txn(ctx).If(checks...).Then(writes...).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return errors.New("cost measurements changed while applying the batch")
}

func (r *Region) CostRecords(ctx context.Context, scope arm.SubscriptionScope, group string, start, end time.Time) (costmanagement.Rates,
	[]costmanagement.Record, error) {
	if r.cost == nil || r.telemetry == nil || !validScope(scope) {
		return costmanagement.Rates{}, nil, costmanagement.ErrUnavailable
	}
	if err := r.ensureCostRates(ctx); err != nil {
		return costmanagement.Rates{}, nil, errors.Join(costmanagement.ErrUnavailable, err)
	}
	var records []costmanagement.Record
	var revision int64
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		prefix := r.costDayPrefix(scope, day)
		from := prefix
		if group != "" {
			from += strings.ToLower(group) + "/"
		}
		rows, err := r.telemetry.client.Get(ctx, from, clientv3.WithPrefix(), clientv3.WithRev(revision),
			clientv3.WithLimit(int64(costmanagement.MaxRecords-len(records)+1)))
		if err != nil {
			return costmanagement.Rates{}, nil, errors.Join(costmanagement.ErrUnavailable, err)
		}
		if len(rows.Kvs)+len(records) > costmanagement.MaxRecords || rows.More {
			return costmanagement.Rates{}, nil, costmanagement.ErrQueryLimit
		}
		if revision == 0 {
			revision = rows.Header.Revision
		}
		for _, row := range rows.Kvs {
			groupName, path, _ := strings.Cut(strings.TrimPrefix(string(row.Key), prefix), "/")
			resource := arm.ResourceAddress{Group: groupName, Path: path}
			var totals costmanagement.Totals
			if !resource.Valid() || json.Unmarshal(row.Value, &totals) != nil || !totals.Valid() {
				return costmanagement.Rates{}, nil, costmanagement.ErrUnavailable
			}
			records = append(records, costmanagement.Record{ResourceID: resource.ID(scope), Day: day, Totals: totals})
		}
	}
	return r.cost.rates, records, nil
}
