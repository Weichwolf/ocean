package arm

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/costmanagement"
)

func TestCostTableRoundsOnlyAfterAggregation(t *testing.T) {
	rates, err := (costmanagement.RateConfig{Currency: "CHF", CPUPerHour: "0.018", MemoryPerGiBHour: "0.036"}).Rates()
	if err != nil {
		t.Fatal(err)
	}
	today := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	first := costmanagement.Record{ResourceID: "/app/one", Day: today, Totals: costmanagement.Totals{
		CPUTimeMicros: 100_000, MemoryByteMillis: 50 * (1 << 30),
	}}
	second := first
	second.Day = first.Day.AddDate(0, 0, -1)
	table, err := buildCostTable(rates, []costmanagement.Record{first, second}, []string{"MeterId", "ResourceId"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]any{{json.Number("0.000001"), costmanagement.CPUTimeMeter, first.ResourceID, rates.Currency},
		{json.Number("0.000001"), costmanagement.MemoryUseMeter, first.ResourceID, rates.Currency}}
	if !reflect.DeepEqual(table.Rows, want) {
		t.Fatalf("two half-micro amounts were rounded before aggregation: got %v, want %v", table.Rows, want)
	}
	table, err = buildCostTable(rates, []costmanagement.Record{first, second}, []string{"ResourceId"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want = [][]any{{json.Number("0.000001"), 20261125, first.ResourceID, rates.Currency},
		{json.Number("0.000001"), 20261126, first.ResourceID, rates.Currency}}
	if !reflect.DeepEqual(table.Rows, want) {
		t.Fatalf("unexpected daily resource rows: got %v, want %v", table.Rows, want)
	}
}

func TestCostWindowsUseUTCCalendarDates(t *testing.T) {
	now := time.Date(2026, 3, 4, 23, 0, 0, 0, time.FixedZone("offset", -4*60*60))
	for _, test := range []struct {
		body      string
		from, end string
	}{
		{`{"timeframe":"Custom","timePeriod":{"from":"2026-03-03T00:00:00Z","to":"2026-03-04T00:00:00Z"}}`, "2026-03-03", "2026-03-05"},
		{`{"timeframe":"MonthToDate"}`, "2026-03-01", "2026-03-06"},
		{`{"timeframe":"TheLastMonth"}`, "2026-02-01", "2026-03-01"},
		{`{"timeframe":"MonthToDate","timePeriod":{"from":"2026-03-01T00:00:00Z","to":"2026-03-04T00:00:00Z"}}`, "", ""},
		{`{"timeframe":"Custom","timePeriod":{"from":"2026-03-03T12:00:00Z","to":"2026-03-04T00:00:00Z"}}`, "", ""},
		{`{"timeframe":"Custom","timePeriod":{"from":"2026-03-06T00:00:00Z","to":"2026-03-06T00:00:00Z"}}`, "", ""},
		{`{"timeframe":"Custom","timePeriod":{"from":"2026-01-30T00:00:00Z","to":"2026-03-05T00:00:00Z"}}`, "", ""},
		{`{"timeframe":"Custom","timePeriod":{"from":"2025-11-25T00:00:00Z","to":"2025-11-25T00:00:00Z"}}`, "", ""},
	} {
		var query costQueryDefinition
		if err := json.Unmarshal([]byte(test.body), &query); err != nil {
			t.Fatal(err)
		}
		start, end, ok := query.window(now)
		if test.from == "" && ok || test.from != "" && (!ok || start.Format(time.DateOnly) != test.from || end.Format(time.DateOnly) != test.end) {
			t.Fatalf("unexpected cost window %s through %s, valid=%v for %s", start, end, ok, test.body)
		}
	}
}
