package arm

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/telemetry"
)

const requestSummaryQuery = "AppRequests | summarize Requests=count(), Errors=countif(Success == false), ErrorRate=100.0*countif(Success == false)/count(), P50=percentile(DurationMs, 50), P95=percentile(DurationMs, 95)"
const requestsQuery = "AppRequests | project TimeGenerated, Name, ResultCode, Success, DurationMs"
const dependenciesQuery = "AppDependencies | project TimeGenerated, Name, Target, ResultCode, Success, DurationMs"
const exceptionsQuery = "AppExceptions | project TimeGenerated, ExceptionType"
const gapsQuery = "OceanTelemetryGaps_CL | project TimeGenerated, Dropped, From, To"

type logColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type logTable struct {
	Name    string      `json:"name"`
	Columns []logColumn `json:"columns"`
	Rows    [][]any     `json:"rows"`
}

func resourceLogsRoute(parts []string) armRoute {
	if len(parts) != 9 || !strings.EqualFold(parts[0], "subscriptions") || !strings.EqualFold(parts[2], "resourceGroups") ||
		!validGroupName(parts[3]) || !strings.EqualFold(parts[4], "providers") || parts[8] != "query" {
		return armRoute{}
	}
	address := ResourceAddress{Group: parts[3], Path: strings.Join(parts[5:8], "/")}
	if !isMonitoredWorkload(address) {
		return armRoute{}
	}
	return armRoute{collection: "resourceLogs", group: address.Group, name: address.Path}
}

func insightsWindow(value string, now time.Time) (time.Time, time.Time, bool) {
	switch value {
	case "PT5M":
		return now.Add(-5 * time.Minute), now, true
	case "", "PT15M":
		return now.Add(-15 * time.Minute), now, true
	case "PT1H":
		return now.Add(-time.Hour), now, true
	}
	begin, end, ok := strings.Cut(value, "/")
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	start, startErr := time.Parse(time.RFC3339Nano, begin)
	last, endErr := time.Parse(time.RFC3339Nano, end)
	return start.UTC(), last.UTC(), startErr == nil && endErr == nil && last.After(start) && last.Sub(start) <= time.Hour &&
		!last.After(now.Add(time.Minute)) && !start.Before(now.Add(-24*time.Hour))
}

func (s Server) resourceLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader string, address ResourceAddress) {
	if s.Monitor == nil {
		unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var input struct {
		Query    string `json:"query"`
		Timespan string `json:"timespan,omitempty"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	if r.URL.RawQuery != "" || dec.Decode(&input) != nil || dec.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "InvalidQuery", "Provide a supported query and optional timespan in a JSON body.")
		return
	}
	_, kind, _ := address.parts()
	query := strings.Join(strings.Fields(input.Query), " ")
	if query != gapsQuery && (!strings.EqualFold(kind, functions.SiteType) || query != requestSummaryQuery &&
		query != requestsQuery && query != dependenciesQuery && query != exceptionsQuery) {
		writeError(w, http.StatusBadRequest, "UnsupportedQuery", "The query is outside the supported resource log contract.")
		return
	}
	start, end, ok := insightsWindow(input.Timespan, time.Now().UTC())
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidTimespan", "Use a supported log query time window of up to one hour.")
		return
	}
	samples, err := s.Monitor.TelemetrySamples(ctx, scope, reader, address, start, end, maxTelemetrySamples)
	if err != nil {
		telemetryQueryError(w, err)
		return
	}
	table := buildLogTable(query, samples)
	writeJSON(w, http.StatusOK, map[string]any{"tables": []logTable{table}})
}

func buildLogTable(query string, samples []telemetry.Sample) logTable {
	table := logTable{Name: "PrimaryResult", Rows: make([][]any, 0)}
	at := logColumn{"TimeGenerated", "datetime"}
	name := logColumn{"Name", "string"}
	code := logColumn{"ResultCode", "string"}
	success := logColumn{"Success", "bool"}
	duration := logColumn{"DurationMs", "real"}
	switch query {
	case requestSummaryQuery:
		table.Columns = []logColumn{{"Requests", "long"}, {"Errors", "long"}, {"ErrorRate", "real"}, {"P50", "real"}, {"P95", "real"}}
		durations := make([]float64, 0)
		failures := 0
		for _, sample := range samples {
			if sample.Span != nil && sample.Span.Kind == telemetry.Request {
				durations = append(durations, sample.Span.DurationMS)
				if !sample.Span.Success {
					failures++
				}
			}
		}
		if count := len(durations); count != 0 {
			sort.Float64s(durations)
			percentile := func(fraction float64) float64 { return durations[int(math.Ceil(float64(count)*fraction))-1] }
			table.Rows = append(table.Rows, []any{count, failures, 100 * float64(failures) / float64(count), percentile(0.50), percentile(0.95)})
		} else {
			table.Rows = append(table.Rows, []any{0, 0, nil, nil, nil})
		}
	case requestsQuery:
		table.Columns = []logColumn{at, name, code, success, duration}
		for _, sample := range samples {
			if span := sample.Span; span != nil && span.Kind == telemetry.Request {
				table.Rows = append(table.Rows, []any{sample.Time, span.Name, metricResultCode(span.Code), span.Success, span.DurationMS})
			}
		}
	case dependenciesQuery:
		table.Columns = []logColumn{at, name, {"Target", "string"}, code, success, duration}
		for _, sample := range samples {
			if span := sample.Span; span != nil && span.Kind == telemetry.Dependency {
				table.Rows = append(table.Rows, []any{sample.Time, span.Name, span.Target, metricResultCode(span.Code), span.Success, span.DurationMS})
			}
		}
	case exceptionsQuery:
		table.Columns = []logColumn{at, {"ExceptionType", "string"}}
		for _, sample := range samples {
			if span := sample.Span; span != nil && span.Kind == telemetry.Exception {
				table.Rows = append(table.Rows, []any{sample.Time, span.Name})
			}
		}
	case gapsQuery:
		table.Columns = []logColumn{at, {"Dropped", "long"}, {"From", "datetime"}, {"To", "datetime"}}
		for _, sample := range samples {
			if gap := sample.Gap; gap != nil {
				table.Rows = append(table.Rows, []any{sample.Time, gap.Dropped, gap.From, gap.To})
			}
		}
	}
	return table
}

func metricResultCode(value int) any {
	if value == 0 {
		return nil
	}
	return strconv.Itoa(value)
}
