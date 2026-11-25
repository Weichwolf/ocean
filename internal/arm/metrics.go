package arm

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
)

const (
	metricsVersion      = "2018-01-01"
	metricsType         = "Microsoft.Insights/metrics"
	maxTelemetrySamples = 8192
)

type metricQuery struct {
	start, end          time.Time
	grain               time.Duration
	interval            string
	names, aggregations []string
}

var metricIntervals = map[string]time.Duration{
	"PT1M": time.Minute, "PT5M": 5 * time.Minute, "PT15M": 15 * time.Minute,
	"PT30M": 30 * time.Minute, "PT1H": time.Hour,
}

func metricParameter(key, value string) bool {
	switch key {
	case "timespan", "interval", "metricnames", "aggregation":
		return value != "" && len(value) <= 128
	case "metricnamespace":
		return strings.EqualFold(value, workload.ContainerGroupType)
	case "top":
		return value == "10"
	case "resultType":
		return strings.EqualFold(value, "Data")
	default:
		return false
	}
}

func parseMetricQuery(values url.Values, now time.Time) (metricQuery, bool) {
	query := metricQuery{start: now.Add(-time.Hour), end: now, interval: "PT1M", names: []string{"CpuUsage", "MemoryUsage"},
		aggregations: []string{"average"}}
	if raw := values.Get("timespan"); raw != "" {
		var err error
		if strings.Contains(raw, "%") {
			raw, err = url.QueryUnescape(raw)
		}
		first, last, ok := strings.Cut(raw, "/")
		if err != nil || !ok {
			return query, false
		}
		query.start, err = parseMonitorTime(first)
		if err != nil {
			return query, false
		}
		query.end, err = parseMonitorTime(last)
		if err != nil || !query.end.After(query.start) || query.end.Sub(query.start) > time.Hour ||
			query.start.Before(now.Add(-24*time.Hour)) || query.end.After(now.Add(time.Minute)) {
			return query, false
		}
	}
	if value := values.Get("interval"); value != "" {
		query.interval = strings.ToUpper(value)
	}
	query.grain = metricIntervals[query.interval]
	if query.grain == 0 {
		return query, false
	}
	if raw := values.Get("metricnames"); raw != "" {
		query.names = nil
		for _, value := range strings.Split(raw, ",") {
			switch strings.ToLower(value) {
			case "cpuusage":
				query.names = append(query.names, "CpuUsage")
			case "memoryusage":
				query.names = append(query.names, "MemoryUsage")
			default:
				return query, false
			}
		}
		if len(query.names) > 2 || len(query.names) == 2 && query.names[0] == query.names[1] {
			return query, false
		}
	}
	if raw := values.Get("aggregation"); raw != "" {
		query.aggregations = strings.Split(strings.ToLower(raw), ",")
		seen := make(map[string]bool, len(query.aggregations))
		for _, value := range query.aggregations {
			if value != "average" && value != "minimum" && value != "maximum" || seen[value] {
				return query, false
			}
			seen[value] = true
		}
	}
	return query, true
}

type metricBucket struct {
	count                   int
	minimum, maximum, total float64
}

func (bucket metricBucket) add(value float64) metricBucket {
	if bucket.count == 0 {
		bucket.minimum, bucket.maximum = value, value
	}
	bucket.count++
	bucket.minimum = min(bucket.minimum, value)
	bucket.maximum = max(bucket.maximum, value)
	bucket.total += value
	return bucket
}

func metricPoints(samples []telemetry.Sample, name string, query metricQuery) []map[string]any {
	start := query.start.Truncate(query.grain)
	count := int(query.end.Sub(start)/query.grain) + 1
	buckets := make([]metricBucket, count)
	for _, sample := range samples {
		if sample.Usage == nil || sample.Time.Before(query.start) || sample.Time.After(query.end) {
			continue
		}
		value := sample.Usage.CPUMillis
		if name == "MemoryUsage" {
			value = float64(sample.Usage.MemoryBytes)
		}
		index := int(sample.Time.Sub(start) / query.grain)
		buckets[index] = buckets[index].add(value)
	}
	points := make([]map[string]any, 0, count)
	for index, bucket := range buckets {
		point := map[string]any{"timeStamp": start.Add(time.Duration(index) * query.grain)}
		if bucket.count != 0 {
			for _, aggregation := range query.aggregations {
				switch aggregation {
				case "average":
					point[aggregation] = bucket.total / float64(bucket.count)
				case "minimum":
					point[aggregation] = bucket.minimum
				case "maximum":
					point[aggregation] = bucket.maximum
				}
			}
		}
		points = append(points, point)
	}
	return points
}

func telemetryQueryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, telemetry.ErrTooManySamples):
		writeError(w, http.StatusBadRequest, "TelemetryWindowTooLarge", "Use a shorter telemetry query time window.")
	case errors.Is(err, telemetry.ErrDisabled):
		writeError(w, http.StatusServiceUnavailable, "TelemetryUnavailable", "The telemetry backend is unavailable.")
	case errors.Is(err, ErrContainerMissing):
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The monitored workload does not exist.")
	default:
		inventoryError(w, err)
	}
}

func (s Server) workloadMetrics(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, address ResourceAddress) {
	values, ok := readQuery(w, r, metricsVersion, metricParameter)
	if !ok {
		return
	}
	query, ok := parseMetricQuery(values, time.Now().UTC())
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidMetricQuery", "Use a supported metric, aggregation, interval, and time window of up to one hour.")
		return
	}
	samples, err := s.Monitor.TelemetrySamples(ctx, scope, reader, address, query.start, query.end, maxTelemetrySamples)
	if err != nil {
		telemetryQueryError(w, err)
		return
	}
	series := make([]map[string]any, 0, len(query.names))
	for _, name := range query.names {
		label, unit := "CPU Usage", "Count"
		if name == "MemoryUsage" {
			label, unit = "Memory Usage", "Bytes"
		}
		series = append(series, map[string]any{"id": address.ID(scope) + "/providers/" + metricsType + "/" + name,
			"type": metricsType, "name": map[string]string{"value": name, "localizedValue": label}, "unit": unit,
			"timeseries": []map[string]any{{"metadatavalues": []any{}, "data": metricPoints(samples, name, query)}}})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cost": len(query.names), "timespan": query.start.Format(time.RFC3339Nano) + "/" + query.end.Format(time.RFC3339Nano),
		"interval": query.interval, "namespace": workload.ContainerGroupType, "resourceregion": s.Location, "value": series})
}
