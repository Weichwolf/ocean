package arm

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
)

const (
	activityVersion = "2015-04-01"
	healthVersion   = "2025-05-01"
	usageVersion    = "2025-09-01"
	healthType      = "Microsoft.ResourceHealth/availabilityStatuses"
	activityType    = "Microsoft.Insights/eventtypes/management/values"
)

type ActivityFilter struct {
	Start, End                        time.Time
	Group, ResourceID, Caller, Status string
	BeforeTime                        time.Time
	BeforeID                          string
}

type ActivityRecord struct {
	ID string
	AuditEvent
}

type ResourceHealth struct {
	State, Reason, Category string
	ChangedAt               time.Time
}

type RegionalUsage struct {
	Groups, GroupLimit        int64
	CPUMillis, CPULimitMillis int64
	MemoryMiB, MemoryLimitMiB int64
}

type MonitorStore interface {
	ListActivity(context.Context, SubscriptionScope, string, ActivityFilter, int) ([]ActivityRecord, error)
	WorkloadHealth(context.Context, SubscriptionScope, string, ResourceAddress) (*ResourceHealth, error)
	RegionalUsage(context.Context, SubscriptionScope) (RegionalUsage, error)
	TelemetrySamples(context.Context, SubscriptionScope, string, ResourceAddress, time.Time, time.Time, int64) ([]telemetry.Sample, error)
}

func monitorRoute(segments []string) (armRoute, bool) {
	if len(segments) == 7 && strings.EqualFold(strings.Join(segments[2:], "/"), "providers/"+activityType) {
		return armRoute{collection: "activityLog"}, true
	}
	if len(segments) == 7 && strings.EqualFold(strings.Join(segments[2:5], "/"), "providers/Microsoft.ContainerInstance/locations") &&
		strings.EqualFold(segments[6], "usages") && resourceSegment.MatchString(segments[5]) {
		return armRoute{collection: "regionUsage", name: segments[5]}, true
	}
	if len(segments) == 11 && strings.EqualFold(segments[2], "resourceGroups") && validGroupName(segments[3]) &&
		strings.EqualFold(segments[4], "providers") && strings.EqualFold(strings.Join(segments[8:], "/"), "providers/"+metricsType) {
		address := ResourceAddress{Group: segments[3], Path: strings.Join(segments[5:8], "/")}
		if _, kind, valid := address.parts(); valid && strings.EqualFold(kind, workload.ContainerGroupType) {
			return armRoute{collection: "workloadMetrics", group: address.Group, name: address.Path}, true
		}
	}
	if len(segments) < 12 || !strings.EqualFold(segments[2], "resourceGroups") || !validGroupName(segments[3]) ||
		!strings.EqualFold(strings.Join(segments[len(segments)-4:], "/"), "providers/"+healthType+"/current") ||
		!strings.EqualFold(segments[4], "providers") {
		return armRoute{}, false
	}
	address := ResourceAddress{Group: segments[3], Path: strings.Join(segments[5:len(segments)-4], "/")}
	if !isMonitoredWorkload(address) {
		return armRoute{}, false
	}
	return armRoute{collection: "resourceHealth", group: address.Group, name: address.Path}, true
}

func isMonitoredWorkload(address ResourceAddress) bool {
	_, kind, valid := address.parts()
	return valid && (strings.EqualFold(kind, workload.ContainerGroupType) || strings.EqualFold(kind, functions.SiteType))
}

func (s Server) monitor(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader string, route armRoute) {
	if s.Monitor == nil {
		unavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	switch route.collection {
	case "activityLog":
		s.activityLog(ctx, w, r, scope, reader)
	case "workloadMetrics":
		s.workloadMetrics(ctx, w, r, scope, reader, ResourceAddress{Group: route.group, Path: route.name})
	case "resourceHealth":
		if _, ok := readQuery(w, r, healthVersion, nil); !ok {
			return
		}
		s.resourceHealth(ctx, w, scope, reader, ResourceAddress{Group: route.group, Path: route.name})
	case "regionUsage":
		if _, ok := readQuery(w, r, usageVersion, nil); !ok {
			return
		}
		if reader != "" {
			writeError(w, http.StatusForbidden, "AuthorizationFailed", "Subscription ownership is required to read regional quota usage.")
			return
		}
		if route.name != s.Location {
			writeError(w, http.StatusNotFound, "LocationNotFound", "The requested region does not exist.")
			return
		}
		s.regionalUsage(ctx, w, scope)
	}
}

func parseMonitorTime(value string) (time.Time, error) {
	value = strings.Trim(value, "'")
	if result, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return result.UTC(), nil
	}
	return time.ParseInLocation("2006-01-02T15:04:05", value, time.UTC)
}

var activityClause = regexp.MustCompile(`^(eventTimestamp (?:ge|le) (?:'[0-9T:.+Z-]+'|[0-9T:.+Z-]+)|(resourceGroupName|resourceId|caller|status) eq '[^'\r\n]{1,512}')$`)

func parseActivityFilter(query url.Values, scope SubscriptionScope) (ActivityFilter, bool) {
	var filter ActivityFilter
	seen := make(map[string]bool)
	for _, predicate := range strings.Split(query.Get("$filter"), " and ") {
		if !activityClause.MatchString(predicate) {
			return filter, false
		}
		field, rest, _ := strings.Cut(predicate, " ")
		comp, raw, _ := strings.Cut(rest, " ")
		if seen[field+comp] {
			return filter, false
		}
		seen[field+comp] = true
		var err error
		switch field {
		case "eventTimestamp":
			if comp == "ge" {
				filter.Start, err = parseMonitorTime(raw)
			} else {
				filter.End, err = parseMonitorTime(raw)
			}
		case "resourceGroupName":
			filter.Group = strings.Trim(raw, "'")
			if !validGroupName(filter.Group) {
				return filter, false
			}
		case "resourceId":
			filter.ResourceID = strings.Trim(raw, "'")
			if !strings.HasPrefix(strings.ToLower(filter.ResourceID), "/subscriptions/"+strings.ToLower(scope.SubscriptionID)+"/") {
				return filter, false
			}
		case "caller":
			filter.Caller = strings.Trim(raw, "'")
		case "status":
			filter.Status = strings.Trim(raw, "'")
		}
		if err != nil {
			return filter, false
		}
	}
	if filter.Start.IsZero() || filter.End.IsZero() || filter.End.Before(filter.Start) || filter.End.Sub(filter.Start) > 30*24*time.Hour ||
		filter.Group != "" && filter.ResourceID != "" {
		return filter, false
	}
	if raw := query.Get("$skiptoken"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		stamp, id, ok := strings.Cut(string(decoded), "/")
		nanos, parseErr := strconv.ParseInt(stamp, 10, 64)
		if err != nil || parseErr != nil || !ok || !activityID.MatchString(id) {
			return filter, false
		}
		filter.BeforeTime, filter.BeforeID = time.Unix(0, nanos).UTC(), id
	}
	return filter, true
}

var activityID = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

func (s Server) activityLog(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader string) {
	query, ok := readQuery(w, r, activityVersion, func(key, value string) bool {
		return len(value) <= 2048 && (key == "$filter" || key == "$skiptoken" && value != "")
	})
	if !ok {
		return
	}
	filter, ok := parseActivityFilter(query, scope)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidFilter", "Supply a valid event timestamp range and supported activity filter.")
		return
	}
	const pageSize = 64
	records, err := s.Monitor.ListActivity(ctx, scope, reader, filter, pageSize+1)
	if err != nil {
		inventoryError(w, err)
		return
	}
	count := min(pageSize, len(records))
	items := make([]map[string]any, 0, count)
	for _, record := range records[:count] {
		items = append(items, record.view(scope))
	}
	reply := map[string]any{"value": items}
	if len(records) > count {
		last := records[count-1]
		cursor := strconv.FormatInt(last.Time.UnixNano(), 10) + "/" + last.ID
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(cursor)))
		reply["nextLink"] = s.Origin + r.URL.EscapedPath() + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, reply)
}

func monitorName(value string) map[string]string {
	return map[string]string{"value": value, "localizedValue": value}
}

func (row ActivityRecord) view(scope SubscriptionScope) map[string]any {
	parts := strings.Split(row.Target, "/")
	var group, provider string
	if len(parts) >= 5 && strings.EqualFold(parts[3], "resourceGroups") {
		group = parts[4]
	}
	if len(parts) >= 7 && strings.EqualFold(parts[5], "providers") {
		provider = parts[6]
	}
	status := row.Outcome
	if status == "Denied" {
		status = "Failed"
	}
	base := "/subscriptions/" + scope.SubscriptionID + "/providers/" + activityType + "/"
	return map[string]any{"id": base + row.ID, "eventDataId": row.ID, "operationId": row.ID, "correlationId": row.ID,
		"eventTimestamp": row.Time, "submissionTimestamp": row.Time, "caller": row.Actor, "resourceId": row.Target,
		"resourceGroupName": group, "resourceProviderName": monitorName(provider), "subscriptionId": scope.SubscriptionID,
		"operationName": monitorName(row.Action), "status": monitorName(status), "category": monitorName("Administrative"),
		"eventName": monitorName("EndRequest"), "properties": map[string]string{"outcome": row.Outcome}}
}

func (s Server) resourceHealth(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader string, address ResourceAddress) {
	health, err := s.Monitor.WorkloadHealth(ctx, scope, reader, address)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if health == nil {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The monitored workload does not exist.")
		return
	}
	id := address.ID(scope) + "/providers/" + healthType + "/current"
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": "current", "type": healthType, "location": s.Location,
		"properties": map[string]any{"availabilityState": health.State, "category": health.Category, "reasonType": health.Reason,
			"summary": health.Reason, "reportedTime": time.Now().UTC(), "occurredTime": health.ChangedAt}})
}

func (s Server) regionalUsage(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope) {
	usage, err := s.Monitor.RegionalUsage(ctx, scope)
	if err != nil {
		inventoryError(w, err)
		return
	}
	base := "/subscriptions/" + scope.SubscriptionID + "/providers/Microsoft.ContainerInstance/locations/" + s.Location + "/usages/"
	entry := func(name, label string, current, limit int64) map[string]any {
		return map[string]any{"id": base + name, "name": map[string]string{"value": name, "localizedValue": label},
			"unit": "Count", "currentValue": current, "limit": limit}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": []any{
		entry("ContainerGroups", "Container Groups", usage.Groups, usage.GroupLimit),
		entry("ReservedCPUMillis", "Reserved CPU millicores", usage.CPUMillis, usage.CPULimitMillis),
		entry("ReservedMemoryMiB", "Reserved memory MiB", usage.MemoryMiB, usage.MemoryLimitMiB),
	}})
}
