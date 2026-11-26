package arm

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/costmanagement"
)

type CostManagementStore interface {
	CostRecords(context.Context, SubscriptionScope, string, time.Time, time.Time) (costmanagement.Rates, []costmanagement.Record, error)
}

type costQueryDefinition struct {
	Type       string `json:"type"`
	Timeframe  string `json:"timeframe"`
	TimePeriod *struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"timePeriod,omitempty"`
	Dataset struct {
		Granularity string `json:"granularity"`
		Aggregation map[string]struct {
			Name     string `json:"name"`
			Function string `json:"function"`
		} `json:"aggregation"`
		Grouping []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"grouping,omitempty"`
	} `json:"dataset"`
}

func (query costQueryDefinition) window(now time.Time) (start, end time.Time, valid bool) {
	today := costmanagement.Day(now)
	switch query.Timeframe {
	case "Custom":
		period := query.TimePeriod
		if period == nil || period.From.IsZero() || period.To.IsZero() ||
			!period.From.Equal(costmanagement.Day(period.From)) || !period.To.Equal(costmanagement.Day(period.To)) {
			return start, end, false
		}
		start = costmanagement.Day(period.From)
		end = costmanagement.Day(period.To).AddDate(0, 0, 1)
	case "MonthToDate", "TheLastMonth":
		if query.TimePeriod != nil {
			return start, end, false
		}
		first := today.AddDate(0, 0, 1-today.Day())
		if query.Timeframe == "MonthToDate" {
			start, end = first, today.AddDate(0, 0, 1)
		} else {
			start, end = first.AddDate(0, -1, 0), first
		}
	default:
		return start, end, false
	}
	return start, end, end.After(start) && !start.Before(today.AddDate(0, 0, 1-costmanagement.HistoryDays)) &&
		!end.After(today.AddDate(0, 0, 1)) && !end.After(start.AddDate(0, 0, costmanagement.MaxDays))
}

func (query costQueryDefinition) dimensions() ([]string, bool) {
	if query.Type != "Usage" && query.Type != "ActualCost" ||
		query.Dataset.Granularity != "None" && query.Dataset.Granularity != "Daily" ||
		len(query.Dataset.Aggregation) != 1 || len(query.Dataset.Grouping) > 2 {
		return nil, false
	}
	for label, metric := range query.Dataset.Aggregation {
		if !resourceSegment.MatchString(label) || metric.Name != "PreTaxCost" || metric.Function != "Sum" {
			return nil, false
		}
	}
	dimensions := make([]string, 0, len(query.Dataset.Grouping))
	for _, group := range query.Dataset.Grouping {
		if group.Type != "Dimension" || group.Name != "ResourceId" && group.Name != "MeterId" || slices.Contains(dimensions, group.Name) {
			return nil, false
		}
		dimensions = append(dimensions, group.Name)
	}
	return dimensions, true
}

func (s Server) costQuery(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, group, reader string) {
	if s.CostManagement == nil {
		writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if _, ok := readQuery(w, r, costmanagement.APIVersion, nil); !ok {
		return
	}
	var query costQueryDefinition
	if err := strictJSON(http.MaxBytesReader(w, r.Body, 16<<10), &query); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidCostQuery", "The cost query body is invalid.")
		return
	}
	start, end, dateOK := query.window(time.Now())
	dimensions, aggregationOK := query.dimensions()
	if !dateOK || !aggregationOK {
		writeError(w, http.StatusBadRequest, "InvalidCostQuery", "Use a supported date window and the documented PreTaxCost aggregation and dimensions.")
		return
	}
	if group != "" && !s.costGroupAccess(ctx, w, scope, group, reader) {
		return
	}
	rates, records, err := s.CostManagement.CostRecords(ctx, scope, group, start, end)
	if err != nil {
		costQueryError(w, err)
		return
	}
	// Recheck a group grant after the independent ledger snapshot.
	if reader != "" && !s.costGroupAccess(ctx, w, scope, group, reader) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(records) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	table, err := buildCostTable(rates, records, dimensions, query.Dataset.Granularity == "Daily")
	if err != nil {
		costQueryError(w, err)
		return
	}
	id := "/subscriptions/" + scope.SubscriptionID
	if group != "" {
		id = groupID(scope, group)
	}
	name := strings.ToLower(rand.Text())
	writeJSON(w, http.StatusOK, map[string]any{"id": id + "/providers/" + costmanagement.Type + "/" + name,
		"name": name, "type": costmanagement.Type, "properties": table})
}

func (s Server) costGroupAccess(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, group, reader string) bool {
	var resolved *Group
	var err error
	if reader == "" {
		resolved, err = s.Groups.GetGroup(ctx, scope, group)
	} else {
		resolved, err = s.Roles.GetGrantedGroup(ctx, scope, group, reader)
	}
	switch {
	case err != nil:
		unavailable(w)
	case resolved != nil:
		return true
	case reader != "":
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
	default:
		writeError(w, http.StatusNotFound, "ResourceGroupNotFound", "The resource group could not be found.")
	}
	return false
}

func costQueryError(w http.ResponseWriter, err error) {
	if errors.Is(err, costmanagement.ErrQueryLimit) {
		writeError(w, http.StatusBadRequest, "CostQueryLimitExceeded", "Use a shorter cost query window or a narrower scope.")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "CostManagementUnavailable", "The regional usage ledger is unavailable.")
}

type costColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type costTable struct {
	Columns  []costColumn `json:"columns"`
	Rows     [][]any      `json:"rows"`
	NextLink *string      `json:"nextLink"`
}

type costRowKey struct {
	date       int
	dimensions [2]string
}

func buildCostTable(rates costmanagement.Rates, records []costmanagement.Record, dimensions []string, daily bool) (costTable, error) {
	table := costTable{Columns: []costColumn{{"PreTaxCost", "Number"}}}
	if daily {
		table.Columns = append(table.Columns, costColumn{"UsageDate", "Number"})
	}
	for _, dimension := range dimensions {
		table.Columns = append(table.Columns, costColumn{dimension, "String"})
	}
	table.Columns = append(table.Columns, costColumn{"Currency", "String"})
	totals := make(map[costRowKey]*big.Rat)
	for _, entry := range records {
		var key costRowKey
		if daily {
			year, month, day := entry.Day.Date()
			key.date = year*10000 + int(month)*100 + day
		}
		for index, amount := range rates.Amounts(entry.Totals) {
			for i, dimension := range dimensions {
				if dimension == "ResourceId" {
					key.dimensions[i] = entry.ResourceID
				} else {
					key.dimensions[i] = [2]string{costmanagement.CPUTimeMeter, costmanagement.MemoryUseMeter}[index]
				}
			}
			if current := totals[key]; current != nil {
				current.Add(current, amount)
			} else {
				totals[key] = amount
			}
		}
	}
	if len(totals) > costmanagement.MaxRecords {
		return costTable{}, costmanagement.ErrQueryLimit
	}
	keys := make([]costRowKey, 0, len(totals))
	for key := range totals {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b costRowKey) int {
		if a.date != b.date {
			return a.date - b.date
		}
		return slices.Compare(a.dimensions[:], b.dimensions[:])
	})
	table.Rows = make([][]any, 0, len(keys))
	for _, key := range keys {
		row := []any{costmanagement.Amount(totals[key])}
		if daily {
			row = append(row, key.date)
		}
		for _, dimension := range key.dimensions[:len(dimensions)] {
			row = append(row, dimension)
		}
		table.Rows = append(table.Rows, append(row, rates.Currency))
	}
	return table, nil
}
