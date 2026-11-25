package telemetry

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTracesKeepOnlyScopedFields(t *testing.T) {
	now := time.Unix(1770000000, 0).UTC()
	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[{
		"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","kind":2,
		"startTimeUnixNano":"1769999999900000000","endTimeUnixNano":"1770000000000000000",
		"status":{"code":2},"attributes":[{"key":"http.response.status_code","value":{"intValue":"503"}},
		{"key":"http.route","value":{"stringValue":"/api/hello"}},{"key":"url.full","value":{"stringValue":"secret-query"}}],
		"events":[{"name":"exception","timeUnixNano":"1769999999990000000","attributes":[
		{"key":"exception.type","value":{"stringValue":"RangeError"}},
		{"key":"exception.message","value":{"stringValue":"secret-message"}}]}]
	}]}]}]}`
	parse := func(at time.Time) []Sample {
		samples, err := ParseTraces(httptest.NewRequest("POST", "/v1/traces", strings.NewReader(body)), at)
		if err != nil {
			t.Fatal(err)
		}
		return samples
	}
	samples := parse(now)
	if len(samples) != 2 || samples[0].Span.Kind != Request || samples[0].Span.Success ||
		samples[0].Span.Code != 503 || samples[0].Span.DurationMS != 100 || samples[1].Span.Kind != Exception ||
		samples[1].Span.Name != "RangeError" || samples[0].ID == samples[1].ID {
		t.Fatalf("unexpected trace projection: %+v", samples)
	}
	replay := parse(now.Add(time.Second))
	if replay[0].ID != samples[0].ID || replay[1].ID != samples[1].ID {
		t.Fatal("trace replay changed a sample ID")
	}
	stored, err := json.Marshal(samples)
	if err != nil || strings.Contains(string(stored), "secret-") {
		t.Fatal("the telemetry sample retained a secret-bearing attribute")
	}
}
