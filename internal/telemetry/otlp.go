package telemetry

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ParseTraces accepts the HTTP/JSON trace signal and keeps only fields that
// have an equivalent in the supported Application Insights tables.
func ParseTraces(r *http.Request, now time.Time) ([]Sample, error) {
	var input io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		compressed, err := gzip.NewReader(input)
		if err != nil {
			return nil, err
		}
		defer func() { _ = compressed.Close() }()
		input = compressed
	} else if r.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("unsupported trace compression")
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxBody+1))
	if err != nil || len(data) > MaxBody {
		return nil, errors.New("trace payload exceeds its size limit")
	}
	var body struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []exportedSpan `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	samples := make([]Sample, 0, 8)
	for _, resource := range body.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				samples = span.appendSamples(samples, now)
				if len(samples) > MaxBatch {
					return nil, errors.New("trace payload exceeds its sample limit")
				}
			}
		}
	}
	return samples, nil
}

type traceAttribute struct {
	Name  string `json:"key"`
	Value struct {
		String  string `json:"stringValue"`
		Integer string `json:"intValue"`
	} `json:"value"`
}

type exportedSpan struct {
	TraceID string `json:"traceId"`
	SpanID  string `json:"spanId"`
	Kind    int    `json:"kind"`
	Start   string `json:"startTimeUnixNano"`
	End     string `json:"endTimeUnixNano"`
	Status  struct {
		Code int `json:"code"`
	} `json:"status"`
	Attributes []traceAttribute `json:"attributes"`
	Events     []struct {
		Name       string           `json:"name"`
		Time       string           `json:"timeUnixNano"`
		Attributes []traceAttribute `json:"attributes"`
	} `json:"events"`
}

func (span exportedSpan) appendSamples(samples []Sample, now time.Time) []Sample {
	trace, traceErr := hex.DecodeString(span.TraceID)
	id, idErr := hex.DecodeString(span.SpanID)
	start, startErr := strconv.ParseInt(span.Start, 10, 64)
	end, endErr := strconv.ParseInt(span.End, 10, 64)
	if traceErr != nil || idErr != nil || len(trace) != 16 || len(id) != 8 ||
		startErr != nil || endErr != nil || start <= 0 || end < start {
		return samples
	}
	base := append(trace, id...)
	newSample := func(subtype string, index int, at int64, span Span) Sample {
		sum := sha256.Sum256(append(base, []byte(subtype+strconv.Itoa(index))...))
		return Sample{ID: hex.EncodeToString(sum[:16]), Time: time.Unix(0, at).UTC(), Span: &span}
	}
	result := Span{DurationMS: float64(end-start) / float64(time.Millisecond), Success: span.Status.Code != 2}
	for _, attribute := range span.Attributes {
		switch attribute.Name {
		case "http.response.status_code", "http.status_code":
			result.Code, _ = strconv.Atoi(attribute.Value.Integer)
		case "http.route":
			if route := attribute.Value.String; safeName.MatchString("GET:" + route) {
				result.Name = "HTTP:" + route
			}
		case "server.address", "net.peer.name":
			if safeName.MatchString(attribute.Value.String) {
				result.Target = attribute.Value.String
			}
		}
	}
	if result.Code >= 400 {
		result.Success = false
	}
	switch span.Kind {
	case 2:
		result.Kind, result.Target = Request, ""
		if result.Name == "" {
			result.Name = "http.request"
		}
		if result.Code == 0 {
			result.Code = http.StatusOK
			if !result.Success {
				result.Code = http.StatusInternalServerError
			}
		}
	case 3:
		result.Kind, result.Name = Dependency, "http.dependency"
	}
	if sample := newSample(result.Kind, 0, end, result); sample.Valid(now) {
		samples = append(samples, sample)
	}
	for index, event := range span.Events {
		if event.Name != "exception" {
			continue
		}
		at, err := strconv.ParseInt(event.Time, 10, 64)
		if err != nil || at < start || at > end {
			continue
		}
		name := "Exception"
		for _, attribute := range event.Attributes {
			if attribute.Name == "exception.type" && safeName.MatchString(attribute.Value.String) {
				name = attribute.Value.String
			}
		}
		sample := newSample(Exception, index, at, Span{Kind: Exception, Name: name})
		if sample.Valid(now) {
			samples = append(samples, sample)
		}
	}
	return samples
}
