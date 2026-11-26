// Package telemetry defines bounded workload observations independent of placement.
package telemetry

import (
	"errors"
	"math"
	"regexp"
	"time"
)

const (
	MaxBatch = 48
	MaxBody  = 96 << 10

	Request    = "request"
	Dependency = "dependency"
	Exception  = "exception"
)

var (
	ErrDisabled       = errors.New("the telemetry backend is not configured")
	ErrTooManySamples = errors.New("the telemetry query exceeds its sample limit")
)

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,94}$`)
var sampleID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Usage struct {
	CPUMillis   float64        `json:"cpuMillis"`
	MemoryBytes int64          `json:"memoryBytes"`
	Interval    *UsageInterval `json:"interval,omitempty"`
}

// UsageInterval describes the measured period ending at the sample timestamp.
type UsageInterval struct {
	Milliseconds  int64 `json:"milliseconds"`
	CPUTimeMicros int64 `json:"cpuTimeMicros"`
}

func (period UsageInterval) Valid() bool {
	return period.Milliseconds >= 100 && period.Milliseconds <= 5000 &&
		period.CPUTimeMicros >= 0 && period.CPUTimeMicros <= 64000*period.Milliseconds
}

type Span struct {
	Kind       string  `json:"kind"`
	Name       string  `json:"name"`
	Target     string  `json:"target,omitempty"`
	Code       int     `json:"code,omitempty"`
	DurationMS float64 `json:"durationMs"`
	Success    bool    `json:"success"`
}

type Gap struct {
	Dropped int64     `json:"dropped"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
}

type Sample struct {
	ID    string    `json:"id"`
	Time  time.Time `json:"time"`
	Usage *Usage    `json:"usage,omitempty"`
	Span  *Span     `json:"span,omitempty"`
	Gap   *Gap      `json:"gap,omitempty"`
}

type Assignment struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	ID             string `json:"placementId"`
	Generation     string `json:"generation"`
}

type Observation struct {
	Assignment Assignment `json:"assignment"`
	Sample     Sample     `json:"sample"`
}

type Batch struct {
	Observations []Observation `json:"observations"`
}

func (sample Sample) Valid(now time.Time) bool {
	if !sampleID.MatchString(sample.ID) || sample.Time.Before(now.Add(-24*time.Hour)) ||
		sample.Time.After(now.Add(30*time.Second)) {
		return false
	}
	switch {
	case sample.Usage != nil && sample.Span == nil && sample.Gap == nil:
		return finiteBetween(sample.Usage.CPUMillis, 0, 64000) && sample.Usage.MemoryBytes >= 0 && sample.Usage.MemoryBytes <= 64<<30 &&
			(sample.Usage.Interval == nil || sample.Usage.Interval.Valid())
	case sample.Span != nil && sample.Usage == nil && sample.Gap == nil:
		s := sample.Span
		if !safeName.MatchString(s.Name) || !finiteBetween(s.DurationMS, 0, 10*60*1000) ||
			s.Target != "" && !safeName.MatchString(s.Target) || s.Code < 0 || s.Code > 599 {
			return false
		}
		switch s.Kind {
		case Request:
			return s.Target == "" && s.Code >= 100
		case Dependency:
			return s.Target != ""
		case Exception:
			return s.Target == "" && !s.Success
		}
	case sample.Gap != nil && sample.Usage == nil && sample.Span == nil:
		gap := sample.Gap
		return gap.Dropped > 0 && !gap.From.IsZero() && !gap.To.Before(gap.From) && !gap.To.After(now.Add(30*time.Second))
	}
	return false
}

func finiteBetween(value, least, most float64) bool {
	return !math.IsNaN(value) && value >= least && value <= most
}
