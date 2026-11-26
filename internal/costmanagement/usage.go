// Package costmanagement defines the measured usage and pricing contract.
package costmanagement

import (
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	APIVersion = "2025-03-01"
	Namespace  = "Microsoft.CostManagement"
	Type       = Namespace + "/Query"

	HistoryDays = 90
	MaxDays     = 31
	MaxRecords  = 4096

	CPUTimeMeter   = "cpu-vcpu-hour"
	MemoryUseMeter = "memory-gib-hour"

	microUnits       = 1_000_000
	hourMilliseconds = 3_600_000
	hourMicroseconds = hourMilliseconds * 1000
	gibibyte         = 1 << 30
)

var (
	ErrUnavailable = errors.New("the regional usage ledger is unavailable")
	ErrQueryLimit  = errors.New("the cost query exceeds its source record or result row limit")
	ratePattern    = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})(\.[0-9]{1,6})?$`)
)

type RateConfig struct {
	Currency         string `json:"currency"`
	CPUPerHour       string `json:"cpuPerVCPUHour"`
	MemoryPerGiBHour string `json:"memoryPerGiBHour"`
}

// Rates records fixed prices in millionths of the chosen currency per unit-hour.
type Rates struct {
	Currency string `json:"currency"`
	CPU      int64  `json:"cpuPerVCPUHourMicros"`
	Memory   int64  `json:"memoryPerGiBHourMicros"`
}

func (config RateConfig) Rates() (Rates, error) {
	switch config.Currency {
	case "CHF", "EUR", "USD":
	default:
		return Rates{}, errors.New("cost management currency must be CHF, EUR, or USD")
	}
	cpu, cpuOK := parseRate(config.CPUPerHour)
	memory, memoryOK := parseRate(config.MemoryPerGiBHour)
	if !cpuOK || !memoryOK {
		return Rates{}, errors.New("both cost management meter prices must be nonnegative decimals with at most six fractional digits")
	}
	return Rates{Currency: config.Currency, CPU: cpu, Memory: memory}, nil
}

func parseRate(value string) (int64, bool) {
	if !ratePattern.MatchString(value) {
		return 0, false
	}
	whole, fraction, _ := strings.Cut(value, ".")
	result, err := strconv.ParseInt(whole+fraction+strings.Repeat("0", 6-len(fraction)), 10, 64)
	return result, err == nil
}

type Totals struct {
	CPUTimeMicros    int64 `json:"cpuTimeMicros"`
	MemoryByteMillis int64 `json:"memoryByteMillis"`
}

func (usage Totals) Valid() bool {
	return usage.CPUTimeMicros >= 0 && usage.CPUTimeMicros <= 64*24*hourMicroseconds &&
		usage.MemoryByteMillis >= 0 && usage.MemoryByteMillis <= 64*gibibyte*24*hourMilliseconds
}

type Record struct {
	ResourceID string
	Day        time.Time
	Totals     Totals
}

// Day places a timestamp at the start of its UTC calendar day.
func Day(timestamp time.Time) time.Time { return timestamp.UTC().Truncate(24 * time.Hour) }

func (rates Rates) Amounts(usage Totals) [2]*big.Rat {
	cpu := new(big.Rat).SetFrac64(usage.CPUTimeMicros, hourMicroseconds)
	cpu.Mul(cpu, new(big.Rat).SetFrac64(rates.CPU, microUnits))
	memory := new(big.Rat).SetFrac64(usage.MemoryByteMillis, gibibyte*hourMilliseconds)
	memory.Mul(memory, new(big.Rat).SetFrac64(rates.Memory, microUnits))
	return [2]*big.Rat{cpu, memory}
}

// Amount rounds a final aggregate once, to six decimal places, half up for
// monetary values in this profile. The wire value is a JSON number.
func Amount(total *big.Rat) json.Number { return json.Number(total.FloatString(6)) }
