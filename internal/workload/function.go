package workload

import (
	"github.com/Weichwolf/ocean/internal/functions"
)

// FunctionApp is the sealed configuration attached to a placement.
type FunctionApp struct {
	PlanID     string            `json:"planId"`
	HTTPSOnly  bool              `json:"httpsOnly"`
	PublicHost string            `json:"publicHost,omitempty"`
	Settings   map[string]string `json:"settings,omitempty"`
	Runtime    functions.Runtime `json:"runtime"`
}
