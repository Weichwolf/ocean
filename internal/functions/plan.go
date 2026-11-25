// Package functions defines the supported Linux Functions hosting contract.
package functions

import "regexp"

const (
	APIVersion         = "2025-05-01"
	SiteReadAPIVersion = "2023-12-01"
	PlanType           = "Microsoft.Web/serverfarms"
	SiteType           = "Microsoft.Web/sites"
)

var resourceName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidName(name string) bool { return resourceName.MatchString(name) }

type Plan struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags,omitempty"`
	SKU        SKU               `json:"sku"`
	Properties PlanProperties    `json:"properties"`
}

type SKU struct {
	Name     string `json:"name"`
	Tier     string `json:"tier"`
	Capacity int    `json:"capacity"`
}

type PlanProperties struct {
	Reserved bool `json:"reserved"`
}

func (p Plan) Valid(location string) bool {
	return p.Location == location && p.Properties.Reserved && p.SKU == (SKU{Name: "B1", Tier: "BASIC", Capacity: 1})
}
