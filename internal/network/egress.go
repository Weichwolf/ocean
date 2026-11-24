package network

const (
	PublicIPType       = "Microsoft.Network/publicIPAddresses"
	PublicIPAPIVersion = "2025-09-01"
	NATGatewayType     = "Microsoft.Network/natGateways"
	NATAPIVersion      = "2025-07-01"
)

type PublicIPAddressProperties struct {
	Address           string `json:"ipAddress,omitempty"`
	AllocationMethod  string `json:"publicIPAllocationMethod"`
	IPVersion         string `json:"publicIPAddressVersion"`
	IdleTimeout       int    `json:"idleTimeoutInMinutes"`
	ProvisioningState string `json:"provisioningState"`
}

type NATGatewayProperties struct {
	PublicIPAddresses []ResourceReference `json:"publicIpAddresses"`
	IdleTimeout       int                 `json:"idleTimeoutInMinutes"`
	ProvisioningState string              `json:"provisioningState"`
}
