// Package enrollment implements host registration and certificate authentication.
package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

var hostName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Approval struct {
	HostID           string    `json:"hostId"`
	MAC              string    `json:"mac"`
	Address          string    `json:"address"`
	Profile          string    `json:"profile"`
	Cell             string    `json:"cell"`
	Pool             string    `json:"pool"`
	Roles            []string  `json:"roles"`
	MinimumCPU       int       `json:"minimumCPU"`
	MinimumMemoryMiB int       `json:"minimumMemoryMiB"`
	RequireKVM       bool      `json:"requireKVM"`
	TokenSHA256      string    `json:"tokenSHA256"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

func (a Approval) Valid() bool {
	mac, macErr := net.ParseMAC(a.MAC)
	address, addrErr := netip.ParseAddr(a.Address)
	digest, digestErr := hex.DecodeString(a.TokenSHA256)
	if !hostName.MatchString(a.HostID) || !hostName.MatchString(a.Profile) || !hostName.MatchString(a.Cell) || !hostName.MatchString(a.Pool) ||
		macErr != nil || len(mac) != 6 || mac.String() != a.MAC || addrErr != nil || !address.Is4() || !address.IsGlobalUnicast() ||
		digestErr != nil || len(digest) != sha256.Size || a.ExpiresAt.IsZero() || a.MinimumCPU < 1 || a.MinimumMemoryMiB < 1 || len(a.Roles) == 0 {
		return false
	}
	seen := make(map[string]bool)
	for _, role := range a.Roles {
		if seen[role] || !slices.Contains([]string{"compute", "storage", "gateway"}, role) {
			return false
		}
		seen[role] = true
	}
	return true
}

type Report struct {
	MAC            string `json:"mac"`
	Address        string `json:"address"`
	OS             string `json:"os"`
	OSVersion      string `json:"osVersion"`
	CPU            int    `json:"cpu"`
	MemoryMiB      int    `json:"memoryMiB"`
	RootlessPodman bool   `json:"rootlessPodman"`
	KVM            bool   `json:"kvm"`
}

func (a Approval) Qualifies(r Report) bool {
	return strings.EqualFold(r.MAC, a.MAC) && r.Address == a.Address && r.OS == "debian" && r.OSVersion == "13" &&
		r.CPU >= a.MinimumCPU && r.MemoryMiB >= a.MinimumMemoryMiB && r.RootlessPodman && (!a.RequireKVM || r.KVM)
}

type Request struct {
	CSR    []byte `json:"csr"`
	Report Report `json:"report"`
}

type Host struct {
	HostID      string     `json:"hostId"`
	Cell        string     `json:"cell"`
	Pool        string     `json:"pool"`
	Profile     string     `json:"profile"`
	Roles       []string   `json:"roles"`
	Report      Report     `json:"report"`
	KeySHA256   string     `json:"keySHA256"`
	Certificate []byte     `json:"certificate"`
	JoinedAt    time.Time  `json:"joinedAt"`
	RevokedAt   *time.Time `json:"revokedAt,omitempty"`
}

type Registration struct {
	HostID      string   `json:"hostId"`
	Cell        string   `json:"cell"`
	Pool        string   `json:"pool"`
	Roles       []string `json:"roles"`
	Certificate []byte   `json:"certificate"`
}

func (h Host) Registration() Registration {
	return Registration{HostID: h.HostID, Cell: h.Cell, Pool: h.Pool, Roles: h.Roles, Certificate: h.Certificate}
}
