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

	"github.com/Weichwolf/ocean/internal/network"
)

var hostName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const HostAvailabilityTTL = 15 * time.Second

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
	Reserved         *Capacity `json:"reserved,omitempty"`
	TokenSHA256      string    `json:"tokenSHA256"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

func (a Approval) Valid() bool {
	mac, macErr := net.ParseMAC(a.MAC)
	address, addrErr := netip.ParseAddr(a.Address)
	digest, digestErr := hex.DecodeString(a.TokenSHA256)
	return hostName.MatchString(a.HostID) &&
		macErr == nil && len(mac) == 6 && mac.String() == a.MAC && addrErr == nil && address.Is4() && address.IsGlobalUnicast() &&
		digestErr == nil && len(digest) == sha256.Size && !a.ExpiresAt.IsZero() && a.ValidPlacementPolicy()
}

// ValidPlacementPolicy validates the part of an approval shared by hosts in a pool.
func (a Approval) ValidPlacementPolicy() bool {
	if !hostName.MatchString(a.Profile) || !hostName.MatchString(a.Cell) || !hostName.MatchString(a.Pool) ||
		a.MinimumCPU < 1 || a.MinimumMemoryMiB < 1 || len(a.Roles) == 0 ||
		(a.Reserved != nil && (a.Reserved.CPUMillis < 0 || a.Reserved.MemoryMiB < 0)) {
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

// Capacity describes the CPU and RAM available for managed workloads.
type Capacity struct {
	CPUMillis int64 `json:"cpuMillis"`
	MemoryMiB int64 `json:"memoryMiB"`
}

func (a Approval) Available(r Report) (Capacity, bool) {
	if !a.Qualifies(r) || int64(r.CPU) > (1<<63-1)/1000 {
		return Capacity{}, false
	}
	reserved := Capacity{CPUMillis: 100, MemoryMiB: 128}
	if a.Reserved != nil {
		reserved = *a.Reserved
	}
	capacity := Capacity{CPUMillis: int64(r.CPU)*1000 - reserved.CPUMillis, MemoryMiB: int64(r.MemoryMiB) - reserved.MemoryMiB}
	return capacity, capacity.CPUMillis > 0 && capacity.MemoryMiB > 0
}

type Availability struct {
	HostID           string   `json:"hostId"`
	Cell             string   `json:"cell"`
	Pool             string   `json:"pool"`
	Roles            []string `json:"roles"`
	Capacity         Capacity `json:"capacity"`
	ContainerNetwork bool     `json:"containerNetwork,omitempty"`
	DirectoryRuntime bool     `json:"directoryRuntime,omitempty"`
	VMRuntime        bool     `json:"vmRuntime,omitempty"`
}

type Assignment struct {
	ID                 string                `json:"id"`
	Generation         string                `json:"generation"`
	Cell               string                `json:"cell"`
	TenantID           string                `json:"tenantId"`
	SubscriptionID     string                `json:"subscriptionId"`
	Role               string                `json:"role"`
	Resources          Capacity              `json:"resources"`
	SubnetID           string                `json:"subnetId,omitempty"`
	PrivateIPv4        netip.Addr            `json:"privateIPv4,omitzero"`
	Network            *network.SubnetPolicy `json:"network,omitempty"`
	NetworkUnavailable bool                  `json:"networkUnavailable,omitempty"`
	Directory          *DirectoryAssignment  `json:"directory,omitempty"`
}

// DirectoryAssignment identifies one controller and its peers in a private AD domain.
type DirectoryAssignment struct {
	DirectoryID     string        `json:"directoryId"`
	DNSName         string        `json:"dnsName"`
	NetBIOSName     string        `json:"netbiosName"`
	ControllerIndex int           `json:"controllerIndex"`
	ControllerIPv4  [2]netip.Addr `json:"controllerIPv4"`
	WriterIndex     int           `json:"writerIndex,omitempty"`
	RetireReplica   string        `json:"retireReplicaGeneration,omitempty"`
	PromoteFrom     string        `json:"promoteFromGeneration,omitempty"`
	ControllerNames [2]string     `json:"controllerNames,omitzero"`
	RecoveryID      string        `json:"recoveryId,omitempty"`
	RecoverySHA256  string        `json:"recoverySha256,omitempty"`
}

func (a DirectoryAssignment) IsWriter() bool {
	return a.ControllerIndex == max(a.WriterIndex, 1)
}

type AssignmentPage struct {
	Assignments []Assignment `json:"assignments"`
	Next        string       `json:"continuation,omitempty"`
}

type Report struct {
	MAC              string `json:"mac"`
	Address          string `json:"address"`
	OS               string `json:"os"`
	OSVersion        string `json:"osVersion"`
	CPU              int    `json:"cpu"`
	MemoryMiB        int    `json:"memoryMiB"`
	RootlessPodman   bool   `json:"rootlessPodman"`
	KVM              bool   `json:"kvm"`
	ContainerNetwork bool   `json:"containerNetwork,omitempty"`
	DirectoryRuntime bool   `json:"directoryRuntime,omitempty"`
	VMRuntime        bool   `json:"vmRuntime,omitempty"`
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
