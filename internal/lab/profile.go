package lab

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"go.yaml.in/yaml/v3"
)

// Resources are the allocations requested from the local hypervisor.
type Resources struct {
	MemoryMiB uint `json:"memoryMiB" yaml:"memoryMiB"`
	VCPUs     uint `json:"vcpus" yaml:"vcpus"`
}

type overrides struct {
	MemoryMiB *uint `yaml:"memoryMiB"`
	VCPUs     *uint `yaml:"vcpus"`
}

type profile struct {
	Farms         int                  `yaml:"farms"`
	NodesPerFarm  int                  `yaml:"nodesPerFarm"`
	ExternalProbe bool                 `yaml:"externalProbe"`
	Defaults      Resources            `yaml:"defaults"`
	Overrides     map[string]overrides `yaml:"overrides"`
}

// Interface connects a guest to one private lab segment.
type Interface struct {
	Name    string       `json:"name"`
	Segment string       `json:"segment"`
	MAC     string       `json:"mac"`
	Address netip.Prefix `json:"address"`
}

// Guest is a node or an isolated client in the development inventory.
type Guest struct {
	Name       string      `json:"name"`
	Farm       int         `json:"farm"`
	Roles      []string    `json:"roles"`
	Resources  Resources   `json:"resources"`
	Interfaces []Interface `json:"interfaces"`
}

// Plan is the deterministic guest and network inventory for a profile.
type Plan struct {
	Segments []string `json:"segments"`
	Guests   []Guest  `json:"guests"`
}

// LoadPlan reads and validates one YAML profile.
func LoadPlan(path string) (Plan, error) {
	file, err := os.Open(path)
	if err != nil {
		return Plan{}, err
	}
	defer file.Close()
	settings := profile{Defaults: Resources{MemoryMiB: 1024, VCPUs: 1}}
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&settings); err != nil {
		return Plan{}, fmt.Errorf("read profile: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Plan{}, errors.New("profile must contain one YAML document")
	}
	return settings.plan()
}

func (settings profile) plan() (Plan, error) {
	if settings.Farms < 1 || settings.Farms > 4 || settings.NodesPerFarm < 3 || settings.NodesPerFarm > 16/settings.Farms {
		return Plan{}, errors.New("profile requires one to four farms, three or more nodes per farm, and at most sixteen nodes")
	}
	if settings.Defaults.MemoryMiB == 0 || settings.Defaults.VCPUs == 0 {
		return Plan{}, errors.New("default RAM and vCPUs must be positive")
	}

	var plan Plan
	if settings.Farms > 1 {
		plan.Segments = append(plan.Segments, "wan-a", "wan-b")
	}
	known := make(map[string]bool)
	for farm := 1; farm <= settings.Farms; farm++ {
		management, workload, customer := localSegments(farm)
		plan.Segments = append(plan.Segments, management, workload, customer)
		external := fmt.Sprintf("f%d-external", farm)
		if settings.ExternalProbe {
			plan.Segments = append(plan.Segments, external)
		}
		for number := 1; number <= settings.NodesPerFarm; number++ {
			guest := Guest{
				Name:      fmt.Sprintf("farm-%d-node-%02d", farm, number),
				Farm:      farm,
				Roles:     []string{"compute"},
				Resources: settings.Defaults,
				Interfaces: []Interface{
					privateInterface("mgmt0", management, 231, farm, number),
					privateInterface("work0", workload, 232, farm, number),
				},
			}
			if number <= 3 {
				guest.Roles = append(guest.Roles, "control-plane")
			}
			if number <= 2 {
				guest.Roles = append(guest.Roles, "gateway")
				guest.Interfaces = append(guest.Interfaces, privateInterface("customer0", customer, 233, farm, number))
				if settings.ExternalProbe {
					guest.Interfaces = append(guest.Interfaces, externalInterface(external, farm, number+1))
				}
				if settings.Farms > 1 {
					guest.Interfaces = append(guest.Interfaces, wanInterface(farm, number))
				}
			}
			known[guest.Name] = true
			override := settings.Overrides[guest.Name]
			if override.MemoryMiB != nil {
				guest.Resources.MemoryMiB = *override.MemoryMiB
			}
			if override.VCPUs != nil {
				guest.Resources.VCPUs = *override.VCPUs
			}
			if guest.Resources.MemoryMiB == 0 || guest.Resources.VCPUs == 0 {
				return Plan{}, fmt.Errorf("%s RAM and vCPUs must be positive", guest.Name)
			}
			plan.Guests = append(plan.Guests, guest)
		}
		plan.Guests = append(plan.Guests,
			client(farm, "operator", privateInterface("mgmt0", management, 231, farm, 90)),
			client(farm, "customer", privateInterface("customer0", customer, 233, farm, 91)),
		)
		if settings.ExternalProbe {
			plan.Guests = append(plan.Guests, client(farm, "observer", externalInterface(external, farm, 30)))
		}
	}
	for name := range settings.Overrides {
		if !known[name] {
			return Plan{}, fmt.Errorf("resource override refers to unknown node %q", name)
		}
	}
	return plan, nil
}

func externalInterface(segment string, farm, address int) Interface {
	return Interface{
		Name: "external0", Segment: segment,
		MAC:     fmt.Sprintf("02:4f:00:eb:%02x:%02x", farm, address),
		Address: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(address + 48*(farm-1))}), 24),
	}
}

func localSegments(farm int) (management, workload, customer string) {
	return fmt.Sprintf("f%d-management", farm), fmt.Sprintf("f%d-workload", farm), fmt.Sprintf("f%d-customer", farm)
}

func privateInterface(name, segment string, family, farm, number int) Interface {
	return Interface{
		Name:    name,
		Segment: segment,
		MAC:     fmt.Sprintf("02:4f:00:%02x:%02x:%02x", family, farm, number),
		Address: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(family), byte(farm), byte(number + 10)}), 24),
	}
}

func wanInterface(farm, gateway int) Interface {
	return Interface{
		Name:    "wan0",
		Segment: []string{"wan-a", "wan-b"}[gateway-1],
		MAC:     fmt.Sprintf("02:4f:00:ea:%02x:%02x", farm, gateway),
		Address: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 234, byte(gateway), byte(farm + 10)}), 24),
	}
}

func client(farm int, role string, intf Interface) Guest {
	return Guest{
		Name:       fmt.Sprintf("farm-%d-%s", farm, role),
		Farm:       farm,
		Roles:      []string{role},
		Resources:  Resources{MemoryMiB: 512, VCPUs: 1},
		Interfaces: []Interface{intf},
	}
}
