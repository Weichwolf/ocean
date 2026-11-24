package lab

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestInventoryGrowthPreservesExistingGuests(t *testing.T) {
	for _, names := range [][2]string{{"single-farm-3", "scale-16"}, {"geo-4x3", "geo-4x4"}} {
		t.Run(names[1], func(t *testing.T) {
			small := loadTestProfile(t, names[0])
			large := loadTestProfile(t, names[1])
			byName := make(map[string]Guest)
			compute := 0
			for _, guest := range large.Guests {
				byName[guest.Name] = guest
				if slices.Contains(guest.Roles, "compute") {
					compute++
				}
			}
			if compute != 16 {
				t.Fatalf("compute nodes = %d, want 16", compute)
			}
			for _, existing := range small.Guests {
				if !reflect.DeepEqual(existing, byName[existing.Name]) {
					t.Fatalf("growing the lab changed %s", existing.Name)
				}
			}
		})
	}
}

func TestGeoInventorySeparatesSegmentsAndRoles(t *testing.T) {
	plan := loadTestProfile(t, "geo-4x4")
	voters := make(map[int]int)
	addresses := make(map[string]bool)
	for _, guest := range plan.Guests {
		if slices.Contains(guest.Roles, "control-plane") {
			voters[guest.Farm]++
		}
		if slices.Contains(guest.Roles, "customer") && (len(guest.Interfaces) != 1 || guest.Interfaces[0].Name != "customer0") {
			t.Errorf("customer %s has access to unintended segments", guest.Name)
		}
		if slices.Contains(guest.Roles, "operator") && (len(guest.Interfaces) != 1 || guest.Interfaces[0].Name != "mgmt0") {
			t.Errorf("operator %s has access to unintended segments", guest.Name)
		}
		for _, attachment := range guest.Interfaces {
			address := attachment.Address.String()
			if addresses[address] {
				t.Errorf("duplicate address %s", address)
			}
			addresses[address] = true
			if !slices.Contains(plan.Segments, attachment.Segment) {
				t.Errorf("unknown segment %s", attachment.Segment)
			}
		}
	}
	for farm := 1; farm <= 4; farm++ {
		if voters[farm] != 3 {
			t.Errorf("farm %d has %d voters, want 3", farm, voters[farm])
		}
	}
}

func TestProfileOverridesNodeResourcesIndependently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.yaml")
	contents := []byte("farms: 1\nnodesPerFarm: 3\noverrides:\n  farm-1-node-01:\n    memoryMiB: 1536\n  farm-1-node-03:\n    vcpus: 2\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	for index, want := range []Resources{{1536, 1}, {1024, 1}, {1024, 2}} {
		if plan.Guests[index].Resources != want {
			t.Errorf("guest %s = %+v, want %+v", plan.Guests[index].Name, plan.Guests[index].Resources, want)
		}
	}
}

func loadTestProfile(t *testing.T, name string) Plan {
	t.Helper()
	plan, err := LoadPlan(filepath.Join("..", "..", "lab", "profiles", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
