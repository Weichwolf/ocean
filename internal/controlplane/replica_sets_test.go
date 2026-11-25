package controlplane

import (
	"slices"
	"testing"

	"github.com/Weichwolf/ocean/internal/workload"
)

func TestReplicaSelectionKeepsServingSlotAndReplacesLostHost(t *testing.T) {
	slot := func(eligible bool, desired, observed string) replicaSlot {
		return replicaSlot{eligible: eligible, record: &containerRecord{Desired: desired, Observed: observed}}
	}
	before := []replicaSlot{
		slot(true, workload.Running, workload.Running),
		slot(true, workload.Running, workload.Running),
		slot(true, workload.Stopped, workload.Stopped),
		slot(true, workload.Stopped, workload.Stopped),
	}
	if found := selectReplicaSlots(before, 2); !slices.Equal(found, []bool{true, true, false, false}) {
		t.Fatalf("the controller changed a healthy fixed placement: %v", found)
	}
	before[0].eligible = false
	if found := selectReplicaSlots(before, 2); !slices.Equal(found, []bool{false, true, true, false}) || countReadySelected(before, found) != 1 {
		t.Fatalf("the controller did not keep the surviving backend while starting a spare: %v", found)
	}
	before[0].eligible = true
	before[0].record.Desired = workload.Stopped
	before[2].record.Desired = workload.Running
	before[2].record.Observed = workload.Running
	before[3].record.Desired = workload.Running
	before[3].record.Observed = workload.Running
	if found := selectReplicaSlots(before, 2); !slices.Equal(found, []bool{false, true, true, false}) {
		t.Fatalf("scale-in moved a ready replica or selected a returning standby: %v", found)
	}
}
