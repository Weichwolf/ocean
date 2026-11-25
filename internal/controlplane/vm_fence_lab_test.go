//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func seedVMWorker(t *testing.T, ctx context.Context, r *Region, name string, qualified bool) {
	t.Helper()
	lease, err := r.client.Grant(ctx, 45)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollment.Host{HostID: name, Cell: r.cell, Pool: "kvm", Roles: []string{"compute"}, Certificate: []byte(name)}
	available := enrollment.Availability{HostID: name, Cell: r.cell, Pool: host.Pool, Roles: host.Roles,
		Capacity: enrollment.Capacity{CPUMillis: 4000, MemoryMiB: 8192}, VMRuntime: qualified}
	body, err := json.Marshal(available)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.hostKey("registered", name), host),
		clientv3.OpPut(r.hostKey("live", name), string(body), clientv3.WithLease(lease.ID))).Commit(); err != nil {
		t.Fatal(err)
	}
}

func probeVMFence(t *testing.T, ctx context.Context, r *Region, fencer ed25519.PrivateKey, scope arm.SubscriptionScope,
	address arm.ResourceAddress, worker string, first workload.VMTask) string {
	t.Helper()
	proof := storage.FenceAttestation{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, VolumeID: first.Disk.ID,
		HostID: worker, PlacementID: first.ID, Generation: first.Generation, Observation: storage.PoweredOff, ObservedAt: time.Now().UTC()}
	body, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	signed := storage.SignedFence{Attestation: body, Signature: ed25519.Sign(fencer, body)}
	if err := r.ApplyStorageFence(ctx, signed); !errors.Is(err, arm.ErrStorageBusy) {
		t.Fatalf("fence accepted while the worker was still live: %v", err)
	}
	if _, err := r.client.Delete(ctx, r.hostKey("live", worker)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileVMFencePage(ctx, ""); err != nil {
		t.Fatal(err)
	}
	_, before, _, _, _, err := r.readVM(ctx, scope, address)
	if err != nil || before.Reservation.HostID != worker || before.Reservation.Generation != first.Generation {
		t.Fatalf("VM writer changed after lease loss alone: %v", err)
	}
	if err := r.ApplyStorageFence(ctx, storage.SignedFence{Attestation: body}); !errors.Is(err, arm.ErrStorageAccess) {
		t.Fatalf("unsigned fence was accepted: %v", err)
	}
	if err := r.ApplyStorageFence(ctx, signed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileVMFencePage(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if live, err := r.GetVirtualMachineInstanceView(ctx, scope, "", address); err != nil || live == nil || live.Statuses[1].Code != "PowerState/unknown" {
		t.Fatalf("VM advertised a power state while fenced and awaiting placement: %+v %v", live, err)
	}
	seedVMWorker(t, ctx, r, worker, true)
	if previous, err := r.HostVirtualMachineTasks(ctx, worker, []byte(worker), ""); err != nil || len(previous.Tasks) != 0 {
		t.Fatalf("fenced worker recovered its retired assignment: %v", err)
	}
	const replacement = "c-kvm"
	seedVMWorker(t, ctx, r, replacement, true)
	if _, err := r.reconcileVMFencePage(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplyStorageFence(ctx, signed); err != nil {
		t.Fatalf("fence replay changed the accepted proof: %v", err)
	}
	recovered := readVMStoreTask(t, ctx, r, replacement)
	defer clear(recovered.VolumeKey)
	if recovered.Network == nil || recovered.Network.Address != first.Network.Address || recovered.MachineID != first.MachineID ||
		recovered.Disk != first.Disk || !recovered.Prepared || recovered.Generation == first.Generation ||
		len(recovered.VolumeKey) != 32 || !bytes.Equal(recovered.VolumeKey, first.VolumeKey) {
		t.Fatal("relocation changed the VM private address, disk, key or hardware identity, or reused its generation")
	}
	if err := r.ReportVirtualMachine(ctx, worker, []byte(worker), workload.VMReport{AssignmentID: first.AssignmentID, State: workload.Running}); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("retired VM generation can still report state: %v", err)
	}
	if err := r.ReportVirtualMachine(ctx, replacement, []byte(replacement), workload.VMReport{AssignmentID: recovered.AssignmentID, State: workload.Running}); err != nil {
		t.Fatal(err)
	}
	if usage, err := r.counter(ctx, r.hostKey("placement-usage", worker)); err != nil || usage.used != (enrollment.Capacity{}) {
		t.Fatalf("fenced worker retained the relocated reservation: %+v %v", usage, err)
	}
	t.Log("a persisted signed fence changed the writer generation only after capacity became available, preserving disk, key, identity and private address")
	return replacement
}
