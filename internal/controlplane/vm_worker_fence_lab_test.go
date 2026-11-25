//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/lab"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const vmLabSpare = "farm-1-node-06"

type packagedVMFence struct {
	planned lab.Plan
	fencer  ed25519.PublicKey
	auth    []byte
}

func loadPackagedVMFence(t *testing.T, state string) *packagedVMFence {
	t.Helper()
	authPath := os.Getenv("OCEAN_E2E_VM_SMB_AUTH")
	if authPath == "" {
		return nil
	}
	info, err := os.Stat(authPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		t.Fatal("provide a private SMB authentication file for the disposable Windows checkpoint account")
	}
	auth, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(auth) })
	plan, err := lab.LoadPlan(os.Getenv("OCEAN_E2E_VM_FENCE_PROFILE"))
	if err != nil {
		t.Fatalf("load the original VM lab profile: %v", err)
	}
	cert, err := os.ReadFile(filepath.Join(state, "storage-pki", "lab-fencer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("invalid KVM lab fencer public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	fencer, ok := key.(ed25519.PublicKey)
	if err != nil || !ok {
		t.Fatal("the lab fencer requires an Ed25519 public key")
	}
	return &packagedVMFence{planned: plan, fencer: fencer, auth: auth}
}

type windowsVMCheckpoint struct {
	UUID     string    `json:"machineUUID"`
	GUID     string    `json:"machineGuid"`
	Hostname string    `json:"computerName"`
	Build    string    `json:"build"`
	BootedAt time.Time `json:"bootedAt"`
}

func (f packagedVMFence) verify(t *testing.T, ctx context.Context, vmLab *lab.Lab, worker directoryKVMHosts,
	r *Region, api *httptest.Server, scope arm.SubscriptionScope, address arm.ResourceAddress) {
	t.Helper()
	_, first, _, _, _, err := r.readVM(ctx, scope, address)
	if err != nil || first.Reservation.HostID != vmLabPrimary || first.Observed != workload.Running || !first.Prepared {
		t.Fatalf("the initial VM is not running on the expected writer: %v", err)
	}
	probe := startVMCheckpointClient(t, ctx, worker, f.auth)
	marker := make([]byte, 48)
	rand.Read(marker)
	worker.run(ctx, vmLabSpare, "sudo tee "+probe.path+"/sent >/dev/null", bytes.NewReader(marker))
	var before windowsVMCheckpoint
	pollVMWorker(t, ctx, 65*time.Second, "the Windows SMB checkpoint upload and readback", func() bool {
		output, err := probe.smb(ctx, "put "+probe.path+"/sent data/checkpoint")
		if err != nil {
			t.Logf("waiting for the SMB upload: %s", strings.TrimSpace(string(output)))
			return false
		}
		before, err = probe.read(ctx)
		return err == nil
	})
	if !strings.EqualFold(before.UUID, first.MachineID) || before.GUID == "" || before.Hostname == "" || before.Build != "26100" || before.BootedAt.IsZero() {
		t.Fatalf("unexpected initial Windows guest identity: %+v", before)
	}
	t.Logf("Windows build %s acknowledged an encrypted SMB checkpoint at 10.232.1.20", before.Build)

	partitionVMPrimary(t, ctx, worker, api.URL)
	pollVMWorker(t, ctx, 65*time.Second, "the partitioned worker's placement lease to expire", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", vmLabPrimary), clientv3.WithCountOnly())
		return err == nil && live.Count == 0
	})
	if _, err := r.reconcileVMFencePage(ctx, ""); err != nil {
		t.Fatal(err)
	}
	verifyVMFenceAssignment(t, ctx, r, scope, first, vmLabSpare)
	if vmDiskMapping(t, ctx, worker, vmLabPrimary, first.Disk.ID) != 1 || vmDiskMapping(t, ctx, worker, vmLabSpare, first.Disk.ID) != 0 {
		t.Fatal("lease loss changed the number of attached disk writers")
	}
	if _, err := probe.smb(ctx, "ls"); err == nil {
		t.Fatal("the partitioned guest accepted traffic after its network policy lease expired")
	}
	t.Log("the partition expired the placement and network leases while the old worker alone retained the writable disk")

	proof := storage.FenceAttestation{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, VolumeID: first.Disk.ID,
		HostID: vmLabPrimary, PlacementID: first.Reservation.ID, Generation: first.Reservation.Generation}
	started := time.Now()
	signed := powerOffLabVMWriter(t, ctx, worker, proof)
	forged := signed
	forged.Signature = make([]byte, ed25519.SignatureSize)
	verifyFenceHTTP(t, ctx, api, forged, http.StatusForbidden)
	verifyVMFenceAssignment(t, ctx, r, scope, first, vmLabSpare)
	verifyFenceHTTP(t, ctx, api, signed, http.StatusNoContent)
	verifyFenceHTTP(t, ctx, api, signed, http.StatusNoContent)
	pollVMWorker(t, ctx, 3*time.Minute, "the fenced Windows VM to boot on the standby worker", func() bool {
		if _, err := r.reconcileVMFencePage(ctx, ""); err != nil {
			t.Fatal(err)
		}
		_, record, op, _, _, err := r.readVM(ctx, scope, address)
		return err == nil && op != nil && op.Status == arm.OperationSucceeded && record.Observed == workload.Running &&
			record.Reservation.HostID == vmLabSpare && record.Reservation.Generation != first.Reservation.Generation &&
			record.Disk == first.Disk && record.MachineID == first.MachineID
	})
	var after windowsVMCheckpoint
	pollVMWorker(t, ctx, 65*time.Second, "the replacement Windows SMB checkpoint and new boot record", func() bool {
		var err error
		after, err = probe.read(ctx)
		return err == nil && after.BootedAt.After(before.BootedAt)
	})
	if after.UUID != before.UUID || after.GUID != before.GUID || after.Hostname != before.Hostname || after.Build != before.Build {
		t.Fatalf("Windows machine identity changed during fenced replacement: %+v then %+v", before, after)
	}
	t.Logf("confirmed power loss, fenced replacement, identical SMB checkpoint and Windows identity after %s", time.Since(started).Round(time.Millisecond))

	if err := vmLab.UpSelected(ctx, f.planned, "", 0, []string{vmLabPrimary}); err != nil {
		t.Fatal(err)
	}
	pollVMWorker(t, ctx, 75*time.Second, "the retired Debian worker to reboot", func() bool {
		ping, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		_, err := worker.ssh(ping, vmLabPrimary, "true", nil)
		return err == nil
	})
	worker.run(ctx, vmLabPrimary, "sudo systemctl start ocean-vm-agent.service", nil)
	waitPackagedVMHost(t, ctx, r, vmLabPrimary)
	if vmDiskMapping(t, ctx, worker, vmLabPrimary, first.Disk.ID) != 0 || vmDiskMapping(t, ctx, worker, vmLabSpare, first.Disk.ID) != 1 {
		t.Fatal("the original worker regained the detached disk writer after reboot")
	}
	tasks, err := r.client.Get(ctx, r.hostVMPrefix(vmLabPrimary), clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil || tasks.Count != 0 {
		t.Fatalf("the original worker regained a regional VM assignment: %v", err)
	}
	t.Log("the rebooted Debian worker rejoined without a VM assignment or writable disk map")
}

func partitionVMPrimary(t *testing.T, ctx context.Context, worker directoryKVMHosts, apiURL string) {
	t.Helper()
	endpoint, err := url.Parse(apiURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil || port == 0 || endpoint.Hostname() != "127.0.0.1" {
		t.Fatal("the VM worker partition requires a loopback API fixture")
	}
	const table = "ocean_vm_lab_partition"
	rules := fmt.Sprintf(`add table inet %[1]s
add chain inet %[1]s output { type filter hook output priority filter; policy accept; }
add rule inet %[1]s output ip daddr 10.0.2.2 tcp dport %[2]d reject with tcp reset
`, table, port)
	worker.run(ctx, vmLabPrimary, "sudo nft -f -", strings.NewReader(rules))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, _ = worker.ssh(cleanup, vmLabPrimary, "if sudo nft list table inet "+table+" >/dev/null 2>&1; then sudo nft delete table inet "+table+"; fi", nil)
	})
}

func verifyVMFenceAssignment(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, first vmRecord, spare string) {
	t.Helper()
	writer, err := r.client.Get(ctx, r.writerKey(scope, first.Disk.ID))
	if err != nil {
		t.Fatal(err)
	}
	var grant volumeWriter
	if len(writer.Kvs) != 1 || json.Unmarshal(writer.Kvs[0].Value, &grant) != nil || grant != first.writer() {
		t.Fatal("the authoritative writer changed before a valid fence")
	}
	tasks, err := r.client.Get(ctx, r.hostVMPrefix(spare), clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil || tasks.Count != 0 {
		t.Fatalf("the standby received a VM assignment before a valid fence: %v", err)
	}
}

func vmDiskMapping(t *testing.T, ctx context.Context, worker directoryKVMHosts, host, disk string) int {
	t.Helper()
	output, err := worker.ssh(ctx, host, "sudo rbd --conf /etc/ocean-agent/ceph.conf device list --format json", nil)
	if err != nil {
		t.Fatalf("inspect Ceph mappings on %s: %v: %s", host, err, output)
	}
	var maps []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(output, &maps); err != nil {
		t.Fatalf("decode Ceph mappings on %s: %v: %s", host, err, output)
	}
	count := 0
	for _, mapping := range maps {
		if mapping.Name == disk {
			count++
		}
	}
	return count
}

func powerOffLabVMWriter(t *testing.T, ctx context.Context, worker directoryKVMHosts, proof storage.FenceAttestation) storage.SignedFence {
	t.Helper()
	assignment, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	const script = `import json, sys
from pathlib import Path
from fencing import sign_terminal_state
print(json.dumps(sign_terminal_state(Path(sys.argv[1]), json.load(sys.stdin))))`
	command := exec.CommandContext(ctx, "python3", "-B", "-c", script, worker.state)
	command.Dir = filepath.Join(worker.root, "lab")
	command.Stdin = bytes.NewReader(assignment)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("the lab fence authority could not confirm power-off: %v", err)
	}
	var signed storage.SignedFence
	if err := json.Unmarshal(output, &signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

func verifyFenceHTTP(t *testing.T, ctx context.Context, api *httptest.Server, signed storage.SignedFence, status int) {
	t.Helper()
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, api.URL+"/ocean/storage/fences", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := api.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != status {
		t.Fatalf("storage fence API returned %s, expected %d", response.Status, status)
	}
}

type vmCheckpointClient struct {
	worker          directoryKVMHosts
	namespace, path string
}

func startVMCheckpointClient(t *testing.T, ctx context.Context, worker directoryKVMHosts, auth []byte) vmCheckpointClient {
	t.Helper()
	probe := vmCheckpointClient{worker: worker, namespace: worker.directory, path: "/run/" + worker.directory}
	worker.run(ctx, vmLabSpare, "sudo install -d -m 0700 "+probe.path, nil)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		worker.run(cleanup, vmLabSpare, fmt.Sprintf(`for file in auth sent received identity; do
    if sudo test -f %[2]s/$file; then sudo unlink %[2]s/$file; fi
done
if sudo test -e /run/netns/%[1]s; then sudo ip netns del %[1]s; fi
sudo rmdir %[2]s`, probe.namespace, probe.path), nil)
	})
	worker.run(ctx, vmLabSpare, "sudo sh -c 'umask 077; cat >"+probe.path+"/auth'", bytes.NewReader(auth))
	worker.run(ctx, vmLabSpare, fmt.Sprintf(`set -eu
sudo ip netns add %[1]s
sudo ip link add link work0 name vmpeer netns %[1]s type macvlan mode bridge
sudo ip -n %[1]s addr add 10.232.1.21/28 dev vmpeer
sudo ip -n %[1]s link set vmpeer up`, probe.namespace), nil)
	return probe
}

func (p vmCheckpointClient) smb(ctx context.Context, commands string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	command := fmt.Sprintf("sudo ip netns exec %s smbclient //10.232.1.20/OceanVmProbe -A %s/auth -m SMB3 --client-protection=encrypt --use-kerberos=off -t 4 -c '%s'",
		p.namespace, p.path, commands)
	return p.worker.ssh(ctx, vmLabSpare, command, nil)
}

func (p vmCheckpointClient) read(ctx context.Context) (windowsVMCheckpoint, error) {
	var identity windowsVMCheckpoint
	output, err := p.smb(ctx, "get identity.json "+p.path+"/identity; get data/checkpoint "+p.path+"/received")
	if err != nil {
		return identity, fmt.Errorf("SMB checkpoint read: %w: %s", err, output)
	}
	output, err = p.worker.ssh(ctx, vmLabSpare, "sudo cmp "+p.path+"/sent "+p.path+"/received && sudo cat "+p.path+"/identity", nil)
	if err != nil {
		return identity, fmt.Errorf("SMB checkpoint comparison: %w: %s", err, output)
	}
	return identity, json.Unmarshal(output, &identity)
}
