//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/lab"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const smbLabStandby = "farm-1-node-08"

func TestPackagedSMBFailover(t *testing.T) {
	state, fixture, endpoint := os.Getenv("OCEAN_E2E_DOMAIN_STATE"), os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE"), os.Getenv("OCEAN_E2E_SMB_ETCD")
	az, profile := os.Getenv("OCEAN_E2E_SMB_AZ"), os.Getenv("OCEAN_E2E_SMB_FAILOVER_PROFILE")
	if state == "" || fixture == "" || endpoint == "" || az == "" || profile == "" {
		t.Skip("requires the dedicated two-member SMB lab, its profile, loopback etcd and pinned Azure CLI")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := lab.LoadPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()

	raw, err := os.ReadFile(filepath.Join(fixture, "member-rbd.json"))
	var member smb.Member
	if err != nil || json.Unmarshal(raw, &member) != nil || len(member.Shares) != 1 || member.Validate() != nil {
		t.Fatalf("read the native SMB fixture: %v", err)
	}
	policy := smb.Policy{QuotaGiB: 1, ReaderSIDs: member.Shares[0].ReaderSIDs, WriterSIDs: member.Shares[0].WriterSIDs}
	id, err := os.ReadFile(filepath.Join(fixture, "failover-state-id"))
	if err != nil {
		t.Fatal(err)
	}
	const vip = "10.232.1.40"
	member.Shares = nil
	member.Address, member.ServiceInterface = netip.MustParseAddr(vip), "work0"
	member.StateVolumeID = strings.TrimSpace(string(id))
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	binding := smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		HostID: smbLabHost, StandbyHostID: smbLabStandby, Member: member, StateKeyFile: filepath.Join(fixture, "failover-state.key")}
	public, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(signer) })
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	fencer := filepath.Join(t.TempDir(), "smb-fence.pem")
	if err := os.WriteFile(fencer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	r := setupSMBWorkerRegion(t, endpoint, binding, fencer)
	api, caFile, caPEM := startSMBLabAPI(t, r, scope, arm.SubscriptionScope{})
	worker := directoryKVMHosts{root: root, state: state, directory: "smb-failover-" + scope.TenantID[:8], t: t}
	origin := directoryGuestOrigin(t, api)
	startSMBWorkerHost(t, ctx, r, worker, smbLabHost, origin, caPEM, true)
	startSMBWorkerHost(t, ctx, r, worker, smbLabStandby, origin, caPEM, false)
	isLive := func(host string, expected int64) bool {
		live, err := r.client.Get(ctx, r.hostKey("live", host), clientv3.WithCountOnly())
		return err == nil && live.Count == expected
	}
	pollVMWorker(t, ctx, 45*time.Second, "both SMB members to enroll", func() bool {
		return isLive(smbLabHost, 1) && isLive(smbLabStandby, 1)
	})
	readOwner := func() smbOwner {
		t.Helper()
		rows, err := r.client.Get(ctx, r.smbOwnerKey(binding))
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := readSMBOwner(binding, rows.Kvs)
		if err != nil {
			t.Fatal(err)
		}
		return owner
	}
	denyPlan := func(host string) {
		t.Helper()
		_, registered, _, err := r.Enrollment(ctx, host)
		if err != nil || registered == nil {
			t.Fatalf("read the enrolled SMB host %s: %v", host, err)
		}
		plan, err := r.HostSMBPlan(ctx, host, registered.Certificate)
		defer plan.ClearKeys()
		if !errors.Is(err, enrollment.ErrHostDenied) || len(plan.StateKey) != 0 || len(plan.Volumes) != 0 {
			t.Fatalf("unassigned SMB host %s obtained a storage plan: %v", host, err)
		}
	}
	firstOwner := readOwner()
	if firstOwner.HostID != smbLabHost {
		t.Fatal("the fixture must begin with the primary as the member owner")
	}
	worker.run(ctx, smbLabStandby, "sudo systemctl start ocean-smb-agent.service", nil)
	denyPlan(smbLabStandby)

	const group, shareName = "smb-failover", "failover-files"
	share := arm.ResourceAddress{Group: group, Path: smb.ResourceType + "/" + shareName}
	cli := regionalWorkerCLI(t, ctx, api.URL, caFile, az)
	call := func(method, path string, body []byte, expected string) []byte {
		t.Helper()
		return cli(method, path, string(body), "smb-worker-lab", expected)
	}
	call("put", "/subscriptions/"+scope.SubscriptionID+"/resourceGroups/"+group+"?api-version=2024-11-01",
		fmt.Appendf(nil, `{"location":%q}`, r.name), "")
	url := share.ID(scope) + "?api-version=" + smb.APIVersion
	payload, err := json.Marshal(map[string]any{"location": r.name, "properties": policy})
	if err != nil {
		t.Fatal(err)
	}
	call("put", url, payload, "")
	initial := readSMBLabShare(t, ctx, r, binding)
	waitOperation := func(id string) {
		t.Helper()
		pollVMWorker(t, ctx, 90*time.Second, "the SMB worker to complete "+id, func() bool {
			op, err := r.GetOperation(ctx, scope, id)
			return err == nil && op != nil && op.Status == arm.OperationSucceeded
		})
	}
	worker.run(ctx, smbLabHost, "sudo systemctl start ocean-smb-agent.service", nil)
	waitOperation(initial.Operation)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, vip, member.StateVolumeID, initial.Volume.ID, true)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, initial.Volume.ID, false)

	const client = "farm-1-node-02"
	marker := operationID()
	probe := smbFailoverClient(t, worker, fixture, vip, shareName, marker)
	type reply struct {
		output []byte
		err    error
	}
	clientHold := make(chan reply, 1)
	clientDone := make(chan struct{})
	control := "/tmp/ocean-failover-" + marker
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, _ = worker.ssh(cleanup, client, "if test -d "+control+"; then touch "+control+"/abort; fi", nil)
		select {
		case <-clientDone:
			_, _ = worker.ssh(cleanup, client, "if test -d "+control+"; then find "+control+" -maxdepth 1 -type f -delete && rmdir "+control+"; fi", nil)
		case <-cleanup.Done():
			t.Error("the CIFS descriptor probe did not exit during cleanup")
		}
	}()
	go func() {
		defer close(clientDone)
		output, err := probe(ctx, "hold")
		clientHold <- reply{output, err}
	}()
	pollVMWorker(t, ctx, 35*time.Second, "the CIFS write, fsync and byte-range lock", func() bool {
		select {
		case result := <-clientHold:
			t.Fatalf("hold the SMB file: %v: %s", result.err, result.output)
		default:
		}
		probeContext, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		_, err := worker.ssh(probeContext, client, "test -f "+control+"/ready", nil)
		return err == nil
	})
	partitioned := time.Now()
	partitionWorkerAPI(t, ctx, worker, api.URL, smbLabHost, "ocean_smb_lab_partition")
	pollVMWorker(t, ctx, 65*time.Second, "the old SMB member's lease to expire", func() bool {
		return isLive(smbLabHost, 0)
	})
	leaseExpired := time.Since(partitioned)
	if firstOwner != readOwner() {
		t.Fatal("a management partition changed the SMB owner")
	}
	denyPlan(smbLabStandby)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, vip, member.StateVolumeID, initial.Volume.ID, true)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, initial.Volume.ID, false)
	if out, err := probe(ctx, "read"); err != nil {
		t.Fatalf("read the flushed checkpoint during the management partition: %v: %s", err, out)
	}
	if out, err := probe(ctx, "locked"); err != nil {
		t.Fatalf("verify the old member still enforces the byte-range lock: %v: %s", err, out)
	}
	t.Logf("the old member remained the only writer after its management lease expired in %s", leaseExpired.Round(time.Millisecond))

	fenceStart := time.Now()
	if err := workspace.Stop(smbLabHost); err != nil {
		t.Fatal(err)
	}
	bootPrimary := func(restartContext context.Context) error {
		return workspace.UpSelected(restartContext, planned, "", 0, []string{smbLabHost})
	}
	t.Cleanup(func() {
		restart, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := bootPrimary(restart); err != nil {
			t.Errorf("restore the original SMB lab guest: %v", err)
		}
		pollVMWorker(t, restart, 40*time.Second, "the restored SMB lab guest's SSH endpoint", func() bool {
			_, err := worker.ssh(restart, smbLabHost, "true", nil)
			return err == nil
		})
	})
	pollVMWorker(t, ctx, 15*time.Second, "the original SMB writer to stop", func() bool {
		nodes, err := workspace.Status()
		return err == nil && slices.ContainsFunc(nodes, func(node lab.GuestStatus) bool {
			return node.Guest.Name == smbLabHost && !node.Running
		})
	})
	proof, err := json.Marshal(smb.FenceAttestation{
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: smbLabHost,
		Generation: firstOwner.Generation, Observation: storage.PoweredOff, ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(signer, proof)
	signed := func(sig []byte) []byte {
		t.Helper()
		data, err := json.Marshal(storage.SignedFence{Attestation: proof, Signature: sig})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	const fencePath = "/ocean/storage/smb-fences"
	call("post", fencePath, signed(make([]byte, ed25519.SignatureSize)), "StorageAuthorizationFailed")
	if firstOwner != readOwner() {
		t.Fatal("an invalid signature changed the SMB owner")
	}
	onWire := signed(signature)
	call("post", fencePath, onWire, "")
	call("post", fencePath, onWire, "")
	recoveredOwner, recovered := readOwner(), readSMBLabShare(t, ctx, r, binding)
	if recoveredOwner.HostID != smbLabStandby || recoveredOwner.Generation == firstOwner.Generation ||
		recovered.Volume != initial.Volume || !bytes.Equal(recovered.Envelope, initial.Envelope) || recovered.Operation == initial.Operation {
		t.Fatal("the fence did not preserve the encrypted storage while changing the writer generation")
	}
	waitOperation(recovered.Operation)
	view := call("get", url, nil, "")
	if !bytes.Contains(view, []byte("Succeeded")) || !bytes.Contains(view, []byte("//files04.ad.ocean.test/"+shareName)) {
		t.Fatalf("unexpected recovered SMB endpoint: %s", view)
	}
	if out, err := probe(ctx, "read"); err != nil {
		t.Fatalf("read the flushed checkpoint after reconnecting: %v: %s", err, out)
	}
	reconnect := time.Since(fenceStart)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, initial.Volume.ID, true)
	worker.run(ctx, client, "touch "+control+"/resume", nil)
	var handleOutcome string
	select {
	case result := <-clientHold:
		if result.err != nil {
			t.Fatalf("read from the pre-fence CIFS descriptor: %v: %s", result.err, result.output)
		}
		for _, line := range strings.Split(string(result.output), "\n") {
			if strings.HasPrefix(line, "oldHandle=") {
				handleOutcome = strings.TrimPrefix(line, "oldHandle=")
			}
		}
		if handleOutcome == "" {
			t.Fatalf("the old CIFS descriptor produced no observation: %s", result.output)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("the old descriptor did not complete its recovery probe")
	}
	if out, err := probe(ctx, "reopen"); err != nil {
		t.Fatalf("reopen, acquire a new lock and flush to the replacement: %v: %s", err, out)
	}

	if err := bootPrimary(ctx); err != nil {
		t.Fatal(err)
	}
	pollVMWorker(t, ctx, 75*time.Second, "the retired SMB guest to reboot", func() bool {
		probeContext, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		_, err := worker.ssh(probeContext, smbLabHost, "true", nil)
		return err == nil
	})
	worker.run(ctx, smbLabHost, "set -eu\n"+packagedDirectoryWorker+
		"worker systemctl --user restart ocean-agent.service\nsudo systemctl start ocean-smb-agent.service", nil)
	pollVMWorker(t, ctx, 45*time.Second, "the original SMB member to re-enroll", func() bool { return isLive(smbLabHost, 1) })
	denyPlan(smbLabHost)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, vip, member.StateVolumeID, initial.Volume.ID, false)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, initial.Volume.ID, true)
	call("delete", url, nil, "")
	waitOperation(smbLabDeleteOperation(t, ctx, r, scope))
	call("get", url, nil, "ResourceNotFound")
	evidence, err := json.MarshalIndent(map[string]any{
		"azureCLI": "2.93.0", "primary": smbLabHost, "replacement": smbLabStandby,
		"managementLeaseExpiryMilliseconds": leaseExpired.Milliseconds(), "powerOffToVerifiedReconnectMilliseconds": reconnect.Milliseconds(),
		"oldHandle": handleOutcome, "acknowledgedBytesRetained": true, "lockEnforcedDuringPartition": true, "replacementLockAndWriteVerified": true,
		"forgedFenceDenied": true, "replayedFenceAccepted": true, "oldOwnerDeniedAfterRestart": true,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "evidence", "kerberos-smb-failover.json"), append(evidence, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("fenced SMB recovery and verified Kerberos reconnect took %s; pre-fence CIFS handle: %s",
		reconnect.Round(time.Millisecond), handleOutcome)
}

func smbFailoverClient(t *testing.T, worker directoryKVMHosts, fixture, address, share, marker string) func(context.Context, string) ([]byte, error) {
	t.Helper()
	script, err := os.ReadFile(filepath.Join(worker.root, "lab/verify_smb_failover_client.sh"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture, "smbwriter")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 128 {
		t.Fatalf("provide a private lab Kerberos client credential: %v", err)
	}
	quoted := "'" + strings.ReplaceAll(string(script), "'", "'\"'\"'") + "'"
	return func(ctx context.Context, mode string) ([]byte, error) {
		password, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		defer clear(password)
		password = bytes.TrimSuffix(password, []byte{'\n'})
		if len(password) == 0 || bytes.ContainsAny(password, "\n\x00") {
			return nil, errors.New("invalid lab Kerberos client credential")
		}
		input := io.MultiReader(bytes.NewReader(password), strings.NewReader("\n"))
		return worker.ssh(ctx, "farm-1-node-02",
			fmt.Sprintf("keyctl session - bash -c %s -- %s %s %s %s", quoted, mode, address, share, marker), input)
	}
}

func assertSMBLabPlacement(t *testing.T, ctx context.Context, worker directoryKVMHosts, host, addr, stateID, shareID string, active bool) {
	t.Helper()
	output, err := worker.ssh(ctx, host, "sudo rbd --conf /etc/ocean-smb/rbd/ceph.conf device list --format json", nil)
	if err != nil {
		t.Fatalf("inspect block device mappings on %s: %v: %s", host, err, output)
	}
	type mapping struct {
		Name string `json:"name"`
	}
	var mappings []mapping
	if err := json.Unmarshal(output, &mappings); err != nil {
		t.Fatalf("decode block device mappings on %s: %v: %s", host, err, output)
	}
	for _, id := range []string{stateID, shareID} {
		attached := slices.ContainsFunc(mappings, func(entry mapping) bool { return entry.Name == id })
		if attached != active {
			t.Fatalf("unexpected writable block device mapping on %s for %s: %t", host, id, attached)
		}
	}
	found, err := worker.ssh(ctx, host, "ip -4 -o address show dev work0 && sudo ss -H -ltn '( sport = :445 )'", nil)
	listeners := bytes.Count(found, []byte(":445"))
	if err != nil || bytes.Contains(found, []byte(addr+"/32")) != active ||
		active && (listeners != 1 || !bytes.Contains(found, []byte(addr+":445"))) || !active && listeners != 0 {
		t.Fatalf("unexpected SMB service placement on %s: %v: %s", host, err, found)
	}
}
