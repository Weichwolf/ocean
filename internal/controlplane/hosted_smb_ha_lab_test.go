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
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedSMBStandbyHost = "worker-b"

func TestHostedSMBHAOffboarding(t *testing.T) {
	state, fixture := os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE"), os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE")
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	profile := os.Getenv("OCEAN_E2E_SMB_FAILOVER_PROFILE")
	if state == "" || fixture == "" || archive == "" || cli == "" || profile == "" {
		t.Skip("requires the disposable two-member SMB KVM lab and profile, pinned etcd, and stock Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	labPlan, err := lab.LoadPlan(profile)
	if err != nil {
		t.Fatal(err)
	}
	var member smb.Member
	raw, err := os.ReadFile(filepath.Join(fixture, "member-rbd.json"))
	if err != nil || json.Unmarshal(raw, &member) != nil || member.Validate() != nil || len(member.Shares) != 1 {
		t.Fatalf("read the lab member fixture: %v", err)
	}
	policy := smb.Policy{QuotaGiB: 1, ReaderSIDs: member.Shares[0].ReaderSIDs, WriterSIDs: member.Shares[0].WriterSIDs}
	const vip = "10.232.1.40"
	standaloneVolume := member.Shares[0].VolumeID
	member.Shares, member.Address, member.ServiceInterface = nil, netip.MustParseAddr(vip), "work0"
	worker := directoryKVMHosts{root: root, state: state, directory: "hosted-smb-ha-" + operationID()[:12], t: t}
	restoreShare := restoreHostedSMBLabShare(t, ctx, worker, fixture, standaloneVolume)
	member.StateVolumeID = cloneHostedSMBState(t, ctx, worker, fixture)
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	binding := smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: hostedSuspensionHost,
		StandbyHostID: hostedSMBStandbyHost, StateKeyFile: filepath.Join(fixture, "failover-state.key"), Member: member}
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-smb-ha")
	cfg.ManagedDirectories = &enrollment.Capacity{CPUMillis: 500, MemoryMiB: 256}
	cfg.SMBMembers = []smbBinding{binding}
	signer, path := hostedSMBTestFencer(t)
	defer clear(signer)
	cfg.Storage.FencePublicKeyFile = path
	r := openHostedLabRegion(t, ctx, cfg)
	seedHostedLabTenant(t, ctx, r, tenant)
	seedHostedSMBDomain(t, ctx, r, binding)
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, scope.TenantID)
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate())
	primaryConfig, primaryCert := identityFor(binding.HostID)
	standbyConfig, standbyCert := identityFor(binding.StandbyHostID)
	var shareVolume string
	t.Cleanup(func() {
		if shareVolume == "" {
			return
		}
		clean, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		image := "ocean/" + shareVolume
		if out, err := worker.ssh(clean, smbRecoveryCeph, "if sudo rbd info "+image+" >/dev/null 2>&1; then sudo rbd rm "+image+"; fi", nil); err != nil {
			t.Errorf("clean the disposable SMB share: %v: %s", err, out)
		}
	})
	primary := stageHostedSMBHAMember(t, ctx, worker, smbLabHost, primaryConfig, restoreShare)
	standby := stageHostedSMBHAMember(t, ctx, worker, smbLabStandby, standbyConfig, nil)
	registerNamedHostedLabWorker(t, ctx, r, binding.HostID, primaryCert)
	registerNamedHostedLabWorker(t, ctx, r, binding.StandbyHostID, standbyCert)
	primary()
	standby()

	tenantCall := func(method, path, body, expected string) []byte {
		t.Helper()
		return az(method, path, body, sign(tenant.TenantID, operatorClient, tenant.Administrator, origin), expected)
	}
	operatorCall := func(method, path, body, expected string) []byte {
		t.Helper()
		return az(method, path, body, sign(operatorRealm, operatorClient, operator, origin), expected)
	}
	const shareName = "hosted-ha-files"
	address := arm.ResourceAddress{Group: "retained-fixture", Path: smb.ResourceType + "/" + shareName}
	sharePath := address.ID(scope) + "?api-version=" + smb.APIVersion
	body, err := json.Marshal(map[string]any{"location": r.name, "properties": policy})
	if err != nil {
		t.Fatal(err)
	}
	tenantCall("put", sharePath, string(body), "")
	record := hostedSMBLabRecord(t, ctx, r, binding, shareName)
	shareVolume = record.Volume.ID
	waitHostedSMBRecovery(t, ctx, r, scope, record.Operation)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, vip, member.StateVolumeID, record.Volume.ID, true)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, record.Volume.ID, false)
	denyHostedSMBHost(t, ctx, r, binding.StandbyHostID, standbyCert)
	probeCheckpoint := smbFailoverClient(t, worker, fixture, vip, shareName, operationID())
	if out, err := probeCheckpoint(ctx, "checkpoint"); err != nil {
		t.Fatalf("fsync the native SMB checkpoint: %v: %s", err, out)
	}

	first, _ := hostedSMBLabOwner(t, ctx, r, binding)
	firstPlan, err := r.HostSMBPlan(ctx, binding.HostID, primaryCert)
	if err != nil {
		t.Fatal(err)
	}
	priorReceipt := firstPlan.Receipt()
	firstPlan.ClearKeys()
	bootMember := func(ctx context.Context, guest string) {
		t.Helper()
		if err := workspace.UpSelected(ctx, labPlan, "", 0, []string{guest}); err != nil {
			t.Errorf("restore the lab guest %s: %v", guest, err)
			return
		}
		pollVMWorker(t, ctx, 45*time.Second, "SSH after booting "+guest, func() bool {
			_, err := worker.ssh(ctx, guest, "true", nil)
			return err == nil
		})
	}
	stopMember := func(owner smbOwner, guest string) {
		t.Helper()
		t.Cleanup(func() {
			clean, stop := context.WithTimeout(context.Background(), 60*time.Second)
			defer stop()
			bootMember(clean, guest)
		})
		shortenHostedTestLease(t, ctx, r, owner.HostID)
		if err := workspace.Stop(guest); err != nil {
			t.Fatal(err)
		}
		pollVMWorker(t, ctx, 15*time.Second, "the fenced KVM guest and its lease to stop", func() bool {
			guests, err := workspace.Status()
			if err != nil || !slices.ContainsFunc(guests, func(g lab.GuestStatus) bool { return g.Guest.Name == guest && !g.Running }) {
				return false
			}
			live, err := r.client.Get(ctx, r.hostKey("live", owner.HostID), clientv3.WithCountOnly())
			return err == nil && live.Count == 0
		})
	}
	stopMember(first, smbLabHost)
	denyHostedSMBHost(t, ctx, r, binding.StandbyHostID, standbyCert)
	registerNamedHostedLabWorker(t, ctx, r, binding.StandbyHostID, standbyCert)
	denyHostedSMBHost(t, ctx, r, binding.StandbyHostID, standbyCert)
	prepareFence := func(owner smbOwner, signed bool) string {
		t.Helper()
		attestation, err := json.Marshal(smb.FenceAttestation{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
			HostID: owner.HostID, Generation: owner.Generation, Observation: storage.PoweredOff, ObservedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		signature := make([]byte, ed25519.SignatureSize)
		if signed {
			signature = ed25519.Sign(signer, attestation)
		}
		raw, err := json.Marshal(storage.SignedFence{Attestation: attestation, Signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	const fencePath = "/ocean/storage/smb-fences"
	tenantCall("post", fencePath, prepareFence(first, false), "StorageAuthorizationFailed")
	tenantCall("post", fencePath, prepareFence(first, true), "")
	second, _ := hostedSMBLabOwner(t, ctx, r, binding)
	if second.HostID != binding.StandbyHostID || second.Generation == first.Generation {
		t.Fatal("fencing did not move the certified writer generation to the standby")
	}
	replacement := hostedSMBLabRecord(t, ctx, r, binding, shareName)
	if replacement.Volume != record.Volume || !bytes.Equal(replacement.Envelope, record.Envelope) {
		t.Fatal("failover changed the encrypted share identity")
	}
	waitHostedSMBRecovery(t, ctx, r, scope, replacement.Operation)
	assertSMBLabPlacement(t, ctx, worker, smbLabStandby, vip, member.StateVolumeID, record.Volume.ID, true)
	var lastCheckpointFailure []byte
	t.Cleanup(func() {
		if t.Failed() && len(lastCheckpointFailure) != 0 {
			t.Logf("last native SMB checkpoint probe:\n%s", lastCheckpointFailure)
		}
	})
	pollVMWorker(t, ctx, 25*time.Second, "a native client to recover the checkpoint after fencing", func() bool {
		probe, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		out, err := probeCheckpoint(probe, "verify-checkpoint")
		lastCheckpointFailure = out
		return err == nil
	})

	bootMember(ctx, smbLabHost)
	registerNamedHostedLabWorker(t, ctx, r, binding.HostID, primaryCert)
	registerNamedHostedLabWorker(t, ctx, r, binding.StandbyHostID, standbyCert)
	primary()
	denyHostedSMBHost(t, ctx, r, binding.HostID, primaryCert)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, vip, member.StateVolumeID, record.Volume.ID, false)

	// Delay the current worker so the test can examine the withdrawal plan
	// before any acknowledgment is possible.
	unit := worker.directory + ".service"
	worker.run(ctx, smbLabStandby, "sudo systemctl kill --signal=STOP --kill-whom=main "+unit, nil)
	started := time.Now()
	offboard := "/ocean/tenants/" + scope.TenantID + "/offboarding?api-version=2026-11-01"
	operatorCall("put", offboard, fmt.Sprintf("{\"subscriptionId\":%q}", scope.SubscriptionID), "")
	probe := newHostedPurgeProbe(tenant, address.ID(scope))
	approved := checkHostedPurgeView(t, operatorCall("put", probe.path, probe.body, ""), probe.id, record.Volume.ID, "Pending")
	if approved.Worker != binding.StandbyHostID {
		t.Fatal("the deletion approval did not bind the current certified member")
	}
	denyHostedSMBHost(t, ctx, r, binding.HostID, primaryCert)
	withdraw, err := r.HostSMBPlan(ctx, binding.StandbyHostID, standbyCert)
	if err != nil || !withdraw.Valid() || withdraw.Suspension == nil || withdraw.Suspension.PurgeVolume != "" ||
		withdraw.Generation != second.Generation || len(withdraw.StateKey) != 0 ||
		!slices.Contains(withdraw.Suspension.Volumes, member.StateVolumeID) || !slices.Contains(withdraw.Suspension.Volumes, record.Volume.ID) {
		t.Fatalf("the current writer did not receive a keyless plan for both volumes: %v", err)
	}
	priorReceipt.Suspended, priorReceipt.Directory = true, smb.DirectoryWriter{}
	if err := r.CompleteSMBPlan(ctx, binding.StandbyHostID, standbyCert, priorReceipt); !errors.Is(err, enrollment.ErrSMBPlanChanged) {
		t.Fatalf("a receipt from the fenced generation was accepted: %v", err)
	}
	if t.Failed() {
		t.FailNow()
	}
	operatorCall("post", fencePath, prepareFence(second, true), "StorageResourceInUse")
	worker.run(ctx, smbLabHost, "sudo systemctl kill --signal=STOP --kill-whom=main "+unit, nil)
	stopMember(second, smbLabStandby)
	denyHostedSMBHost(t, ctx, r, binding.HostID, primaryCert)
	registerNamedHostedLabWorker(t, ctx, r, binding.HostID, primaryCert)
	proof := prepareFence(second, true)
	operatorCall("post", fencePath, proof, "")
	operatorCall("post", fencePath, proof, "")
	third, _ := hostedSMBLabOwner(t, ctx, r, binding)
	if third.HostID != binding.HostID || third.Generation == second.Generation || third.Generation == first.Generation {
		t.Fatal("the suspended fence did not assign a fresh cleanup generation")
	}
	current := hostedSMBLabRecord(t, ctx, r, binding, shareName)
	if current.Operation != replacement.Operation || !current.Ready || current.Volume != record.Volume {
		t.Fatal("the cleanup fence changed the share or scheduled publication")
	}
	cleanup, err := r.HostSMBPlan(ctx, third.HostID, primaryCert)
	if err != nil || !cleanup.Valid() || cleanup.Generation != third.Generation || cleanup.Suspension == nil ||
		cleanup.Suspension.PurgeVolume != "" || len(cleanup.StateKey) != 0 || len(cleanup.Volumes) != 0 ||
		!slices.Contains(cleanup.Suspension.Volumes, member.StateVolumeID) || !slices.Contains(cleanup.Suspension.Volumes, record.Volume.ID) {
		t.Fatalf("the replacement did not receive a keyless withdrawal before deletion: %v", err)
	}
	if err := r.CompleteSMBPlan(ctx, third.HostID, primaryCert, withdraw.Receipt()); !errors.Is(err, enrollment.ErrSMBPlanChanged) {
		t.Fatalf("the replacement accepted the failed writer's withdrawal receipt: %v", err)
	}
	bootMember(ctx, smbLabStandby)
	registerNamedHostedLabWorker(t, ctx, r, binding.StandbyHostID, standbyCert)
	standby()
	denyHostedSMBHost(t, ctx, r, binding.StandbyHostID, standbyCert)
	if err := r.CompleteSMBPlan(ctx, binding.StandbyHostID, standbyCert, withdraw.Receipt()); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("the restarted writer could report its old receipt: %v", err)
	}
	for _, guest := range []string{smbLabHost, smbLabStandby} {
		assertSMBLabPlacement(t, ctx, worker, guest, vip, member.StateVolumeID, record.Volume.ID, false)
	}
	worker.run(ctx, smbLabHost, "sudo systemctl kill --signal=CONT --kill-whom=main "+unit, nil)
	pollVMWorker(t, ctx, 55*time.Second, "the cleanup owner to withdraw and purge the approved share", func() bool {
		found, err := r.HostedFilePurge(ctx, scope.TenantID, probe.id)
		return err == nil && found != nil && !found.CompletedAt.IsZero()
	})
	completed := checkHostedPurgeView(t, operatorCall("get", probe.path, "", ""), probe.id, record.Volume.ID, "Succeeded")
	if completed.Worker != approved.Worker || completed.ApprovalID != approved.ApprovalID {
		t.Fatal("the completion changed the independent deletion approval")
	}
	verifyHostedSMBCleanupAudit(t, ctx, r, scope, third.HostID, address)
	for _, guest := range []string{smbLabHost, smbLabStandby} {
		assertSMBLabPlacement(t, ctx, worker, guest, vip, member.StateVolumeID, record.Volume.ID, false)
	}
	worker.run(ctx, smbRecoveryCeph, "sudo rbd ls ocean --format json | python3 -c 'import json, sys; ids=json.load(sys.stdin); assert sys.argv[1] in ids and sys.argv[2] not in ids' "+
		member.StateVolumeID+" "+record.Volume.ID, nil)
	t.Logf("The first QEMU fence transferred the service to the standby and Kerberos recovered the original checkpoint. A second QEMU fence after suspension assigned only keyless cleanup. The failed writer's approval stayed intact, the audit recorded the actual cleanup worker, and the approved share alone was deleted in %d ms from suspension.", time.Since(started).Milliseconds())
}

func verifyHostedSMBCleanupAudit(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, host string, address arm.ResourceAddress) {
	t.Helper()
	rows, err := r.client.Get(ctx, r.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	var fenced, withdrawn, deleted int
	for _, row := range rows.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(row.Value, &event); err != nil {
			t.Fatal(err)
		}
		switch {
		case event.Action == "Ocean.Hosted/offboarding/fenceSMB" && event.Actor == "storage-fencing-authority" && event.Outcome == arm.OperationSucceeded:
			fenced++
		case event.Action == "Ocean.Hosted/offboarding/withdrawSMB" && event.Actor == host && event.Outcome == "Suspended":
			withdrawn++
		case event.Action == "Ocean.Hosted/offboarding/completeFilePurge" && event.Actor == host && event.Target == address.ID(scope) && event.Outcome == arm.OperationSucceeded:
			deleted++
		}
	}
	if fenced != 1 || withdrawn == 0 || deleted != 1 {
		t.Fatalf("want a cleanup fence, withdrawal and attributed deletion in the audit, got %d, %d, %d", fenced, withdrawn, deleted)
	}
}

func hostedSMBTestFencer(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fencer.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return private, path
}

func cloneHostedSMBState(t *testing.T, ctx context.Context, worker directoryKVMHosts, fixture string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture, "failover-state-id"))
	source := strings.TrimSpace(string(raw))
	if err != nil || !storage.ValidSMBStateVolumeID(source) {
		t.Fatalf("read the isolated Samba member state image ID: %v", err)
	}
	target := "smb-state-" + operationID()
	image := "ocean/" + target
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if out, err := worker.ssh(clean, smbRecoveryCeph, "if sudo rbd info "+image+" >/dev/null 2>&1; then sudo rbd rm "+image+"; fi", nil); err != nil {
			t.Errorf("remove the copied SMB member-state image: %v: %s", err, out)
		}
	})
	worker.run(ctx, smbRecoveryCeph, "sudo rbd cp ocean/"+source+" "+image, nil)
	return target
}

func seedHostedSMBDomain(t *testing.T, ctx context.Context, r *Region, binding smbBinding) {
	t.Helper()
	member := binding.Member
	now := time.Now().UTC()
	domain := identity.ManagedDirectory{TenantID: binding.TenantID, SubscriptionID: binding.SubscriptionID, ID: operationID(),
		RequestedAt: now, ProvisionedAt: now, DomainSID: member.DomainSID,
		Spec: identity.DirectorySpec{DNSName: member.DNSDomain, NetBIOSName: member.NetBIOSDomain}}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.managedDirectoryKey(binding.TenantID), domain),
		putJSON(r.managedDirectoryPlacementKey(binding.TenantID), directoryPlacement{DirectoryID: domain.ID,
			Controllers: [directoryControllerCount]Reservation{{PrivateIPv4: netip.MustParseAddr("10.232.1.11")}}})).Commit(); err != nil {
		t.Fatal(err)
	}
}

func restoreHostedSMBLabShare(t *testing.T, ctx context.Context, worker directoryKVMHosts, fixture, volume string) func(context.Context) {
	t.Helper()
	mount := filepath.Join(smb.MountRoot, volume)
	check := "sudo findmnt -rn --mountpoint " + mount + " >/dev/null"
	status, err := worker.ssh(ctx, smbLabHost, "if "+check+"; then printf 'mounted'; fi", nil)
	if err != nil {
		t.Fatalf("check the original SMB fixture mount: %v: %s", err, status)
	}
	if string(status) != "mounted" {
		return nil
	}
	return func(ctx context.Context) {
		key, err := os.ReadFile(filepath.Join(fixture, "rbd-volume.key"))
		defer clear(key)
		if err != nil || len(key) != storage.KeySize {
			t.Errorf("read the original SMB fixture mount key: %v", err)
			return
		}
		mapper := "ocean-" + volume
		script := "set -eu\nif " + check + "; then exit 0; fi\n" +
			"device=$(sudo rbd --conf /etc/ocean-smb/rbd/ceph.conf --id smb-lab --keyring /etc/ocean-smb/rbd/keyring device map --exclusive --options ms_mode=secure,lock_timeout=8 ocean/" + volume + ")\n" +
			"sudo cryptsetup open --type luks2 --key-file - \"$device\" " + mapper + "\n" +
			"sudo install -d -m 0755 " + mount + "\nsudo mount -t ext4 -o prjquota /dev/mapper/" + mapper + " " + mount
		if out, err := worker.ssh(ctx, smbLabHost, script, bytes.NewReader(key)); err != nil {
			t.Errorf("restore the original SMB fixture mount: %v: %s", err, out)
		}
	}
}

func stageHostedSMBHAMember(t *testing.T, ctx context.Context, worker directoryKVMHosts, host, localConfig string, restoreShare func(context.Context)) func() {
	t.Helper()
	remote, unit := "/var/tmp/"+worker.directory, worker.directory+".service"
	run := func(command string, input io.Reader) {
		t.Helper()
		worker.run(ctx, host, "cd /tmp\n"+command, input)
	}
	run("set -eu\nsudo test ! -e /run/ocean-smb/placement.json\nsudo install -d -m 0755 "+remote+
		"\nsudo install -d -o ocean-agent -g ocean-agent -m 0700 "+remote+"/identity\nsudo install -d -m 0700 "+remote+"/backup\n"+
		"sudo cp -a /etc/samba/smb.conf "+remote+"/backup/smb.conf\n"+
		"for name in smbd winbind; do if sudo systemctl is-active --quiet \"$name.service\"; then sudo touch "+remote+"/backup/\"$name\"; fi; done", nil)
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		if t.Failed() {
			out, _ := worker.ssh(clean, host, "sudo journalctl -u "+unit+" --no-pager -n 12", nil)
			t.Logf("native hosted SMB member %s journal:\n%s", host, out)
		}
		script := "set -eu\nif test \"$(sudo systemctl show -P LoadState " + unit + ")\" = loaded; then " +
			"sudo systemctl kill --signal=CONT --kill-whom=main " + unit + " || true; sudo systemctl stop " + unit + "; fi\n" +
			"sudo systemctl stop smbd.service winbind.service\nsudo cp -a " + remote + "/backup/smb.conf /etc/samba/smb.conf"
		if out, err := worker.ssh(clean, host, script, nil); err != nil {
			t.Errorf("restore the original SMB guest configuration on %s: %v: %s", host, err, out)
			return
		}
		if restoreShare != nil {
			restoreShare(clean)
		}
		script = "set -eu\nfor name in winbind smbd; do if sudo test -f " + remote + "/backup/\"$name\"; then sudo systemctl start \"$name.service\"; fi; done\n" +
			"sudo rm -rf -- " + remote
		if out, err := worker.ssh(clean, host, script, nil); err != nil {
			t.Errorf("restore the original SMB guest %s: %v: %s", host, err, out)
		}
	})
	stageHostedWorkerExecutable(t, ctx, worker.root, remote, run)
	stageHostedVolumeIdentity(t, localConfig, remote, run)
	const conf, keyring = "/etc/ocean-smb/rbd/ceph.conf", "/etc/ocean-smb/rbd/keyring"
	raw, err := json.Marshal(storage.Config{Pool: "ocean", Client: "smb-lab", CephConfig: conf, Keyring: keyring, MountRoot: smb.MountRoot})
	if err != nil {
		t.Fatal(err)
	}
	run("sudo install -m 0600 /dev/stdin "+remote+"/storage.json", bytes.NewReader(raw))
	return func() {
		t.Helper()
		run("sudo systemd-run --quiet --unit="+unit+" --property=Nice=10 --property=KillMode=mixed --setenv=OCEAN_E2E_HOSTED_WORKER_CONFIG="+remote+
			" --setenv=OCEAN_E2E_HOSTED_WORKER_MODE=smb "+remote+"/worker -test.run=^TestHostedWorkerProcess$ -test.timeout=7m", nil)
	}
}

func hostedSMBLabOwner(t *testing.T, ctx context.Context, r *Region, binding smbBinding) (smbOwner, int64) {
	t.Helper()
	current, err := r.client.Get(ctx, r.smbOwnerKey(binding))
	if err != nil {
		t.Fatal(err)
	}
	owner, revision, err := readSMBOwner(binding, current.Kvs)
	if err != nil {
		t.Fatal(err)
	}
	return owner, revision
}

func waitHostedSMBRecovery(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, operation string) {
	t.Helper()
	pollVMWorker(t, ctx, 65*time.Second, "the native SMB operation to complete", func() bool {
		status, err := r.GetOperation(ctx, scope, operation)
		return err == nil && status != nil && status.Status == arm.OperationSucceeded
	})
}

func denyHostedSMBHost(t *testing.T, ctx context.Context, r *Region, host string, certificate []byte) {
	t.Helper()
	plan, err := r.HostSMBPlan(ctx, host, certificate)
	defer plan.ClearKeys()
	if !errors.Is(err, enrollment.ErrHostDenied) || plan.Suspension != nil || len(plan.StateKey) != 0 || len(plan.Volumes) != 0 {
		t.Fatalf("inactive SMB host %s received an assignment: %v", host, err)
	}
}

func shortenHostedTestLease(t *testing.T, ctx context.Context, r *Region, host string) {
	t.Helper()
	key := r.hostKey("live", host)
	current, err := r.client.Get(ctx, key)
	if err != nil || len(current.Kvs) != 1 {
		t.Fatalf("read the original SMB host lease: %v", err)
	}
	lease, err := r.client.Grant(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Put(ctx, key, string(current.Kvs[0].Value), clientv3.WithLease(lease.ID)); err != nil {
		t.Fatal(err)
	}
}
