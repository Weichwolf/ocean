//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/nodeagent"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestHostedSMBOffboarding(t *testing.T) {
	state, fixtures := os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE"), os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE")
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if state == "" || fixtures == "" || archive == "" || cli == "" {
		t.Skip("requires the isolated domain and Ceph lab, private SMB fixture and pinned etcd and Azure CLI")
	}
	raw, err := os.ReadFile(filepath.Join(fixtures, "member-rbd.json"))
	var member smb.Member
	if err != nil || json.Unmarshal(raw, &member) != nil || member.Validate() != nil || len(member.Shares) != 1 || member.StateVolumeID != "" {
		t.Fatalf("read the standalone enrolled member fixture: %v", err)
	}
	policy := smb.Policy{QuotaGiB: 1, ReaderSIDs: member.Shares[0].ReaderSIDs, WriterSIDs: member.Shares[0].WriterSIDs}
	member.Shares = nil
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := "hosted-smb-" + operationID()[:12]
	worker := directoryKVMHosts{root: root, state: state, directory: fixture, t: t}
	remote := "/var/tmp/" + fixture
	run := func(command string, input io.Reader) {
		t.Helper()
		worker.run(ctx, smbLabHost, "cd /tmp\n"+command, input)
	}
	run("set -eu\nsudo test ! -e /run/ocean-smb/placement.json\n"+
		"sudo systemctl is-active --quiet smbd.service winbind.service\n"+
		"sudo net ads testjoin -S dc01.ad.ocean.test\n"+
		"sudo install -d -m 0755 "+remote+"\nsudo install -d -o ocean-agent -g ocean-agent -m 0700 "+remote+"/identity\n"+
		"sudo install -d -m 0700 "+remote+"/backup\nsudo cp -a /etc/samba/smb.conf "+remote+"/backup/smb.conf", nil)
	unit := fixture + ".service"
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if t.Failed() {
			journal, _ := worker.ssh(clean, smbLabHost, "sudo journalctl -u "+unit+" --no-pager -n 12", nil)
			t.Logf("fixture SMB agent:\n%s", journal)
		}
		script := "set -eu\nif test \"$(sudo systemctl show -P LoadState " + unit + ")\" = loaded; then " +
			"sudo systemctl kill --signal=CONT --kill-whom=main " + unit + " || true; sudo systemctl stop " + unit + "; fi\n" +
			"sudo cp -a " + remote + "/backup/smb.conf /etc/samba/smb.conf\nsudo systemctl restart winbind.service smbd.service\n" +
			"sudo rm -rf -- " + remote
		if out, err := worker.ssh(clean, smbLabHost, script, nil); err != nil {
			t.Errorf("restore the standalone SMB lab fixture: %v: %s", err, out)
		}
	})
	stageHostedWorkerExecutable(t, ctx, root, remote, run)
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	binding := smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: hostedSuspensionHost, Member: member}
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-smb")
	cfg.ManagedDirectories = &enrollment.Capacity{CPUMillis: 500, MemoryMiB: 256}
	cfg.SMBMembers = []smbBinding{binding}
	r := openHostedLabRegion(t, ctx, cfg)
	seedHostedLabTenant(t, ctx, r, tenant)
	domain := identity.ManagedDirectory{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, ID: operationID(),
		RequestedAt: time.Now().UTC(), ProvisionedAt: time.Now().UTC(), DomainSID: member.DomainSID,
		Spec: identity.DirectorySpec{DNSName: member.DNSDomain, NetBIOSName: member.NetBIOSDomain}}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.managedDirectoryKey(scope.TenantID), domain),
		putJSON(r.managedDirectoryPlacementKey(scope.TenantID), directoryPlacement{DirectoryID: domain.ID,
			Controllers: [directoryControllerCount]Reservation{{PrivateIPv4: netip.MustParseAddr("10.232.1.11")}}})).Commit(); err != nil {
		t.Fatal(err)
	}
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.TenantID)
	workers := hostedLabInventory(cfg)
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate(), workers...)
	localConfig, hostCert := identityFor(hostedSuspensionHost)
	stageHostedVolumeIdentity(t, localConfig, remote, run)
	host := registerHostedOffboardingWorker(t, ctx, r, hostCert)
	const conf = "/etc/ocean-smb/rbd/ceph.conf"
	const keyring = "/etc/ocean-smb/rbd/keyring"
	storageConfig, err := json.Marshal(storage.Config{Pool: "ocean", Client: "smb-lab", CephConfig: conf, Keyring: keyring, MountRoot: smb.MountRoot})
	if err != nil {
		t.Fatal(err)
	}
	run("sudo install -m 0600 /dev/stdin "+remote+"/storage.json", bytes.NewReader(storageConfig))
	rbdCommand := "rbd --conf " + conf + " --id smb-lab --keyring " + keyring
	rbd := "sudo " + rbdCommand
	run("sudo systemd-run --quiet --unit="+unit+" --property=Nice=10 --property=KillMode=mixed --setenv=OCEAN_E2E_HOSTED_WORKER_CONFIG="+remote+
		" --setenv=OCEAN_E2E_HOSTED_WORKER_MODE=smb "+remote+"/worker -test.run=^TestHostedWorkerProcess$ -test.timeout=5m", nil)
	// These are the only test images eligible for fixture cleanup.
	var fixtureImages []string
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		stop := "if test \"$(sudo systemctl show -P LoadState " + unit + ")\" = loaded; then " +
			"sudo systemctl kill --signal=CONT --kill-whom=main " + unit + " || true; sudo systemctl stop " + unit + "; fi"
		if out, err := worker.ssh(clean, smbLabHost, stop, nil); err != nil {
			t.Errorf("stop the disposable SMB agent: %v: %s", err, out)
			return
		}
		for _, volume := range fixtureImages {
			mount, target := smb.MountRoot+"/"+volume, "ocean/"+volume
			script := "set -eu\nif sudo findmnt -rn --mountpoint " + mount + "; then sudo umount " + mount + "; fi\n" +
				"if sudo test -e /dev/mapper/ocean-" + volume + "; then sudo cryptsetup close ocean-" + volume + "; fi\n" +
				"dev=$(" + rbd + " device list --format json | python3 -c 'import json, sys; print(next((x[\"device\"] for x in json.load(sys.stdin) if x[\"name\"] == sys.argv[1] and x[\"pool\"] == \"ocean\"), \"\"))' " + volume + ")\n" +
				"if test -n \"$dev\"; then " + rbd + " device unmap \"$dev\"; fi\n" +
				"if " + rbd + " info " + target + " >/dev/null 2>&1; then " + rbd + " rm " + target + "; fi"
			if out, err := worker.ssh(clean, smbLabHost, script, nil); err != nil {
				t.Errorf("clean one SMB test image: %v: %s", err, out)
			}
		}
	})
	add := func(name string) smbShareRecord {
		t.Helper()
		address := arm.ResourceAddress{Group: "retained-fixture", Path: smb.ResourceType + "/" + name}
		body, err := json.Marshal(map[string]any{"location": r.name, "properties": policy})
		if err != nil {
			t.Fatal(err)
		}
		az("put", address.ID(scope)+"?api-version="+smb.APIVersion, string(body), sign(scope.TenantID, operatorClient, tenant.Administrator, origin), "")
		record := hostedSMBLabRecord(t, ctx, r, binding, name)
		fixtureImages = append(fixtureImages, record.Volume.ID)
		pollVMWorker(t, ctx, 40*time.Second, "the real SMB worker to publish the share", func() bool {
			status, err := r.GetOperation(ctx, scope, record.Operation)
			return err == nil && status != nil && status.Status == arm.OperationSucceeded
		})
		return record
	}
	deleted, preserved := add("purged-files"), add("retained-files")
	for _, record := range []smbShareRecord{deleted, preserved} {
		probe := exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "lab/verify_smb_member.py"),
			"--state", state, "--fixture", fixtures, "--share", record.Name, "--checkpoint", "write")
		if out, err := probe.CombinedOutput(); err != nil {
			t.Fatalf("write the SMB checkpoint over Kerberos: %v: %s", err, out)
		}
	}
	retainedKey, err := r.smbShareEncryptionKey(binding, preserved)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retainedKey)
	snapshot := takeHostedSMBLabSnapshot(t, ctx, r)
	run("sudo systemctl kill --signal=STOP --kill-whom=main "+unit, nil)
	started := time.Now()
	operatorToken := sign(operatorRealm, operatorClient, operator, origin)
	request := newHostedPurgeProbe(tenant, deleted.Address.ID(scope))
	az("put", request.path, request.body, operatorToken, "FileShareDeletionUnavailable")
	offboard := "/ocean/tenants/" + tenant.TenantID + "/offboarding?api-version=2026-11-01"
	az("put", offboard, fmt.Sprintf("{\"subscriptionId\":%q}", tenant.SubscriptionID), operatorToken, "")
	checkHostedPurgeView(t, az("put", request.path, request.body, operatorToken, ""), request.id, deleted.Volume.ID, "Pending")
	verifyHostedSMBReceiptGate(t, ctx, r, host, localConfig, deleted, preserved)
	run("sudo findmnt -rn --mountpoint "+smb.MountRoot+"/"+deleted.Volume.ID+"\nsudo systemctl kill --signal=CONT --kill-whom=main "+unit, nil)
	pollVMWorker(t, ctx, 30*time.Second, "the SMB worker to detach both volumes and delete the approved image", func() bool {
		decision, err := r.HostedFilePurge(ctx, tenant.TenantID, request.id)
		return err == nil && decision != nil && !decision.CompletedAt.IsZero()
	})
	finished := checkHostedPurgeView(t, az("get", request.path, "", operatorToken, ""), request.id, deleted.Volume.ID, "Succeeded")
	run("set -eu\ntest -z \"$(sudo ss -H -ltn '( sport = :445 )')\"\n"+
		"for id in "+deleted.Volume.ID+" "+preserved.Volume.ID+"; do\n"+
		"if sudo findmnt -rn --mountpoint "+smb.MountRoot+"/\"$id\"; then exit 1; fi\n"+
		"sudo test ! -e /dev/mapper/ocean-\"$id\"\ndone\n"+
		rbd+" ls ocean --format json | python3 -c 'import json, sys; names=json.load(sys.stdin); assert sys.argv[1] not in names and sys.argv[2] in names' "+deleted.Volume.ID+" "+preserved.Volume.ID, nil)
	verifyHostedSMBDeletion(t, ctx, r, binding, host.HostID, deleted, preserved)
	t.Logf("A native Kerberos client wrote both encrypted SMB shares. Suspension withdrew both mounts and the TCP listener. The certified member deleted only the authorized RBD image and its regional sealed key in %d ms.", time.Since(started).Milliseconds())
	run("sudo systemctl stop "+unit, nil)
	verifyHostedReadOnlyCheckpoint(t, remote, rbdCommand, preserved.Volume.ID, "ocean-"+preserved.Volume.ID,
		"data/ocean-managed-checkpoint.bin", "ocean Kerberos SMB payload", retainedKey, run)

	restoredCfg := restoreHostedSMBLabSnapshot(t, ctx, cfg, archive, snapshot)
	restored, err := openRegion(restoredCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.close() })
	key := restored.filePurgeKey(tenant.TenantID, request.id)
	before, err := restored.client.Get(ctx, key, clientv3.WithCountOnly())
	if err != nil || before.Count != 0 {
		t.Fatalf("the native SMB test requires a snapshot predating the independent deletion: %v", err)
	}
	restoredOrigin, _, restoredAz, restoredIdentity := startHostedRestoreAPI(t, ctx, restoredCfg, cli,
		operatorRealm, operatorClient, issuer.URL, issuer.Certificate(), workers...)
	after, err := restored.client.Get(ctx, key, clientv3.WithCountOnly())
	if err != nil || after.Count != 1 {
		t.Fatalf("the restored SMB region admitted requests before replaying the file deletion: %v", err)
	}
	restoredOperator := sign(operatorRealm, operatorClient, operator, restoredOrigin)
	pending := checkHostedPurgeView(t, restoredAz("get", request.path, "", restoredOperator, ""), request.id, deleted.Volume.ID, "Pending")
	if !sameFilePurge(pending, finished) {
		t.Fatal("restore changed the authoritative SMB file decision")
	}
	restoredConfig, restoredCert := restoredIdentity(hostedSuspensionHost)
	restoredHost := registerHostedOffboardingWorker(t, ctx, restored, restoredCert)
	verifyHostedSMBReceiptGate(t, ctx, restored, restoredHost, restoredConfig, deleted, preserved)
	restoredAz("get", deleted.Address.ID(scope)+"?api-version="+smb.APIVersion, "",
		sign(scope.TenantID, operatorClient, tenant.Administrator, restoredOrigin), "InvalidAuthenticationToken")
	t.Log("The pending SMB deletion survived restoration of older metadata. New worker certificates received a keyless suspension and could not complete a purge before the restored writer receipt.")
}

func takeHostedSMBLabSnapshot(t *testing.T, ctx context.Context, r *Region) string {
	t.Helper()
	snapshot, err := r.client.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snapshot.Close() }()
	path := filepath.Join(t.TempDir(), "smb.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(file, snapshot)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	return path
}

func restoreHostedSMBLabSnapshot(t *testing.T, ctx context.Context, cfg regionConfig, archive, snapshot string) regionConfig {
	t.Helper()
	dir := t.TempDir()
	base, cert, key, binary, _ := prepareSMBRecoveryEtcd(t, ctx, archive, dir)
	data := filepath.Join(dir, "restored")
	cfg.Etcd, _, _ = startSMBRecoveryEtcd(t, ctx, base, cert, key, binary, data, func(peer, cluster, token string) {
		etcdLabCommand(t, ctx, nil, filepath.Join(dir, "etcdutl"), "snapshot", "restore", snapshot, "--name=smb-recovery",
			"--initial-cluster="+cluster, "--initial-advertise-peer-urls="+peer, "--initial-cluster-token="+token, "--data-dir="+data)
	})
	return cfg
}

func hostedSMBLabRecord(t *testing.T, ctx context.Context, r *Region, binding smbBinding, name string) smbShareRecord {
	t.Helper()
	rows, err := r.client.Get(ctx, r.smbMemberKey(binding))
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := smbRecords(binding, rows.Kvs)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Name == name {
			return record
		}
	}
	t.Fatalf("missing expected SMB fixture share %s", name)
	return smbShareRecord{}
}

func verifyHostedSMBReceiptGate(t *testing.T, ctx context.Context, r *Region, host enrollment.Host, local string, deleted, preserved smbShareRecord) {
	t.Helper()
	plan, err := r.HostSMBPlan(ctx, host.HostID, host.Certificate)
	if err != nil || !plan.Valid() || plan.Suspension == nil || len(plan.Suspension.Volumes) != 2 || plan.Suspension.PurgeVolume != "" ||
		len(plan.StateKey) != 0 || len(plan.Volumes) != 0 {
		t.Fatalf("a suspended member without a fresh receipt must get a keyless withdrawal plan: %v", err)
	}
	for _, volume := range []string{deleted.Volume.ID, preserved.Volume.ID} {
		if !slices.Contains(plan.Suspension.Volumes, volume) {
			t.Fatal("withdrawal omitted an assigned SMB volume")
		}
	}
	receipt := plan.Receipt()
	stale := receipt
	stale.Generation = operationID()
	if err := r.CompleteSMBPlan(ctx, host.HostID, host.Certificate, stale); !errors.Is(err, enrollment.ErrSMBPlanChanged) {
		t.Fatalf("the regional API accepted a stale SMB writer receipt: %v", err)
	}
	receipt.PurgeVolume = deleted.Volume.ID
	if err := r.CompleteSMBPlan(ctx, host.HostID, host.Certificate, receipt); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("expected the unconfirmed SMB purge receipt to be refused: %v", err)
	}
	jobs, err := r.HostShareJobs(ctx, host.HostID, host.Certificate)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("the ordinary RBD worker received an SMB deletion job: %v", err)
	}
	origin, client, err := nodeagent.OpenHostAccess(local)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/ocean/hosts/"+host.HostID+"/smb-plan", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("a worker without suspension support did not receive its legacy revocation response")
	}
}

func verifyHostedSMBDeletion(t *testing.T, ctx context.Context, r *Region, binding smbBinding, host string, deleted, preserved smbShareRecord) {
	t.Helper()
	scope := binding.scope()
	read, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.smbMemberKey(binding)),
		clientv3.OpGet(r.inventoryPrefix(scope)+deleted.Address.Key(), clientv3.WithCountOnly()),
		clientv3.OpGet(r.smbGroupPrefix(scope, deleted.Address.Group)+deleted.Name, clientv3.WithCountOnly())).Commit()
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := smbRecords(binding, read.Responses[0].GetResponseRange().Kvs)
	if err != nil || len(records) != 1 || records[0].Volume != preserved.Volume || !bytes.Equal(records[0].Envelope, preserved.Envelope) ||
		read.Responses[1].GetResponseRange().Count != 0 || read.Responses[2].GetResponseRange().Count != 0 {
		t.Fatal("SMB purge did not erase exactly the approved key envelope and regional projections")
	}
	events, err := r.ListActivity(ctx, scope, "", arm.ActivityFilter{Start: time.Now().Add(-3 * time.Minute), End: time.Now(), Caller: host}, 64)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn, completed := false, false
	for _, event := range events {
		withdrawn = withdrawn || event.Action == "Ocean.Hosted/offboarding/withdrawSMB"
		completed = completed || event.Action == "Ocean.Hosted/offboarding/completeFilePurge" && event.Target == deleted.Address.ID(scope)
	}
	if !withdrawn || !completed {
		t.Fatal("SMB withdrawal and approved purge must leave distinct audit events")
	}
}
