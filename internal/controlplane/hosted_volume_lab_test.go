//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedVolumeGuest = "farm-1-node-08"
const hostedVolumeMountRoot = "/run/ocean-storage/mounts/"

func TestHostedMountedVolumeOffboarding(t *testing.T) {
	state := os.Getenv("OCEAN_E2E_HOSTED_CEPH_STATE")
	archive := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	cli := os.Getenv("OCEAN_E2E_HOSTED_AZ")
	image := os.Getenv("OCEAN_E2E_HOSTED_PODMAN_IMAGE")
	if state == "" || archive == "" || cli == "" || image == "" {
		t.Skip("requires the running Ceph KVM lab, pinned etcd and Azure CLI, and a local Debian image")
	}
	digest := strings.TrimPrefix(image, "sha256:")
	if decoded, err := hex.DecodeString(digest); err != nil || len(decoded) != 32 {
		t.Fatal("the native mounted-volume fixture requires a pinned local image ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fixture := "hosted-volume-" + operationID()[:12]
	worker := directoryKVMHosts{root: root, state: state, directory: fixture, t: t}
	remote := "/var/tmp/" + fixture
	agentRun := "sudo -u ocean-agent -- env XDG_RUNTIME_DIR=/run/user/$(id -u ocean-agent) nice -n 10 "
	run := func(command string, input io.Reader) {
		t.Helper()
		worker.run(ctx, hostedVolumeGuest, "cd /tmp\n"+command, input)
	}
	run("sudo install -d -m 0755 "+remote+"\nsudo install -d -o ocean-agent -g ocean-agent -m 0700 "+remote+"/identity", nil)
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if out, err := worker.ssh(clean, hostedVolumeGuest, "sudo rm -rf -- "+remote, nil); err != nil {
			t.Errorf("clean the disposable worker files: %v: %s", err, out)
		}
	})
	stageHostedVolumeWorker(t, ctx, root, image, remote, agentRun, run)

	r, cfg := openHostedOffboardingLab(t, ctx, archive, "hosted-volume")
	tenant := seedHostedRestoreTenant(t, ctx, r)
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.TenantID)
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate())
	localConfig, hostCert := identityFor(hostedSuspensionHost)
	stageHostedVolumeIdentity(t, localConfig, remote, run)
	host := registerHostedOffboardingWorker(t, ctx, r, hostCert)

	cephConf := "/etc/ocean-smb/rbd/ceph.conf"
	credential, err := worker.ssh(ctx, smbRecoveryCeph, "sudo ceph auth get-or-create client."+fixture+
		" mon 'profile rbd' osd 'profile rbd pool=ocean' mgr 'profile rbd pool=ocean'", nil)
	if err != nil {
		t.Fatalf("prepare the restricted Ceph fixture identity: %v", err)
	}
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 25*time.Second)
		defer done()
		if _, err := worker.ssh(clean, smbRecoveryCeph, "sudo ceph auth rm client."+fixture, nil); err != nil {
			t.Errorf("remove the disposable Ceph identity: %v", err)
		}
	})
	run("sudo install -m 0600 /dev/stdin "+remote+"/keyring", bytes.NewReader(credential))
	clear(credential)
	configuration, err := json.Marshal(storage.Config{Pool: "ocean", Client: fixture, CephConfig: cephConf,
		Keyring: remote + "/keyring", MountRoot: strings.TrimSuffix(hostedVolumeMountRoot, "/")})
	if err != nil {
		t.Fatal(err)
	}
	run("sudo install -m 0600 /dev/stdin "+remote+"/storage.json", bytes.NewReader(configuration))
	rbd := "/usr/bin/rbd --conf " + cephConf + " --id " + fixture + " --keyring " + remote + "/keyring"
	start := func(mode, userArgs string) {
		t.Helper()
		unit := fixture + "-" + mode
		run("sudo systemd-run --quiet --unit="+unit+" --property=Nice=10 "+userArgs+
			" --setenv=OCEAN_E2E_HOSTED_WORKER_CONFIG="+remote+" --setenv=OCEAN_E2E_HOSTED_WORKER_MODE="+mode+
			" "+remote+"/worker -test.run=^TestHostedWorkerProcess$ -test.timeout=5m", nil)
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			if t.Failed() {
				journal, _ := worker.ssh(clean, hostedVolumeGuest, "sudo journalctl --no-pager -u "+unit+" -n 10", nil)
				t.Logf("fixture %s worker journal:\n%s", mode, journal)
			}
			command := "if test \"$(sudo systemctl show -P LoadState " + unit + ")\" = loaded; then sudo systemctl stop " + unit + "; fi"
			if out, err := worker.ssh(clean, hostedVolumeGuest, command, nil); err != nil {
				t.Errorf("stop the disposable worker: %v: %s", err, out)
			}
		})
	}
	start("storage", "")
	share := stageHostedFileShare(t, ctx, r, scope, tenant.Administrator)
	volume := share.Volume.ID
	mapper := "ocean-" + volume
	mount := hostedVolumeMountRoot + volume
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 25*time.Second)
		defer done()
		// Successful cases have already detached this exact disposable image.
		script := "set -eu\nif test \"$(sudo systemctl show -P LoadState " + fixture + "-storage)\" = loaded; then sudo systemctl stop " + fixture + "-storage; fi\n" +
			"if sudo findmnt -rn --mountpoint " + mount + " >/dev/null; then sudo umount " + mount + "; fi\n" +
			"if sudo test -e /dev/mapper/" + mapper + "; then sudo cryptsetup close " + mapper + "; fi\n" +
			"device=$(sudo " + rbd + " device list --format json | python3 -c 'import json, sys; print(next((x[\"device\"] for x in json.load(sys.stdin) if x[\"pool\"] == \"ocean\" and x[\"name\"] == sys.argv[1]), \"\"))' " + volume + ")\n" +
			"if test -n \"$device\"; then sudo " + rbd + " device unmap \"$device\"; fi\n" +
			"if sudo " + rbd + " info ocean/" + volume + " >/dev/null 2>&1; then sudo " + rbd + " rm ocean/" + volume + "; fi"
		if out, err := worker.ssh(clean, hostedVolumeGuest, script, nil); err != nil {
			t.Errorf("clean the disposable RBD volume: %v: %s", err, out)
		}
	})
	pollVMWorker(t, ctx, 55*time.Second, "the production storage worker to initialize the encrypted share", func() bool {
		status, err := r.GetOperation(ctx, scope, share.Operation)
		return err == nil && status != nil && status.Status == arm.OperationSucceeded
	})
	record := seedHostedContainer(t, ctx, r, scope, tenant.Administrator, workload.ContainerGroupType, 0)
	record.Volume = &volumeBinding{ID: volume, Share: share.Address}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.containerKey(scope, record.Address), record),
		putJSON(r.writerKey(scope, volume), writerFor(record))).Commit(); err != nil {
		t.Fatal(err)
	}
	pollVMWorker(t, ctx, 40*time.Second, "the encrypted RBD mount", func() bool {
		_, err := worker.ssh(ctx, hostedVolumeGuest, "sudo findmnt -rn --mountpoint "+mount+" && sudo test -e /dev/mapper/"+mapper, nil)
		return err == nil
	})
	name := hostedContainerName(scope, record)
	workloadCommand := agentRun + "podman "
	for _, container := range []string{name, name + "-storage"} {
		run(workloadCommand+"run --pull=never --network=none --detach --name "+container+" --volume "+mount+":/data "+
			"-- "+image+" /bin/sh -ec 'trap \"exit 0\" TERM; while :; do sleep 1; done'", nil)
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if out, err := worker.ssh(clean, hostedVolumeGuest, "cd /tmp; "+workloadCommand+"rm --force --ignore --time 1 "+container, nil); err != nil {
				t.Errorf("clean the disposable workload: %v: %s", err, out)
			}
		})
	}
	run(workloadCommand+"exec "+name+" /bin/sh -ec 'echo hosted-encrypted-checkpoint > /data/checkpoint; sync /data/checkpoint'", nil)
	key, err := r.shareEncryptionKey(share)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	start("containers", "--uid=ocean-agent --gid=ocean-agent --property=WorkingDirectory=/tmp --setenv=XDG_RUNTIME_DIR=/run/user/$(id -u ocean-agent)")
	started := time.Now().UTC()
	path := "/ocean/tenants/" + tenant.TenantID + "/offboarding?api-version=2026-11-01"
	az("put", path, fmt.Sprintf(`{"subscriptionId":%q}`, tenant.SubscriptionID), sign(operatorRealm, operatorClient, operator, origin), "")
	receipt := r.suspendedVolumeReceiptKey(scope, volume, record.Reservation.Generation, record.Operation)
	stopped := r.armPrefix(scope) + "hosted-suspensions/containers/" + record.Reservation.ID + "/" + record.Reservation.Generation
	pollVMWorker(t, ctx, 35*time.Second, "a completed RBD unmount and container audit", func() bool {
		mountState, err := r.client.Get(ctx, receipt)
		if err != nil || len(mountState.Kvs) != 1 || string(mountState.Kvs[0].Value) != host.HostID {
			return false
		}
		state, err := r.client.Get(ctx, stopped)
		return err == nil && len(state.Kvs) == 1 && mountState.Kvs[0].ModRevision < state.Kvs[0].ModRevision
	})
	detachedIn := time.Since(started).Milliseconds()
	run("set -eu\nfor name in "+name+" "+name+"-storage; do\n"+
		"test \"$("+workloadCommand+"inspect --format '{{.State.Running}}' \"$name\")\" = false\ndone\n"+
		"if sudo findmnt -rn --mountpoint "+mount+"; then exit 1; fi\n"+
		"sudo test ! -e /dev/mapper/"+mapper+"\n"+
		"sudo test ! -e /run/ocean-storage/writers/"+volume+"\n"+
		"sudo "+rbd+" device list --format json | python3 -c 'import json, sys; assert all(x[\"name\"] != sys.argv[1] for x in json.load(sys.stdin))' "+volume, nil)
	az("get", share.Address.ID(scope)+"?api-version="+storage.ShareAPIVersion, "", sign(tenant.TenantID, operatorClient, tenant.Administrator, origin), "InvalidAuthenticationToken")
	// Stop the mutation worker before the detached fixture is opened for an
	// independent read-only check with the lab key held before offboarding.
	run("sudo systemctl stop "+fixture+"-storage", nil)
	verifyHostedVolumeCheckpoint(t, remote, rbd, volume, mapper, key, run)
	verifyHostedVolumeReceipts(t, ctx, r, scope, record, share, host.HostID, started)
	t.Logf("The RBD worker withdrew the writable LUKS2 volume in %d ms, with its authenticated unmount receipt recorded before the container receipt. Both Podman containers stopped and a read-only audit recovered the original bytes from the detached image.", detachedIn)
}

func verifyHostedVolumeReceipts(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope,
	record containerRecord, share storageShareRecord, host string, started time.Time) {
	t.Helper()
	audit, err := r.ListActivity(ctx, scope, "", arm.ActivityFilter{Start: started, End: time.Now().UTC(), Caller: host}, 20)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Ocean.Hosted/offboarding/unmountVolume": share.Address.ID(scope),
		"Ocean.Hosted/offboarding/stopContainer": record.Address.ID(scope)}
	for _, event := range audit {
		if event.Target != want[event.Action] || event.Outcome != workload.Suspended {
			t.Fatalf("unexpected audited worker receipt action %s", event.Action)
		}
		delete(want, event.Action)
	}
	if len(want) != 0 {
		t.Fatal("the two worker receipts did not produce separate scoped audit events")
	}
	volume := share.Volume.ID
	result, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.writerKey(scope, volume), clientv3.WithCountOnly()),
		clientv3.OpGet(r.unmountReceiptKey(scope, volume, record.Reservation.Generation, record.Operation), clientv3.WithCountOnly())).Commit()
	if err != nil || result.Responses[0].GetResponseRange().Count != 1 || result.Responses[1].GetResponseRange().Count != 0 {
		t.Fatalf("withdrawal changed the writer grant or created a deletion receipt: %v", err)
	}
}

func stageHostedVolumeWorker(t *testing.T, ctx context.Context, root, image, remote, agentRun string, run func(string, io.Reader)) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "worker")
	build := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-tags=e2e", "-c", "-o", bin, "./internal/nodeagent")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("link the disposable lab worker: %v: %s", err, out)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	run("sudo install -m 0755 /dev/stdin "+remote+"/worker", bytes.NewReader(data))
	save := exec.CommandContext(ctx, "nice", "-n", "10", "/usr/bin/podman", "save", "--format", "oci-archive", "--", image)
	archive, err := save.Output()
	if err != nil {
		t.Fatalf("package the pinned local Debian image: %v", err)
	}
	run(agentRun+"podman load", bytes.NewReader(archive))
}

func stageHostedVolumeIdentity(t *testing.T, local, remote string, run func(string, io.Reader)) {
	t.Helper()
	data, err := os.ReadFile(local)
	var config struct {
		Enrollment map[string]string `json:"enrollment"`
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.key", "identity.crt"} {
		data, err := os.ReadFile(filepath.Join(config.Enrollment["stateDirectory"], name))
		if err != nil {
			t.Fatal(err)
		}
		run("sudo install -o ocean-agent -g ocean-agent -m 0600 /dev/stdin "+remote+"/identity/"+name, bytes.NewReader(data))
		clear(data)
	}
	ca, err := os.ReadFile(config.Enrollment["caFile"])
	if err != nil {
		t.Fatal(err)
	}
	config.Enrollment["origin"] = strings.Replace(config.Enrollment["origin"], "127.0.0.1", "10.0.2.2", 1)
	config.Enrollment["stateDirectory"] = remote + "/identity"
	config.Enrollment["tokenFile"] = remote + "/unused"
	config.Enrollment["caFile"] = remote + "/ca.pem"
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	run("sudo install -m 0644 /dev/stdin "+remote+"/ca.pem", bytes.NewReader(ca))
	run("sudo install -m 0644 /dev/stdin "+remote+"/config.json", bytes.NewReader(data))
}

func stageHostedFileShare(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, actor string) storageShareRecord {
	t.Helper()
	account := arm.ResourceAddress{Group: "retained-fixture", Path: storage.AccountType + "/suspension"}
	address := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/fixture"}
	if _, _, err := r.PutStorageAccount(ctx, scope, actor, account,
		storage.AccountRequest{Location: r.name, Kind: "StorageV2", SKU: storage.AccountSKU{Name: "Standard_LRS"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.PutFileShare(ctx, scope, actor, account, address, storage.ShareProperties{QuotaGiB: 1}); err != nil {
		t.Fatal(err)
	}
	rows, err := r.client.Get(ctx, r.shareKey(scope, address))
	var record storageShareRecord
	if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &record) != nil {
		t.Fatalf("read the initialized Ceph volume record: %v", err)
	}
	return record
}

func verifyHostedVolumeCheckpoint(t *testing.T, remote, rbd, volume, mapper string, key []byte, run func(string, io.Reader)) {
	t.Helper()
	path := remote + "/verify"
	offlineMapper := mapper + "-verify"
	run("set -eu\nsudo install -d -m 0700 "+path+"\n"+
		"device=$(sudo "+rbd+" device map --read-only --options ms_mode=secure,lock_timeout=8 ocean/"+volume+")\n"+
		"trap 'sudo umount "+path+" 2>/dev/null || true; sudo cryptsetup close "+offlineMapper+" 2>/dev/null || true; sudo "+rbd+" device unmap \"$device\"' EXIT\n"+
		"sudo cryptsetup isLuks --type luks2 \"$device\"\n"+
		"sudo cryptsetup open --readonly --type luks2 --key-file - \"$device\" "+offlineMapper+"\n"+
		"sudo mount -t ext4 -o ro,noload /dev/mapper/"+offlineMapper+" "+path+"\n"+
		"printf 'hosted-encrypted-checkpoint\\n' | sudo cmp -s - "+path+"/checkpoint\n", bytes.NewReader(key))
}
