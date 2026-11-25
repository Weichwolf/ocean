//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	smbRecoveryCeph  = "farm-1-node-05"
	smbRecoveryVIP   = "10.232.1.40"
	smbRecoveryShare = "restore-files"
)

func TestPackagedSMBBackupRestore(t *testing.T) {
	state, fixture, archive, az := os.Getenv("OCEAN_E2E_DOMAIN_STATE"), os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE"),
		os.Getenv("OCEAN_E2E_SMB_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_SMB_AZ")
	if state == "" || fixture == "" || archive == "" || az == "" {
		t.Skip("requires the two-member SMB lab, its private fixture, pinned etcd archive and Azure CLI")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	directory := t.TempDir()
	toolsDir := filepath.Join(directory, "tools")
	backupDir := filepath.Join(directory, "offline-backup")
	for _, path := range []string{toolsDir, backupDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	certs, serverCert, serverKey, etcd, etcdctl := prepareSMBRecoveryEtcd(t, ctx, archive, toolsDir)
	sourceEtcd, sourceCluster, stopSourceEtcd := startSMBRecoveryEtcd(t, ctx, certs, serverCert, serverKey, etcd, filepath.Join(directory, "source"), nil)

	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	foreign := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: scope.SubscriptionID}
	binding, policy := smbRecoveryBinding(t, fixture, scope)
	keyFile := filepath.Join(directory, "escrow.key")
	fencer := filepath.Join(directory, "fencer.pem")
	wrap := make([]byte, storage.KeySize)
	rand.Read(wrap)
	if err := os.WriteFile(keyFile, wrap, 0600); err != nil {
		t.Fatal(err)
	}
	clear(wrap)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	keyDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fencer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := regionConfig{Name: "smb-" + scope.TenantID[:8], InitialCell: "cell-1", Etcd: sourceEtcd,
		Storage:    &storageConfig{KeyFile: keyFile, FencePublicKeyFile: fencer, Workers: []string{"worker-a", "worker-b"}},
		SMBMembers: []smbBinding{binding}, ManagedDirectories: &enrollment.Capacity{}}
	open := func(config regionConfig) *Region {
		t.Helper()
		r, err := openRegion(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.close() })
		if err := r.bootstrapStorage(ctx); err != nil {
			t.Fatal(err)
		}
		if err := r.bootstrapSMB(ctx); err != nil {
			t.Fatal(err)
		}
		return r
	}
	source := open(cfg)
	seedSMBLabDirectory(t, source, binding)
	api, caFile, caPEM, activate := newSMBLabAPI(t, scope, foreign)
	activate(source)
	worker := directoryKVMHosts{root: root, state: state, directory: "smb-restore-" + scope.TenantID[:8], t: t}
	startSMBWorkerHost(t, ctx, source, worker, smbLabHost, directoryGuestOrigin(t, api), caPEM, true)
	waitLive := func(region *Region) {
		t.Helper()
		pollVMWorker(t, ctx, 50*time.Second, "an enrolled worker heartbeat", func() bool {
			response, err := region.client.Get(ctx, region.hostKey("live", smbLabHost), clientv3.WithCountOnly())
			return err == nil && response.Count == 1
		})
	}
	waitLive(source)
	cli := regionalWorkerCLI(t, ctx, api.URL, caFile, az)
	call := func(method, path string, body []byte, expected string) []byte {
		t.Helper()
		return cli(method, path, string(body), "smb-worker-lab", expected)
	}
	const group = "smb-backup"
	call("put", "/subscriptions/"+scope.SubscriptionID+"/resourceGroups/"+group+"?api-version=2024-11-01",
		fmt.Appendf(nil, `{"location":%q}`, source.name), "")
	share := arm.ResourceAddress{Group: group, Path: smb.ResourceType + "/" + smbRecoveryShare}
	path := share.ID(scope) + "?api-version=" + smb.APIVersion
	body, err := json.Marshal(map[string]any{"location": source.name, "properties": policy})
	if err != nil {
		t.Fatal(err)
	}
	call("put", path, body, "")
	pending := readSMBLabShare(t, ctx, source, binding)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		out, err := worker.ssh(cleanup, smbLabHost, "sudo systemctl stop ocean-smb-agent.service", nil)
		if err != nil {
			t.Errorf("stop the source SMB worker before withdrawing the fixture: %v: %s", err, out)
			return
		}
		image := "ocean/" + pending.Volume.ID
		out, err = worker.ssh(cleanup, smbRecoveryCeph, "if sudo rbd info "+image+" >/dev/null 2>&1; then sudo rbd rm "+image+"; fi", nil)
		if err != nil {
			t.Errorf("withdraw the source SMB test image: %v: %s", err, out)
		}
	})
	worker.run(ctx, smbLabHost, "sudo systemctl start ocean-smb-agent.service", nil)
	waitOperation := func(region *Region, id string) {
		t.Helper()
		pollVMWorker(t, ctx, 90*time.Second, "the SMB operation to succeed", func() bool {
			status, err := region.GetOperation(ctx, scope, id)
			return err == nil && status != nil && status.Status == arm.OperationSucceeded
		})
	}
	waitOperation(source, pending.Operation)
	stable := readSMBLabShare(t, ctx, source, binding)
	key, err := source.smbShareEncryptionKey(binding, stable)
	if err != nil {
		t.Fatal(err)
	}
	expectedKey := sha256.Sum256(key)
	clear(key)

	marker := operationID()
	probe := smbFailoverClient(t, worker, fixture, smbRecoveryVIP, smbRecoveryShare, marker)
	if out, err := probe(ctx, "checkpoint"); err != nil {
		t.Fatalf("write and flush the initial SMB checkpoint: %v: %s", err, out)
	}
	mount := smb.MountRoot + "/" + stable.Volume.ID
	target := mount + "/data/ocean-windows-" + marker + ".txt"
	worker.run(ctx, smbLabHost, "sudo setfacl -m u:0:r-- "+target, nil)
	before := smbRecoveryFilesystem(t, ctx, worker, mount, target)
	if !strings.Contains(before, "user:0:r--") {
		t.Fatal("the source checkpoint has no independent file ACL")
	}

	backupAt := time.Now()
	activate(nil)
	worker.run(ctx, smbLabHost, "sudo systemctl stop ocean-smb-agent.service", nil)
	assertSMBLabPlacement(t, ctx, worker, smbLabHost, smbRecoveryVIP, binding.Member.StateVolumeID, stable.Volume.ID, false)
	snapshot := filepath.Join(backupDir, "region.db")
	etcdLabCommand(t, ctx, nil, etcdctl, "--endpoints", sourceEtcd.Endpoints[0], "--cacert", sourceEtcd.CAFile,
		"--cert", sourceEtcd.CertificateFile, "--key", sourceEtcd.KeyFile, "snapshot", "save", snapshot)
	imageIDs := []string{binding.Member.StateVolumeID, stable.Volume.ID}
	digests := map[string]string{"regionalSnapshotSHA256": smbRecoveryDigest(t, snapshot)}
	for _, id := range imageIDs {
		file := filepath.Join(backupDir, id+".rbd")
		export := "sudo rbd export --export-format 2 --no-progress ocean/" + id + " -"
		smbRecoveryImage(t, ctx, worker, export, file, false)
		digests[id] = smbRecoveryDigest(t, file)
	}
	stopSourceEtcd()
	backupElapsed := time.Since(backupAt)

	restoreAt := time.Now()
	restoredData := filepath.Join(directory, "restored")
	restoredEtcd, restoredCluster, _ := startSMBRecoveryEtcd(t, ctx, certs, serverCert, serverKey, etcd, restoredData,
		func(peer, cluster, token string) {
			etcdLabCommand(t, ctx, nil, filepath.Join(toolsDir, "etcdutl"), "snapshot", "restore", snapshot,
				"--data-dir", restoredData, "--name", "smb-recovery", "--initial-advertise-peer-urls", peer,
				"--initial-cluster", cluster, "--initial-cluster-token", token, "--bump-revision", "1000000", "--mark-compacted")
		})
	if restoredCluster == sourceCluster {
		t.Fatal("the restored metadata must have a distinct etcd cluster identity")
	}
	cfg.Etcd = restoredEtcd
	memberKey, err := readSealingKey(binding.StateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	recoveredStateKey := filepath.Join(directory, "recovered-member-state.key")
	err = os.WriteFile(recoveredStateKey, memberKey, 0600)
	clear(memberKey)
	if err != nil {
		t.Fatal(err)
	}
	restoredBinding := binding
	restoredBinding.StateKeyFile = recoveredStateKey
	cfg.SMBMembers = []smbBinding{restoredBinding}
	restore := open(cfg)
	verifySMBRecoveredKey(t, ctx, root, directory, cfg, scope, foreign, share, expectedKey)

	const pool = "smb-restore-lab"
	smbRecoveryPool(t, ctx, worker, pool, imageIDs)
	for _, id := range imageIDs {
		smbRecoveryImage(t, ctx, worker, "sudo rbd import --export-format 2 --no-progress - "+pool+"/"+id,
			filepath.Join(backupDir, id+".rbd"), true)
	}
	activate(restore)
	waitLive(restore)
	worker.run(ctx, smbLabHost, "sudo systemctl start ocean-smb-agent.service", nil)
	pollVMWorker(t, ctx, 65*time.Second, "the restored SMB listener", func() bool {
		poll, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		out, err := worker.ssh(poll, smbLabHost, "sudo ss -H -ltn '( sport = :445 )'", nil)
		return err == nil && bytes.Contains(out, []byte(smbRecoveryVIP+":445"))
	})
	view := call("get", path, nil, "")
	if !bytes.Contains(view, []byte(share.ID(scope))) || !bytes.Contains(view, []byte("Succeeded")) {
		t.Fatalf("the restored API failed to expose the original share: %s", view)
	}
	cli("get", path, "", "smb-worker-foreign-lab", "ResourceNotFound")
	after := smbRecoveryFilesystem(t, ctx, worker, mount, target)
	if after != before {
		t.Fatalf("restored SMB file identity, ACL or project quota differs: before %q, after %q", before, after)
	}
	actualMappings := smbRecoveryOutput(t, ctx, worker, smbLabHost, "sudo rbd --conf /etc/ocean-smb/rbd/ceph.conf device list --format json")
	var mapped []struct{ Pool, Name string }
	if err := json.Unmarshal(actualMappings, &mapped); err != nil {
		t.Fatal(err)
	}
	for _, id := range imageIDs {
		count := 0
		for _, image := range mapped {
			if image.Name == id {
				if image.Pool != pool {
					t.Fatalf("restored image %s was attached from the original pool", id)
				}
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected one mapping for %s, got %d", id, count)
		}
	}
	debian := verifySMBRestoreClient(t, ctx, root, state, fixture, marker, "debian")
	restoredElapsed := time.Since(restoreAt)

	evidence := map[string]any{
		"azureCLI": "2.93.0", "sourceEtcdCluster": fmt.Sprintf("%x", sourceCluster), "restoredEtcdCluster": fmt.Sprintf("%x", restoredCluster),
		"exportMilliseconds": backupElapsed.Milliseconds(), "restoreMilliseconds": restoredElapsed.Milliseconds(),
		"ciphertextAndMetadataSHA256": digests, "originalPoolInaccessibleToRestoredWorker": true,
		"separateWrappingKeyRequired": true, "aclQuotaAndNativeFileIdentityPreserved": true, "debian": debian,
	}
	if windows := os.Getenv("OCEAN_E2E_SMB_RESTORE_WINDOWS_READY"); windows != "" {
		evidence["windows"] = waitSMBRestoreWindows(t, ctx, root, state, fixture, marker, windows)
	}
	// Import format 2 can carry snapshots. Use the operator's dedicated pool
	// for cleanup and leave the ordinary share deletion contract unchanged.
	worker.run(ctx, smbLabHost, "sudo systemctl stop ocean-smb-agent.service", nil)
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "evidence", "kerberos-smb-restore.json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("independent backups took %s, restored metadata and verified SMB data took %s", backupElapsed.Round(time.Millisecond), restoredElapsed.Round(time.Millisecond))
}

func smbRecoveryBinding(t *testing.T, fixture string, scope arm.SubscriptionScope) (smbBinding, smb.Policy) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture, "member-rbd.json"))
	var member smb.Member
	if err != nil || json.Unmarshal(raw, &member) != nil || len(member.Shares) != 1 || member.Validate() != nil {
		t.Fatalf("read the native SMB fixture: %v", err)
	}
	id, err := os.ReadFile(filepath.Join(fixture, "failover-state-id"))
	if err != nil {
		t.Fatal(err)
	}
	policy := smb.Policy{QuotaGiB: 1, ReaderSIDs: member.Shares[0].ReaderSIDs, WriterSIDs: member.Shares[0].WriterSIDs}
	member.Shares = nil
	member.Address, member.ServiceInterface = netip.MustParseAddr(smbRecoveryVIP), "work0"
	member.StateVolumeID = strings.TrimSpace(string(id))
	return smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: smbLabHost, StandbyHostID: smbLabStandby,
		Member: member, StateKeyFile: filepath.Join(fixture, "failover-state.key")}, policy
}

func smbRecoveryOutput(t *testing.T, ctx context.Context, worker directoryKVMHosts, host, command string) []byte {
	t.Helper()
	out, err := worker.ssh(ctx, host, command, nil)
	if err != nil {
		t.Fatalf("inspect %s on %s: %v: %s", command, host, err, out)
	}
	return out
}

func smbRecoveryFilesystem(t *testing.T, ctx context.Context, worker directoryKVMHosts, mount, target string) string {
	t.Helper()
	script := "set -eu\nsudo stat -c '%u:%g:%s' " + target + "\nsudo getfacl -ncp " + target +
		"\nsudo lsattr -pd " + mount + "/data" +
		"\nsudo repquota -P -n " + mount + " | grep -E '^#1[[:space:]].*[[:space:]]1048576[[:space:]]+1048576[[:space:]]'"
	return string(smbRecoveryOutput(t, ctx, worker, smbLabHost, script))
}

func smbRecoveryDigest(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	if written, err := io.Copy(digest, file); err != nil || written == 0 {
		t.Fatalf("hash the offline backup %s: %v", filepath.Base(path), err)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func smbRecoveryImage(t *testing.T, ctx context.Context, worker directoryKVMHosts, remote, file string, importing bool) {
	t.Helper()
	var stderr bytes.Buffer
	command := exec.CommandContext(ctx, filepath.Join(worker.root, "bin/ocean-lab"), "ssh", "-state", worker.state,
		smbRecoveryCeph, "--", remote)
	command.Stderr = &stderr
	var image *os.File
	var err error
	if importing {
		image, err = os.Open(file)
		command.Stdin = image
	} else {
		image, err = os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		command.Stdout = image
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = image.Close() }()
	if err := command.Run(); err != nil {
		t.Fatalf("transfer the encrypted image %s: %v: %s", filepath.Base(file), err, stderr.Bytes())
	}
	if !importing {
		if err := image.Sync(); err != nil {
			t.Fatal(err)
		}
	}
}

func smbRecoveryPool(t *testing.T, ctx context.Context, worker directoryKVMHosts, pool string, images []string) {
	t.Helper()
	const client = "smb-restore-lab"
	const keyring = "/etc/ocean-smb/rbd/restore-keyring"
	const config = "/etc/ocean-agent/smb-storage.json"
	const previous = "/etc/ocean-agent/smb-restore-fixture.previous"
	worker.run(ctx, smbRecoveryCeph, "sudo ceph osd pool create "+pool+" 8 && sudo rbd pool init "+pool, nil)
	credential, err := worker.ssh(ctx, smbRecoveryCeph, "sudo ceph auth get-or-create client."+client+
		" mon 'profile rbd' osd 'profile rbd pool="+pool+"' mgr 'profile rbd pool="+pool+"'", nil)
	if err != nil {
		t.Fatalf("provision a Ceph identity for the isolated recovery pool: %v", err)
	}
	defer clear(credential)
	worker.run(ctx, smbLabHost, "sudo install -m 0600 /dev/stdin "+keyring, bytes.NewReader(credential))
	worker.run(ctx, smbLabHost, "sudo cp "+config+" "+previous, nil)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		out, err := worker.ssh(cleanup, smbLabHost, "set -eu\nsudo systemctl stop ocean-smb-agent.service\nsudo mv "+previous+" "+config+
			"\nsudo unlink "+keyring, nil)
		if err != nil {
			t.Errorf("restore the source member configuration: %v: %s", err, out)
			return
		}
		for _, id := range images {
			image := pool + "/" + id
			for _, action := range []string{"snap purge ", "rm "} {
				out, err := worker.ssh(cleanup, smbRecoveryCeph,
					"if sudo rbd info "+image+" >/dev/null 2>&1; then sudo rbd "+action+image+"; fi", nil)
				if err != nil {
					t.Errorf("clean up the restored image %s: %v: %s", image, err, out)
				}
			}
		}
	})
	backend, err := json.Marshal(storage.Config{Pool: pool, Client: client, CephConfig: "/etc/ocean-smb/rbd/ceph.conf", Keyring: keyring, MountRoot: smb.MountRoot})
	if err != nil {
		t.Fatal(err)
	}
	worker.run(ctx, smbLabHost, "sudo install -m 0600 /dev/stdin "+config, bytes.NewReader(backend))
	out, err := worker.ssh(ctx, smbLabHost, "sudo rbd --conf /etc/ocean-smb/rbd/ceph.conf --id "+client+
		" --keyring "+keyring+" info ocean/"+images[0], nil)
	diagnostic := bytes.ToLower(out)
	if err == nil || !bytes.Contains(diagnostic, []byte("permission denied")) && !bytes.Contains(diagnostic, []byte("operation not permitted")) {
		t.Fatalf("the recovery identity must be denied access to the source pool: %v: %s", err, out)
	}
}

func verifySMBRecoveredKey(t *testing.T, ctx context.Context, root, directory string, cfg regionConfig,
	scope, foreign arm.SubscriptionScope, share arm.ResourceAddress, expected [32]byte) {
	t.Helper()
	wrongKey := filepath.Join(directory, "wrong-wrap.key")
	wrong := make([]byte, storage.KeySize)
	rand.Read(wrong)
	err := os.WriteFile(wrongKey, wrong, 0600)
	clear(wrong)
	if err != nil {
		t.Fatal(err)
	}
	run := func(name, tenant, want, wrappingKey string) {
		t.Helper()
		copy := cfg
		storageConfig := *copy.Storage
		storageConfig.KeyFile = wrappingKey
		copy.Storage = &storageConfig
		data, err := json.Marshal(settings{Region: &copy})
		if err != nil {
			t.Fatal(err)
		}
		config, keyPath := filepath.Join(directory, name+".json"), filepath.Join(directory, name+".key")
		if err := os.WriteFile(config, data, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, filepath.Join(root, "bin/ocean-recover"), "-config", config, "-tenant", tenant,
			"-subscription", scope.SubscriptionID, "-share", share.ID(scope), "-output", keyPath)
		out, err := command.CombinedOutput()
		if want != "" {
			if err == nil || !bytes.Contains(out, []byte(want)) {
				t.Fatalf("operator recovery expected %q: %v: %s", want, err, out)
			}
			if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
				t.Fatal("failed recovery left a key file")
			}
			return
		}
		if err != nil {
			t.Fatalf("recover the authorized volume key: %v: %s", err, out)
		}
		key, err := readSealingKey(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		if sha256.Sum256(key) != expected {
			t.Fatal("the recovery command wrote the wrong key")
		}
		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}
	}
	run("foreign", foreign.TenantID, arm.ErrStorageMissing.Error(), cfg.Storage.KeyFile)
	run("wrong-key", scope.TenantID, "invalid SMB volume key envelope", wrongKey)
	run("correct-key", scope.TenantID, "", cfg.Storage.KeyFile)
}

func smbRestoreClientCommand(ctx context.Context, root, state, fixture, marker, platform string) *exec.Cmd {
	return exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "lab/verify_smb_member.py"),
		"--state", state, "--fixture", fixture, "--share", smbRecoveryShare, "--server-ip", smbRecoveryVIP,
		"--restored-"+platform+"-run-id", marker)
}

func verifySMBRestoreClient(t *testing.T, ctx context.Context, root, state, fixture, marker, platform string) json.RawMessage {
	t.Helper()
	out, err := smbRestoreClientCommand(ctx, root, state, fixture, marker, platform).CombinedOutput()
	if err != nil || !json.Valid(out) {
		t.Fatalf("verify the restored SMB share from %s: %v: %s", platform, err, out)
	}
	return json.RawMessage(bytes.TrimSpace(out))
}

func waitSMBRestoreWindows(t *testing.T, ctx context.Context, root, state, fixture, marker, ready string) json.RawMessage {
	t.Helper()
	if !filepath.IsAbs(ready) {
		t.Fatal("the Windows probe handoff requires an absolute path")
	}
	notify, err := os.OpenFile(ready, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	encodeErr := json.NewEncoder(notify).Encode(map[string]string{"runId": marker, "share": smbRecoveryShare, "serverIP": smbRecoveryVIP})
	if err := notify.Close(); err != nil || encodeErr != nil {
		t.Fatalf("write the Windows probe handoff: %v %v", err, encodeErr)
	}
	t.Logf("restored SMB share ready for Windows fixture at %s", ready)
	wait, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	var output []byte
	for wait.Err() == nil {
		probe, stop := context.WithTimeout(wait, 12*time.Second)
		output, err = smbRestoreClientCommand(probe, root, state, fixture, marker, "windows").CombinedOutput()
		stop()
		if err == nil && json.Valid(output) {
			return json.RawMessage(bytes.TrimSpace(output))
		}
		select {
		case <-wait.Done():
		case <-time.After(3 * time.Second):
		}
	}
	t.Fatalf("the restored Windows Kerberos probe did not complete: %v: %s", err, output)
	return nil
}
