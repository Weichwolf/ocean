//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

const smbLabHost = "farm-1-node-04"

func TestPackagedSMBWorker(t *testing.T) {
	state, fixture, endpoint, az := os.Getenv("OCEAN_E2E_DOMAIN_STATE"), os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE"),
		os.Getenv("OCEAN_E2E_SMB_ETCD"), os.Getenv("OCEAN_E2E_SMB_AZ")
	if state == "" || fixture == "" || endpoint == "" || az == "" {
		t.Skip("requires the dedicated domain and RBD lab, loopback etcd and pinned Azure CLI")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(fixture, "member-rbd.json"))
	var member smb.Member
	if err != nil || json.Unmarshal(raw, &member) != nil || len(member.Shares) != 1 || member.Validate() != nil {
		t.Fatalf("read the native SMB fixture: %v", err)
	}
	policy := smb.Policy{QuotaGiB: 1, ReaderSIDs: member.Shares[0].ReaderSIDs, WriterSIDs: member.Shares[0].WriterSIDs}
	member.Shares = nil
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	other := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	binding := smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: smbLabHost, Member: member}
	r := setupSMBWorkerRegion(t, endpoint, binding, "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	api, caFile, caPEM := startSMBLabAPI(t, r, scope, other)
	worker := directoryKVMHosts{root: root, state: state, directory: "smb-worker-" + scope.TenantID[:8], t: t}
	startSMBWorkerHost(t, ctx, r, worker, smbLabHost, directoryGuestOrigin(t, api), caPEM, true)
	pollVMWorker(t, ctx, 45*time.Second, "the packaged SMB host enrollment", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", smbLabHost), clientv3.WithCountOnly())
		return err == nil && live.Count == 1
	})
	const shareName = "managed-files"
	group := "smb-worker"
	share := arm.ResourceAddress{Group: group, Path: smb.ResourceType + "/" + shareName}
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: r.name, Tags: map[string]string{}}, "operator"); err != nil {
		t.Fatal(err)
	}
	cli := regionalWorkerCLI(t, ctx, api.URL, caFile, az)
	url := share.ID(scope) + "?api-version=" + smb.APIVersion
	call := func(method, url, body, expected string) []byte {
		t.Helper()
		return cli(method, url, body, "smb-worker-lab", expected)
	}
	discovered := call("get", "/subscriptions/"+scope.SubscriptionID+"/providers/Ocean.Storage?api-version=2024-11-01", "", "")
	if !bytes.Contains(discovered, []byte(`"smbShares"`)) || !bytes.Contains(discovered, []byte(smb.APIVersion)) {
		t.Fatalf("the CLI did not discover the SMB provider version: %s", discovered)
	}
	body := func(p smb.Policy) string {
		data, err := json.Marshal(map[string]any{"location": r.name, "properties": p})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	bad := policy
	bad.ReaderSIDs = []string{"S-1-5-21-99-88-77-1150"}
	call("put", url, body(bad), "InvalidSMBPolicy")
	call("put", url, body(policy), "")
	initial := readSMBLabShare(t, ctx, r, binding)
	call("put", url, body(policy), "")
	replay := readSMBLabShare(t, ctx, r, binding)
	if initial.Operation != replay.Operation || initial.Volume != replay.Volume || replay.Ready {
		t.Fatal("a repeated CLI request must keep the same pending operation and volume")
	}
	cli("get", url, "", "smb-worker-foreign-lab", "SubscriptionNotFound")
	cli("delete", url, "", "smb-worker-foreign-lab", "SubscriptionNotFound")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, api.URL+"/ocean/hosts/"+smbLabHost+"/smb-plan", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := api.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an uncertified caller reached the SMB host plan: %d, %v", response.StatusCode, err)
	}
	call("delete", "/subscriptions/"+scope.SubscriptionID+"/resourceGroups/"+group+"?api-version=2024-11-01",
		"", "ResourceGroupInUse")

	started := time.Now()
	worker.run(ctx, smbLabHost, "sudo systemctl start ocean-smb-agent.service", nil)
	wait := func(op string) time.Duration {
		t.Helper()
		at := time.Now()
		pollVMWorker(t, ctx, 75*time.Second, "the SMB operation to finish after the worker's receipt", func() bool {
			status, err := r.GetOperation(ctx, scope, op)
			return err == nil && status != nil && status.Status == arm.OperationSucceeded
		})
		status := call("get", "/subscriptions/"+scope.SubscriptionID+"/providers/Microsoft.Resources/operationStatuses/"+op+"?api-version=2024-11-01", "", "")
		if !bytes.Contains(status, []byte(`"Succeeded"`)) {
			t.Fatalf("the CLI did not observe a successful SMB operation: %s", status)
		}
		return time.Since(at)
	}
	wait(initial.Operation)
	provisioned := time.Since(started)
	view := call("get", url, "", "")
	if !bytes.Contains(view, []byte(`"Succeeded"`)) || !bytes.Contains(view, []byte("//files04.ad.ocean.test/"+shareName)) ||
		bytes.Contains(view, initial.Envelope) || bytes.Contains(view, []byte(initial.Volume.ID)) {
		t.Fatalf("unexpected public SMB projection: %s", view)
	}
	verify := func(extra ...string) {
		t.Helper()
		args := []string{"-B", filepath.Join(root, "lab/verify_smb_member.py"), "--state", state, "--fixture", fixture, "--share", shareName}
		probe := exec.CommandContext(ctx, "python3", append(args, extra...)...)
		if output, err := probe.CombinedOutput(); err != nil {
			t.Fatalf("native SMB probe: %v: %s", err, output)
		}
	}
	verify()
	verify("--checkpoint", "write")
	image := "ocean/" + initial.Volume.ID
	worker.run(ctx, smbLabHost, `test "$(sudo systemctl show -P Nice ocean-smb-agent.service)" = 10 && sudo findmnt --mountpoint `+smb.MountRoot+"/"+initial.Volume.ID, nil)
	policy.ReaderSIDs = nil
	call("put", url, body(policy), "")
	updated := readSMBLabShare(t, ctx, r, binding)
	if updated.Volume != initial.Volume || updated.Operation == initial.Operation {
		t.Fatal("an ACL change must keep the encrypted volume and start a new operation")
	}
	updatedIn := wait(updated.Operation)
	verify("--reader-denied")
	verify("--checkpoint", "verify")

	call("delete", url, "", "")
	deletedIn := wait(smbLabDeleteOperation(t, ctx, r, scope))
	call("get", url, "", "ResourceNotFound")
	call("delete", url, "", "")
	worker.run(ctx, smbLabHost, `set -eu
test -z "$(sudo ss -H -ltn '( sport = :445 )')"
if sudo findmnt --mountpoint `+smb.MountRoot+"/"+initial.Volume.ID+`; then exit 1; fi
if result=$(sudo rbd --id smb-lab --conf /etc/ocean-smb/rbd/ceph.conf --keyring /etc/ocean-smb/rbd/keyring info `+image+` 2>&1); then exit 1; fi
printf '%s\n' "$result" | grep -F 'No such file or directory'
`, nil)
	evidence, err := json.MarshalIndent(map[string]any{"azureCLI": "2.93.0", "share": share.ID(scope), "publishMilliseconds": provisioned.Milliseconds(),
		"aclUpdateMilliseconds": updatedIn.Milliseconds(), "withdrawalMilliseconds": deletedIn.Milliseconds(),
		"foreignSubscriptionDenied": true, "uncertifiedHostPlanDenied": true, "encryptedVolumeRetainedOnACLUpdate": true,
		"checkpointReadAfterACLUpdate": true, "resourceAndRBDVolumeRemoved": true}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "evidence"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "evidence", "managed-smb-cli.json"), append(evidence, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("stock Azure CLI and the installed SMB worker completed publish in %s, ACL update in %s and withdrawal in %s",
		provisioned.Round(time.Millisecond), updatedIn.Round(time.Millisecond), deletedIn.Round(time.Millisecond))
}

func startSMBLabAPI(t *testing.T, r *Region, scope, other arm.SubscriptionScope) (*httptest.Server, string, []byte) {
	t.Helper()
	ca, caKey, _, _ := directoryJoinClientCertificates(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	key, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(files, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caFile := write("ca.pem", caPEM)
	authority, _, err := enrollment.Open(enrollment.Config{CertificateFile: caFile,
		KeyFile:       write("ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		InventoryFile: write("inventory.json", []byte(`{"hosts":[]}`))}, r)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	api.TLS = directoryLabServerTLS(t, ca, caKey)
	regional := arm.Server{Origin: "https://" + api.Listener.Addr().String(), Location: r.name,
		Inventory: r, Groups: r, Operations: r, Roles: r, SMBShares: r,
		Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			entry := scope
			switch request.Header.Get("Authorization") {
			case "Bearer smb-worker-lab":
			case "Bearer smb-worker-foreign-lab":
				entry = other
			default:
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: entry.TenantID, SubscriptionID: entry.SubscriptionID, Members: []string{"operator"},
			}}, nil
		}}
	api.Config.Handler = authority.Handler(regional.Handler(http.NotFoundHandler()))
	api.StartTLS()
	return api, caFile, caPEM
}

func smbLabDeleteOperation(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope) string {
	t.Helper()
	rows, err := r.client.Get(ctx, r.operationKey(scope, ""), clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows.Kvs {
		key := strings.TrimPrefix(string(row.Key), r.operationKey(scope, ""))
		op, err := decodeOperation(row.Value, key)
		if err != nil {
			t.Fatal(err)
		}
		if op.Kind == removeSMBShare {
			return op.ID
		}
	}
	t.Fatal("the CLI deletion did not create an SMB operation")
	return ""
}

func setupSMBWorkerRegion(t *testing.T, endpoint string, binding smbBinding, fencer string) *Region {
	t.Helper()
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("the SMB worker test requires disposable loopback etcd")
	}
	key := filepath.Join(t.TempDir(), "storage.key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{2}, storage.KeySize), 0600); err != nil {
		t.Fatal(err)
	}
	storageRegion, err := openStorageControl(&storageConfig{KeyFile: key, FencePublicKeyFile: fencer, Workers: []string{"worker-a", "worker-b"}})
	if err != nil {
		t.Fatal(err)
	}
	control, err := openSMBControl([]smbBinding{binding}, storageRegion, true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r := &Region{client: client, root: "/test/smb-worker/" + operationID(), name: "local", cell: "cell-1", storage: storageRegion, smb: control}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, err := client.Delete(ctx, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
		_ = client.Close()
	})
	if err := r.bootstrapSMB(t.Context()); err != nil {
		t.Fatal(err)
	}
	directory := identity.ManagedDirectory{TenantID: binding.TenantID, SubscriptionID: binding.SubscriptionID,
		ID: operationID(), RequestedAt: time.Now().UTC(), ProvisionedAt: time.Now().UTC(), DomainSID: binding.Member.DomainSID,
		Spec: identity.DirectorySpec{DNSName: binding.Member.DNSDomain, NetBIOSName: binding.Member.NetBIOSDomain}}
	if _, err := client.Txn(t.Context()).Then(putJSON(r.managedDirectoryKey(binding.TenantID), directory),
		clientv3.OpPut(r.root+"/cells/"+r.cell+"/metadata", "{}")).Commit(); err != nil {
		t.Fatal(err)
	}
	return r
}

func readSMBLabShare(t *testing.T, ctx context.Context, r *Region, binding smbBinding) smbShareRecord {
	t.Helper()
	rows, err := r.client.Get(ctx, r.smbMemberKey(binding))
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := smbRecords(binding, rows.Kvs)
	if err != nil || len(records) != 1 {
		t.Fatalf("expected one SMB share: %v", err)
	}
	return records[0]
}

func startSMBWorkerHost(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, host, origin string, ca []byte, resumeStandalone bool) {
	t.Helper()
	workspace, err := lab.Open(worker.state)
	if err != nil {
		t.Fatal(err)
	}
	guests, err := workspace.Status()
	if err != nil {
		t.Fatal(err)
	}
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	var approval enrollment.Approval
	for _, guest := range guests {
		if guest.Guest.Name != host || !guest.Running {
			continue
		}
		for _, link := range guest.Guest.Interfaces {
			if link.Name == "mgmt0" {
				approval = enrollment.Approval{HostID: host, MAC: link.MAC, Address: link.Address.Addr().String(), Profile: "debian-13",
					Cell: r.cell, Pool: "lab", Roles: []string{"compute"}, MinimumCPU: 1, MinimumMemoryMiB: 768,
					TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), ExpiresAt: time.Now().Add(time.Hour).UTC()}
			}
		}
	}
	if !approval.Valid() {
		t.Fatal("the SMB worker must be the dedicated running Debian member")
	}
	if err := r.seedHostInventory(ctx, []enrollment.Approval{approval}); err != nil {
		t.Fatal(err)
	}
	const prefix = "/etc/ocean-agent/"
	state := "/var/lib/ocean-agent/" + worker.directory
	worker.run(ctx, host, "set -eu\nsudo test -f /usr/lib/systemd/system/ocean-smb-agent.service\n"+
		"sudo install -d -o ocean-agent -g ocean-agent -m 0700 "+state+"\n"+
		"sudo cp /etc/samba/smb.conf "+state+"/previous-smb.conf", nil)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if t.Failed() {
			out, _ := worker.ssh(cleanup, host, "sudo journalctl -u ocean-smb-agent.service --no-pager -n 25", nil)
			t.Logf("SMB worker journal:\n%s", out)
		}
		command := "set -eu\nsudo systemctl stop ocean-smb-agent.service\n" + packagedDirectoryWorker +
			"worker systemctl --user stop ocean-agent.service\nsudo systemctl stop smbd winbind\nsudo install -m 0600 " + state + "/previous-smb.conf /etc/samba/smb.conf\n"
		if resumeStandalone {
			command += "sudo systemctl restart winbind smbd"
		}
		if out, err := worker.ssh(cleanup, host, command, nil); err != nil {
			t.Errorf("restore the standalone Samba fixture: %v: %s", err, out)
		}
	})
	config, err := json.Marshal(map[string]any{"listenAddress": "127.0.0.1:8081", "enrollment": map[string]string{
		"origin": origin, "hostId": host, "managementInterface": "mgmt0", "caFile": prefix + "smb-lab-ca.pem",
		"tokenFile": state + "/join-token", "stateDirectory": state,
	}})
	if err != nil {
		t.Fatal(err)
	}
	backend := []byte(`{"pool":"ocean","client":"smb-lab","cephConfig":"/etc/ocean-smb/rbd/ceph.conf","keyring":"/etc/ocean-smb/rbd/keyring","mountRoot":"/srv/ocean-smb/volumes"}`)
	for name, data := range map[string][]byte{"config.json": config, "smb-lab-ca.pem": ca, "smb-storage.json": backend} {
		worker.run(ctx, host, "sudo tee "+prefix+name+" >/dev/null", bytes.NewReader(data))
	}
	worker.run(ctx, host, "sudo -u ocean-agent sh -c 'umask 077; cat >"+state+"/join-token'", strings.NewReader(token))
	worker.run(ctx, host, "set -eu\n"+packagedDirectoryWorker+
		"sudo systemctl daemon-reload\nworker systemctl --user daemon-reload\nworker systemctl --user restart ocean-agent.service", nil)
}
