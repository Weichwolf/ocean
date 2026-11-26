//go:build e2e

package controlplane

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	pairDirectoryHost = "farm-1-node-01"
	pairDirectoryIP   = "10.232.1.29"
	pairDomain        = "ad.pair.ocean.test"
	pairObserverIP    = "10.232.1.17"
)

type desktopPairAPI struct {
	az            func(string, string, string) []byte
	cli           func(string, string, string, string, string) []byte
	api           *httptest.Server
	privateOrigin string
	ca            *x509.Certificate
	key           ed25519.PrivateKey
	caPEM         []byte
}

type desktopPairMachine struct {
	name      string
	vm        arm.ResourceAddress
	nic       arm.ResourceAddress
	desktop   arm.ResourceAddress
	id        string
	ip        string
	boot      string
	account   desktopPairAccount
	probe     *packagedDesktopClient
	started   time.Time
	provision time.Duration
}

type desktopPairAccount struct {
	user     enrollment.DirectoryUserView
	password string
}

func testAssignedDesktopPair(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, guests []lab.GuestStatus,
	scope arm.SubscriptionScope, vnet, subnet arm.ResourceAddress, catalog vmCatalogImage, access desktopPairAPI) {
	t.Helper()
	evidence := filepath.Join(worker.state, "evidence")
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"desktop-pair.tsv", "desktop-pair-rdp.tsv"} {
		if err := os.Remove(filepath.Join(evidence, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	tenant := startDesktopPairDirectory(t, ctx, r, worker, scope, subnet, access)
	var accounts []desktopPairAccount
	for _, label := range []string{"deskone", "desktwo", "unassigned"} {
		local := label + scope.TenantID[:7]
		password := "Pair9-" + operationID() + operationID()
		fields, err := json.Marshal(map[string]any{
			"userPrincipalName": local + "@" + pairDomain, "displayName": label, "mailNickname": local, "accountEnabled": true,
			"passwordProfile": map[string]any{"password": password, "forceChangePasswordNextSignIn": false},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := r.RunDirectoryGraph(ctx, tenant, enrollment.DirectoryGraphInput{Operation: enrollment.DirectoryUserCreate, Fields: fields})
		clear(fields)
		if err != nil || result.Status != http.StatusCreated || result.User == nil {
			t.Fatalf("create the disposable Samba workforce account: status %d: %v", result.Status, err)
		}
		accounts = append(accounts, desktopPairAccount{user: *result.User, password: password})
		name := local
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if _, err := worker.ssh(cleanup, pairDirectoryHost, "sudo samba-tool user delete "+name, nil); err != nil {
				t.Error("remove disposable Samba workforce account:", err)
			}
		})
	}

	group := vnet.Group
	address := func(kind, name string) arm.ResourceAddress {
		return arm.ResourceAddress{Group: group, Path: kind + "/" + name}
	}
	url := func(resource arm.ResourceAddress, version string) string {
		return resource.ID(scope) + "?api-version=" + version
	}
	image := address(arm.VMImageType, "debian-desktop")
	imageURL := url(image, arm.VMImageAPIVersion)
	access.az("put", imageURL, fmt.Sprintf(`{"location":"local","properties":{"hyperVGeneration":"V2","storageProfile":{
        "osDisk":{"osType":"Linux","osState":"Specialized","blobUri":%q}}}}`, catalog.URI))
	machines := make([]desktopPairMachine, 0, 2)
	for i, name := range []string{"desk-one", "desk-two"} {
		vm := address(arm.VirtualMachineType, name)
		nic := address(arm.VMNetworkInterfaceType, name)
		dst := address(arm.DesktopType, name)
		access.az("put", url(nic, arm.VMNetworkAPIVersion),
			fmt.Sprintf(`{"location":"local","properties":{"ipConfigurations":[{"name":"private","properties":{
                "subnet":{"id":%q},"privateIPAllocationMethod":"Dynamic"}}]}}`, subnet.ID(scope)))
		created := time.Now()
		request := fmt.Sprintf(`{"location":"local","properties":{"hardwareProfile":{"vmSize":"Standard_B1s"},"storageProfile":{
            "imageReference":{"id":%q},"osDisk":{"name":%q,"createOption":"FromImage","deleteOption":"Delete",
            "managedDisk":{"storageAccountType":"Standard_LRS"}}},"networkProfile":{"networkInterfaces":[{"id":%q}]}}}`,
			image.ID(scope), name+"-disk", nic.ID(scope))
		access.az("put", url(vm, arm.VirtualMachineAPIVersion), request)
		machines = append(machines, desktopPairMachine{name: name, vm: vm, nic: nic, desktop: dst, account: accounts[i], started: created})
	}
	assertPackagedVMQuota(t, ctx, r, scope, enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 2048}, "16")
	for i := range machines {
		machine := &machines[i]
		pollVMWorker(t, ctx, 10*time.Minute, machine.name+" to boot on the packaged KVM worker", func() bool {
			_, record, operation, _, _, err := r.readVM(ctx, scope, machine.vm)
			if err != nil || operation == nil || operation.Status != arm.OperationSucceeded || record.Observed != workload.Running {
				return false
			}
			machine.id = record.MachineID
			return true
		})
		machine.provision = time.Since(machine.started)
		read := access.az("get", url(machine.nic, arm.VMNetworkAPIVersion), "")
		var nic struct {
			Properties struct {
				IPConfigurations []struct {
					Properties struct {
						PrivateIPAddress netip.Addr `json:"privateIPAddress"`
					} `json:"properties"`
				} `json:"ipConfigurations"`
			} `json:"properties"`
		}
		if json.Unmarshal(read, &nic) != nil || len(nic.Properties.IPConfigurations) != 1 {
			t.Fatal("the CLI did not return the provisioned private NIC")
		}
		ip := nic.Properties.IPConfigurations[0].Properties.PrivateIPAddress
		if !netip.MustParsePrefix("10.232.1.16/28").Contains(ip) {
			t.Fatalf("the desktop escaped its private subnet: %s", ip)
		}
		machine.ip = ip.String()
		machine.probe = packagedDesktopSSHAt(t, worker.state, guests, machine.ip)
		pollVMWorker(t, ctx, time.Minute, machine.name+" to serve the allocated private address", func() bool {
			result, err := machine.probe.run(ctx,
				"systemctl is-active --quiet xrdp && sudo -n cat /sys/class/dmi/id/product_uuid /proc/sys/kernel/random/boot_id", nil)
			fields := strings.Fields(string(result))
			if err != nil || len(fields) != 2 || !strings.EqualFold(fields[0], machine.id) || !enrollment.ValidDirectoryJoinID(fields[1]) {
				return false
			}
			machine.boot = fields[1]
			return true
		})
		body := fmt.Sprintf(`{"location":"local","properties":{"virtualMachineId":%q,"principalType":"User","principalId":%q}}`,
			machine.vm.ID(scope), machine.account.user.ID)
		result := access.az("put", url(machine.desktop, arm.DesktopAPIVersion), body)
		var assignment struct {
			Properties desktopAssignment `json:"properties"`
		}
		if json.Unmarshal(result, &assignment) != nil || assignment.Properties.MachineID != machine.id ||
			assignment.Properties.PrincipalID != machine.account.user.ID || !enrollment.ValidDirectoryJoinID(assignment.Properties.AssignmentID) {
			t.Fatalf("the CLI did not assign the guest's observed machine ID: %s", result)
		}
		access.cli("get", url(machine.desktop, arm.DesktopAPIVersion), "", "vm-worker-foreign-lab", "SubscriptionNotFound")
	}
	first, second := machines[0], machines[1]
	if first.id == second.id || first.ip == second.ip || first.boot == second.boot {
		t.Fatal("the two personal desktops must be independent running virtual machines")
	}
	verifyPairAdmission(t, ctx, r, worker, guests, scope, access, machines, accounts[2].user.UPN)
	verifyDesktopPairRDP(t, ctx, worker, access, machines, accounts[2])
	for _, machine := range machines {
		access.az("delete", url(machine.desktop, arm.DesktopAPIVersion), "")
		access.az("delete", url(machine.vm, arm.VirtualMachineAPIVersion), "")
	}
	for _, machine := range machines {
		pollVMWorker(t, ctx, 95*time.Second, machine.name+" to release its disk and quota", func() bool {
			_, _, op, _, _, err := r.readVM(ctx, scope, machine.vm)
			return err == nil && op == nil
		})
		access.az("delete", url(machine.nic, arm.VMNetworkAPIVersion), "")
	}
	assertPackagedVMQuota(t, ctx, r, scope, enrollment.Capacity{}, "0")
	access.az("delete", imageURL, "")
	result := fmt.Sprintf("desktop\tmachine_id\tprivate_ip\tboot_id\tprovision_ms\n%s\t%s\t%s\t%s\t%d\n%s\t%s\t%s\t%s\t%d\n",
		first.name, first.id, first.ip, first.boot, first.provision.Milliseconds(),
		second.name, second.id, second.ip, second.boot, second.provision.Milliseconds())
	if err := os.WriteFile(filepath.Join(evidence, "desktop-pair.tsv"), []byte(result), 0600); err != nil {
		t.Fatal(err)
	}
}

func startDesktopPairDirectory(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, scope arm.SubscriptionScope,
	subnet arm.ResourceAddress, access desktopPairAPI) identity.TenantReservation {
	t.Helper()
	r.directoryCapacity = enrollment.Capacity{CPUMillis: 400, MemoryMiB: 384}
	certificate := directoryFixtureHostCertificate(t, access.ca, access.key, pairDirectoryHost, 12)
	output, err := worker.ssh(ctx, pairDirectoryHost,
		`sudo /usr/bin/python3 -c 'from samba.samdb import SamDB; from samba.param import LoadParm; from samba.auth import system_session; p=LoadParm(); p.load("/etc/samba/smb.conf"); print(SamDB(session_info=system_session(p), lp=p).get_domain_sid())'`, nil)
	if err != nil {
		t.Fatalf("read the provisioned Samba directory SID: %v: %s", err, output)
	}
	tenant := identity.TenantReservation{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		Administrator: operationID(), Fingerprint: operationID()}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		DisplayName: "Live Desktop Pair", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	directory := identity.ManagedDirectory{ID: operationID(), TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		RequestedAt: time.Now().Add(-time.Minute), ProvisionedAt: time.Now(), DomainSID: strings.TrimSpace(string(output)),
		Spec: identity.DirectorySpec{DNSName: pairDomain, NetBIOSName: "OCEANPAIR", SubnetID: strings.ToLower(subnet.ID(scope))}}
	first := Reservation{ID: operationID(), HostID: pairDirectoryHost, Generation: operationID(), PrivateIPv4: netip.MustParseAddr(pairDirectoryIP)}
	second := Reservation{ID: operationID(), HostID: "pair-directory-spare", Generation: operationID(), PrivateIPv4: netip.MustParseAddr("10.232.1.30")}
	placement := directoryPlacement{DirectoryID: directory.ID, Controllers: [2]Reservation{first, second}}
	lease, err := r.client.Grant(ctx, 600)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollment.Host{HostID: first.HostID, Cell: r.cell, Pool: "lab", Roles: []string{"compute"}, Certificate: certificate.Certificate[0]}
	live, err := json.Marshal(enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles, DirectoryRuntime: true})
	if err != nil {
		t.Fatal(err)
	}
	task := enrollment.Assignment{ID: first.ID, Generation: first.Generation, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, PrivateIPv4: first.PrivateIPv4, Directory: &enrollment.DirectoryAssignment{
			DirectoryID: directory.ID, DNSName: directory.Spec.DNSName, NetBIOSName: directory.Spec.NetBIOSName, ControllerIndex: 1,
			ControllerIPv4: [2]netip.Addr{first.PrivateIPv4, second.PrivateIPv4}}}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.managedDirectoryKey(tenant.TenantID), directory),
		putJSON(r.managedDirectoryPlacementKey(tenant.TenantID), placement), putJSON(r.hostKey("registered", host.HostID), host),
		clientv3.OpPut(r.hostKey("live", host.HostID), string(live), clientv3.WithLease(lease.ID)),
		putJSON(r.hostReservationKey(scope, host.HostID, first.ID), task)).Commit(); err != nil {
		t.Fatal(err)
	}
	refresh := func(ctx context.Context) error {
		if _, err := r.client.KeepAliveOnce(ctx, lease.ID); err != nil {
			return err
		}
		return r.ReportDirectoryHealth(ctx, host.HostID, host.Certificate, tenant.TenantID, first.Generation,
			enrollment.DirectoryHealth{Ready: true, DomainSID: directory.DomainSID})
	}
	if err := refresh(ctx); err != nil {
		t.Fatal(err)
	}
	remote := "/run/" + worker.directory + "-graph"
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range []string{"domain_join.py", "directory_graph.py", "directory_groups.py", "directory_users.py"} {
		body, err := os.ReadFile(filepath.Join(worker.root, "packaging", "samba", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	worker.run(ctx, pairDirectoryHost, "sudo install -d -m 0700 "+remote+" && sudo tar -xf - -C "+remote, &archive)
	call := "sudo /usr/bin/python3 -c " + quotePairArgument(`import io, json, sys
sys.path.insert(0, sys.argv[1])
from directory_graph import run
from domain_join import open_directory
raw = sys.stdin.read()
result = run(open_directory("/etc/samba/smb.conf"), "ad.pair.ocean.test", io.StringIO(raw))
result["id"] = json.loads(raw)["id"]
print(json.dumps(result))`) + " " + remote
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		tick := time.NewTicker(150 * time.Millisecond)
		defer tick.Stop()
		next := time.Now().Add(5 * time.Second)
		for {
			select {
			case <-workerCtx.Done():
				done <- nil
				return
			case now := <-tick.C:
				if !now.Before(next) {
					if err := refresh(workerCtx); err != nil {
						done <- fmt.Errorf("refresh Samba fixture health: %w", err)
						return
					}
					next = now.Add(5 * time.Second)
				}
				if err := runDesktopPairGraphTask(workerCtx, r, tenant, host, first, worker, call); err != nil {
					done <- err
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Error(err)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		if _, err := worker.ssh(cleanup, pairDirectoryHost, "sudo rm -rf -- "+remote, nil); err != nil {
			t.Error("remove disposable Graph scripts:", err)
		}
	})
	return tenant
}

func runDesktopPairGraphTask(ctx context.Context, r *Region, tenant identity.TenantReservation, host enrollment.Host,
	controller Reservation, worker directoryKVMHosts, command string) error {
	task, err := r.HostDirectoryGraphTask(ctx, host.HostID, host.Certificate, tenant.TenantID, controller.Generation)
	if err != nil || task == nil {
		return err
	}
	data, err := json.Marshal(task)
	if err != nil {
		return err
	}
	defer clear(data)
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := worker.ssh(call, pairDirectoryHost, command, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("execute Samba Graph fixture %s: %w", task.Operation, err)
	}
	var result enrollment.DirectoryGraphResult
	if err := json.Unmarshal(out, &result); err != nil {
		return fmt.Errorf("decode Samba Graph fixture result %s: %w", task.Operation, err)
	}
	return r.FinishDirectoryGraphTask(ctx, host.HostID, host.Certificate, tenant.TenantID, controller.Generation, result)
}

func quotePairArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func verifyPairAdmission(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, guests []lab.GuestStatus,
	scope arm.SubscriptionScope, access desktopPairAPI, machines []desktopPairMachine, unassigned string) {
	t.Helper()
	relayDesktopPairRegion(t, ctx, access, worker, guests)
	guestsConfig := make([]desktopNativeConfig, 0, len(machines))
	for i, machine := range machines {
		cert := directoryFixtureHostCertificate(t, access.ca, access.key, machine.name, int64(i+50))
		key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		guestsConfig = append(guestsConfig, desktopNativeConfig{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
			DesktopID: machine.desktop.ID(scope), MachineID: machine.id, Certificate: fmt.Sprintf("%x", sha256.Sum256(cert.Certificate[0]))})
		for name, data := range map[string][]byte{"ca.pem": access.caPEM,
			"guest.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
			"guest.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
			command := "sudo install -d -m 0700 /run/ocean-pair && sudo sh -c 'umask 077; cat > /run/ocean-pair/" + name + "'"
			if out, err := machine.probe.run(ctx, command, bytes.NewReader(data)); err != nil {
				t.Fatalf("install the private guest certificate fixture: %v: %s", err, out)
			}
		}
		clear(key)
	}
	signingKey := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(signingKey, access.key.Seed(), 0600); err != nil {
		t.Fatal(err)
	}
	control, err := openDesktopLaunch(&desktopLaunchConfig{SigningKeyFile: signingKey, Gateways: []string{"gateway-one", "gateway-two"},
		NativeGuests: guestsConfig}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.desktopLaunch = control
	if err := r.bootstrapDesktopLaunch(ctx); err != nil {
		t.Fatal(err)
	}

	const probe = `import json, ssl, sys, urllib.error, urllib.request
base, account = sys.argv[1:]
sslctx = ssl.create_default_context(cafile="/run/ocean-pair/ca.pem")
sslctx.load_cert_chain("/run/ocean-pair/guest.pem", "/run/ocean-pair/guest.key")
request = urllib.request.Request(base, json.dumps({"user": account}).encode(), {"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(request, context=sslctx, timeout=12) as response:
        print(response.status, response.headers.get("Cache-Control", ""))
except urllib.error.HTTPError as error:
    print(error.code, error.headers.get("Cache-Control", ""))`
	for i, machine := range machines {
		for _, test := range []struct{ user, result string }{
			{machine.account.user.UPN, "204 no-store"}, {machines[1-i].account.user.UPN, "403 no-store"},
			{unassigned, "403 no-store"}, {"outsider@foreign.ocean.test", "403 no-store"},
		} {
			command := "sudo -n /usr/bin/python3 -c " + quotePairArgument(probe) + " " +
				quotePairArgument(access.privateOrigin+desktop.NativeAdmissionPath) + " " + quotePairArgument(test.user)
			out, err := machine.probe.run(ctx, command, nil)
			if err != nil || strings.TrimSpace(string(out)) != test.result {
				t.Fatalf("%s private admission returned %q, want %q: %v", machine.name, string(out), test.result, err)
			}
		}
	}
	t.Log("both Azure CLI desktops served separate private NICs and each guest certificate accepted only the assigned Samba user")
}

func verifyDesktopPairRDP(t *testing.T, ctx context.Context, worker directoryKVMHosts, access desktopPairAPI,
	machines []desktopPairMachine, unassigned desktopPairAccount) {
	t.Helper()
	worker.run(ctx, desktopRDPObserver, "command -v xfreerdp3 && command -v xvfb-run && command -v xauth", nil)
	admin, err := worker.ssh(ctx, pairDirectoryHost, "sudo cat /var/lib/ocean-desktop-pair-directory/administrator", nil)
	if err != nil || len(bytes.TrimSpace(admin)) == 0 {
		t.Fatalf("read disposable Samba join credentials: %v", err)
	}
	defer clear(admin)
	var report strings.Builder
	report.WriteString("client\tdesktop\taccount_role\toutcome\tduration_ms\n")
	for i, machine := range machines {
		pin := prepareDesktopPairRDP(t, ctx, worker, access, machine, admin)
		for _, test := range []struct {
			account desktopPairAccount
			role    string
		}{
			{machines[1-i].account, "crossed"}, {unassigned, "unassigned"}, {machine.account, "assigned"},
		} {
			elapsed, outcome := probeDesktopPairRDP(t, ctx, worker, machine, test.account, pin, test.role == "assigned")
			fmt.Fprintf(&report, "debian-freerdp\t%s\t%s\t%s\t%d\n", machine.name, test.role, outcome, elapsed.Milliseconds())
		}
	}
	if err := os.WriteFile(filepath.Join(worker.state, "evidence", "desktop-pair-rdp.tsv"), []byte(report.String()), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("Debian FreeRDP opened both assigned Openbox sessions and XRDP denied valid crossed and unassigned Samba credentials")
}

func prepareDesktopPairRDP(t *testing.T, ctx context.Context, worker directoryKVMHosts, access desktopPairAPI,
	machine desktopPairMachine, admin []byte) string {
	t.Helper()
	stage := func(path, mode string, data []byte) {
		t.Helper()
		command := "sudo sh -c " + quotePairArgument("umask 077; cat > "+path+" && chmod "+mode+" "+path)
		if out, err := machine.probe.run(ctx, command, bytes.NewReader(data)); err != nil {
			t.Fatalf("stage %s on %s: %v: %s", path, machine.name, err, out)
		}
	}
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	stage("/run/ocean-pair/join.sh", "0600", read("lab/prepare_assigned_desktop_guest.sh"))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		out, err := worker.ssh(cleanup, pairDirectoryHost, "sudo samba-tool computer delete "+quotePairArgument(machine.name), nil)
		if err != nil && !strings.Contains(string(out), "Unable to find computer") {
			t.Errorf("remove desktop %s's disposable domain account: %v: %s", machine.name, err, out)
		}
	})
	join, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	if out, err := machine.probe.run(join, "sudo sh /run/ocean-pair/join.sh "+quotePairArgument(machine.name), bytes.NewReader(admin)); err != nil {
		t.Fatalf("join %s to the disposable Samba domain: %v: %s", machine.name, err, out)
	}
	public, ok := access.key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("the desktop launch signer must expose an Ed25519 public key")
	}
	adminKey := base64.StdEncoding.EncodeToString(public)
	settings, err := json.Marshal(map[string]any{"machineId": machine.id, "publicKey": adminKey, "native": map[string]string{
		"region": access.privateOrigin, "caFile": "/run/ocean-pair/ca.pem", "certificateFile": "/run/ocean-pair/guest.pem", "keyFile": "/run/ocean-pair/guest.key",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := machine.probe.run(ctx, "sudo install -d -m 0755 /usr/libexec/ocean && sudo install -d -m 0700 /etc/ocean-desktop", nil); err != nil {
		t.Fatalf("prepare guest admission paths: %v: %s", err, out)
	}
	stage("/usr/libexec/ocean/ocean-desktop-guest", "0755", read("bin/ocean-desktop-guest"))
	stage("/etc/ocean-desktop/guest.json", "0600", settings)
	pam, err := machine.probe.run(ctx, "sudo cat /etc/pam.d/xrdp-sesman", nil)
	if err != nil || bytes.Count(pam, []byte("@include common-auth")) != 1 || bytes.Count(pam, []byte("@include common-session\n")) != 1 {
		t.Fatalf("inspect the expected XRDP PAM stack: %v: %s", err, pam)
	}
	pam = bytes.Replace(pam, []byte("@include common-auth"), append(read("packaging/debian/ocean-desktop-pam"), []byte("@include common-auth")...), 1)
	pam = bytes.Replace(pam, []byte("@include common-session\n"), append([]byte("@include common-session\n"), read("packaging/debian/ocean-desktop-pam-session")...), 1)
	stage("/etc/pam.d/xrdp-sesman", "0644", pam)
	command := "sudo adcli testjoin && sudo systemctl restart xrdp-sesman xrdp && sudo openssl x509 -in /etc/xrdp/cert.pem -noout -fingerprint -sha256"
	out, err := machine.probe.run(ctx, command, nil)
	_, pin, found := strings.Cut(strings.TrimSpace(string(out)), "Fingerprint=")
	pin = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
	digest, decodeErr := hex.DecodeString(pin)
	if err != nil || !found || decodeErr != nil || len(digest) != sha256.Size {
		t.Fatalf("verify %s's machine trust and pinned XRDP certificate: %v: %s", machine.name, err, out)
	}
	return pin
}

func probeDesktopPairRDP(t *testing.T, ctx context.Context, worker directoryKVMHosts, machine desktopPairMachine,
	account desktopPairAccount, pin string, allowed bool) (time.Duration, string) {
	t.Helper()
	upn := quotePairArgument(account.user.UPN)
	credential := strings.NewReader(account.password + "\n")
	local, _, _ := strings.Cut(account.user.UPN, "@")
	principal := quotePairArgument(local + "@" + strings.ToUpper(pairDomain))
	check := "sudo env KRB5CCNAME=MEMORY:ocean-pair kinit " + principal
	if out, err := machine.probe.run(ctx, check, credential); err != nil {
		t.Fatalf("validate the disposable Kerberos credential for %s: %v: %s", machine.name, err, out)
	}
	check = "timeout 25s sh -c " + quotePairArgument("until getent passwd "+upn+" >/dev/null; do sleep 1; done")
	if out, err := machine.probe.run(ctx, check, nil); err != nil {
		diagnostics, diagErr := machine.probe.run(ctx, "sudo sssctl config-check; grep -E '^(passwd|group|hosts):' /etc/nsswitch.conf; "+
			"sudo journalctl --no-pager -n 22 -u sssd; sudo tail -n 16 /var/log/sssd/sssd_"+pairDomain+".log", nil)
		t.Fatalf("resolve the disposable workforce UID on %s: %v: %s; SSSD: %v: %s", machine.name, err, out, diagErr, diagnostics)
	}
	before, err := machine.probe.run(ctx, "date +%s.%N", nil)
	if err != nil {
		t.Fatal(err)
	}
	var guestTime float64
	if _, err := fmt.Sscan(string(before), &guestTime); err != nil || guestTime <= 0 {
		t.Fatalf("invalid time from %s: %q: %v", machine.name, before, err)
	}
	command := "timeout -k 2s 14s xvfb-run -a xfreerdp3 /v:" + machine.ip + ":3389 /u:" + upn +
		" /from-stdin:force /sec:tls /cert:fingerprint:sha256:" + pin +
		` /size:800x600 /log-level:WARN; status=$?; test "$status" -eq 0 || test "$status" -eq 124`
	call, cancel := context.WithTimeout(ctx, 22*time.Second)
	defer cancel()
	type outcome struct {
		output []byte
		err    error
	}
	client := make(chan outcome, 1)
	started := time.Now()
	go func() {
		out, err := worker.ssh(call, desktopRDPObserver, command, strings.NewReader(account.password+"\n"))
		client <- outcome{out, err}
	}()
	probe := `uid=$(id -u ` + upn + `) || exit 2; if pgrep -u "$uid" -x openbox >/dev/null; then printf open; fi`
	for call.Err() == nil {
		out, err := machine.probe.run(call, probe, nil)
		if err != nil {
			t.Fatalf("inspect the live Openbox process on %s: %v: %s", machine.name, err, out)
		}
		if string(out) == "open" {
			if !allowed {
				t.Fatalf("XRDP opened a desktop without its assignment on %s", machine.name)
			}
			select {
			case result := <-client:
				t.Fatalf("the permitted FreeRDP connection ended before the desktop opened: %v: %s", result.err, result.output)
			default:
				return time.Since(started), "opened"
			}
		}
		select {
		case result := <-client:
			if allowed {
				t.Fatalf("the permitted FreeRDP client exited during login to %s: %v: %s", machine.name, result.err, result.output)
			}
			log, logErr := machine.probe.run(call, "sudo journalctl --no-pager -o cat --since="+
				quotePairArgument(fmt.Sprintf("@%.6f", guestTime))+" -u xrdp-sesman.service", nil)
			if logErr != nil || !strings.Contains(string(log), account.user.UPN) || !strings.Contains(string(log), "pam_acct_mgmt failed") {
				t.Fatalf("no XRDP account denial was observed on %s: %v: %s; client: %v: %s", machine.name, logErr, log, result.err, result.output)
			}
			return time.Since(started), "denied"
		case <-call.Done():
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatalf("XRDP did not finish the admission attempt for %s: %v", machine.name, call.Err())
	return 0, ""
}

func relayDesktopPairRegion(t *testing.T, ctx context.Context, access desktopPairAPI, worker directoryKVMHosts, guests []lab.GuestStatus) {
	t.Helper()
	_, port, err := net.SplitHostPort(access.api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var sshPort int
	for _, guest := range guests {
		if guest.Guest.Name == desktopRDPObserver && guest.Running {
			sshPort = guest.SSHPort
			break
		}
	}
	if sshPort == 0 {
		t.Fatal("the desktop pair requires the private observer guest")
	}
	tunnelCtx, cancel := context.WithCancel(ctx)
	ssh := exec.CommandContext(tunnelCtx, "ssh", "-N", "-p", strconv.Itoa(sshPort), "-i", filepath.Join(worker.state, "ssh-key"),
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
		"-o", "UserKnownHostsFile="+filepath.Join(worker.state, "known-hosts"), "-o", "HostKeyAlias="+desktopRDPObserver,
		"-R", "127.0.0.1:"+port+":127.0.0.1:"+port, "ocean@127.0.0.1")
	var diagnostics bytes.Buffer
	ssh.Stderr = &diagnostics
	if err := ssh.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := ssh.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
			t.Errorf("pair API relay: %v: %s", err, diagnostics.String())
		}
	})
	pollVMWorker(t, ctx, 12*time.Second, "the end-to-end TLS relay", func() bool {
		_, err := worker.ssh(ctx, desktopRDPObserver, "nc -z -w 1 127.0.0.1 "+port, nil)
		return err == nil
	})
	unit := worker.directory + "-pair-api"
	worker.run(ctx, desktopRDPObserver, "sudo systemd-run --quiet --collect --unit="+unit+
		" /usr/bin/socat TCP-LISTEN:"+port+",bind="+pairObserverIP+",reuseaddr,fork TCP:127.0.0.1:"+port, nil)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 7*time.Second)
		defer stop()
		worker.run(cleanup, desktopRDPObserver, "sudo systemctl stop "+unit, nil)
	})
}
