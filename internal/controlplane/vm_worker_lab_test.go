//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const vmLabPrimary = "farm-1-node-05"

func TestPackagedVMWorker(t *testing.T) {
	state, endpoint := os.Getenv("OCEAN_E2E_VM_WORKER_STATE"), os.Getenv("OCEAN_E2E_VM_ETCD")
	if state == "" || endpoint == "" {
		t.Skip("requires a disposable KVM worker lab, pinned prepared image and loopback etcd")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	vmLab, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	guests, err := vmLab.Status()
	if err != nil {
		t.Fatal(err)
	}
	fence := loadPackagedVMFence(t, state)
	ctx, cancel := context.WithTimeout(t.Context(), 22*time.Minute)
	defer cancel()
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	foreignScope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	const imageURI = "https://images.ocean.test/server-core.vhd"
	r := setupPackagedVMStore(t, endpoint, scope, imageURI, fence)
	ca, caKey, _, _ := directoryJoinClientCertificates(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	key, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	configDir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(configDir, name)
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
		Inventory: r, Operations: r, Roles: r, VirtualMachines: r, Storage: r, Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			authenticatedScope := scope
			switch request.Header.Get("Authorization") {
			case "Bearer vm-worker-lab":
			case "Bearer vm-worker-foreign-lab":
				authenticatedScope = foreignScope
			default:
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: authenticatedScope.TenantID, SubscriptionID: authenticatedScope.SubscriptionID, Members: []string{"operator"},
			}}, nil
		}}
	api.Config.Handler = authority.Handler(regional.Handler(http.NotFoundHandler()))
	api.StartTLS()
	worker := directoryKVMHosts{root: root, state: state, directory: "vm-worker-" + scope.TenantID[:8], t: t}
	origin := directoryGuestOrigin(t, api)
	startPackagedVMHost(t, ctx, r, worker, guests, vmLabPrimary, origin, caPEM)
	t.Cleanup(func() { stopPackagedVMHost(t, worker, vmLab, vmLabPrimary) })
	waitPackagedVMHost(t, ctx, r, vmLabPrimary)
	versions, err := worker.ssh(ctx, vmLabPrimary, "dpkg-query -W ocean-agent qemu-system-x86 ovmf ceph-common", nil)
	if err != nil {
		t.Fatalf("read Debian VM runtime versions: %v: %s", err, versions)
	}
	t.Logf("Debian VM runtime packages:\n%s", strings.TrimSpace(string(versions)))
	group := "vm-worker"
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: group, Location: r.name, Tags: map[string]string{}}, "operator"); err != nil {
		t.Fatal(err)
	}
	address := func(kind, name string) arm.ResourceAddress {
		return arm.ResourceAddress{Group: group, Path: kind + "/" + name}
	}
	vnet := address("Microsoft.Network/virtualNetworks", "private")
	subnet := arm.ResourceAddress{Group: group, Path: vnet.Path + "/subnets/workload"}
	properties := fmt.Sprintf(`{"addressSpace":{"addressPrefixes":["10.232.1.16/28"]},"subnets":[{"name":"workload","id":%q,"properties":{"addressPrefix":"10.232.1.16/28"}}]}`, subnet.ID(scope))
	if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: vnet, Location: r.name, APIVersion: "2025-07-01", Properties: json.RawMessage(properties)}); err != nil {
		t.Fatal(err)
	}
	cli := vmWorkerCLI(t, ctx, api.URL, caFile)
	az := func(method, path, body string) []byte { return cli(method, path, body, "vm-worker-lab", "") }
	image, nic, vm := address(arm.VMImageType, "core"), address(arm.VMNetworkInterfaceType, "primary"), address(arm.VirtualMachineType, "server-core")
	imageURL := image.ID(scope) + "?api-version=" + arm.VMImageAPIVersion
	nicURL := nic.ID(scope) + "?api-version=" + arm.VMNetworkAPIVersion
	diskURL := address(arm.VMDiskType, "boot-disk").ID(scope) + "?api-version=" + arm.VMDiskAPIVersion
	az("put", imageURL, fmt.Sprintf(`{"location":"local","properties":{"hyperVGeneration":"V2","storageProfile":{"osDisk":{"osType":"Windows","osState":"Specialized","blobUri":%q}}}}`, imageURI))
	az("put", nicURL,
		fmt.Sprintf(`{"location":"local","properties":{"ipConfigurations":[{"name":"primary","properties":{"subnet":{"id":%q},"privateIPAllocationMethod":"Dynamic"}}]}}`, subnet.ID(scope)))
	url := vm.ID(scope) + "?api-version=" + arm.VirtualMachineAPIVersion
	input := fmt.Sprintf(`{"location":"local","properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},"storageProfile":{"imageReference":{"id":%q},"osDisk":{"name":"boot-disk","createOption":"FromImage","deleteOption":"Delete","managedDisk":{"storageAccountType":"Standard_LRS"}}},"networkProfile":{"networkInterfaces":[{"id":%q}]}}}`,
		image.ID(scope), nic.ID(scope))
	createdAt := time.Now()
	az("put", url, input)
	_, initial, _, _, _, err := r.readVM(ctx, scope, vm)
	if err != nil || initial.MachineID == "" {
		t.Fatalf("the accepted ARM request did not reserve a VM: %v", err)
	}
	az("put", url, input)
	_, replayed, _, _, _, err := r.readVM(ctx, scope, vm)
	if err != nil || initial.MachineID != replayed.MachineID || initial.Creation != replayed.Creation || initial.writer() != replayed.writer() {
		t.Fatalf("replaying the CLI request changed the VM or reservation: %v", err)
	}
	assertPackagedVMQuota(t, ctx, r, scope, enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 4096}, "64")
	var vmID string
	pollVMWorker(t, ctx, 12*time.Minute, "the image to import and the Windows guest to boot with the assigned private IPv4 address", func() bool {
		_, record, operation, _, _, err := r.readVM(ctx, scope, vm)
		if err == nil && operation != nil && operation.Status == arm.OperationSucceeded && record.Observed == workload.Running {
			vmID = record.MachineID
			return true
		}
		return false
	})
	t.Logf("Windows VM responded on its assigned private interface after %s", time.Since(createdAt).Round(time.Millisecond))
	assertPower := func(state string) {
		var instance arm.VMInstanceView
		body := az("get", vm.ID(scope)+"/instanceView?api-version="+arm.VirtualMachineAPIVersion, "")
		if json.Unmarshal(body, &instance) != nil || len(instance.Statuses) != 2 || instance.Statuses[1].Code != "PowerState/"+state {
			t.Fatalf("unexpected VM power state: %s", body)
		}
	}
	assertPower("running")
	for _, path := range []string{imageURL, nicURL, diskURL, url} {
		az("get", path, "")
		cli("get", path, "", "vm-worker-foreign-lab", "SubscriptionNotFound")
		cli("delete", path, "", "vm-worker-foreign-lab", "SubscriptionNotFound")
	}
	worker.run(ctx, vmLabPrimary, "set -eu\nsudo systemctl is-active ocean-vm-agent.service\n"+
		"pid=$(pgrep -u ocean-vm -f 'qemu-system-x86_64.*ocean-"+vmID+"-')\n"+
		"test \"$(ps -p \"$pid\" -o ni= | tr -d ' ')\" = 10\n"+
		"host_sockets=$(sudo ss -H -lntup)\n"+
		"guest_sockets=$(sudo nsenter -t \"$pid\" -n ss -H -lntup)\n"+
		"if printf '%s\\n' \"$host_sockets\" \"$guest_sockets\" | grep -F \"pid=$pid,\"; then exit 1; fi\n"+
		"sudo nsenter -t \"$pid\" -n ip -o link show ocean0", nil)
	checkObserved := func(observed string) bool {
		_, record, op, _, _, err := r.readVM(ctx, scope, vm)
		return err == nil && op != nil && op.Status == arm.OperationSucceeded && record.Observed == observed && record.MachineID == vmID
	}
	stoppedAt := time.Now()
	az("post", vm.ID(scope)+"/powerOff?api-version="+arm.VirtualMachineAPIVersion, "")
	pollVMWorker(t, ctx, 95*time.Second, "the packaged worker to stop and detach the Windows guest", func() bool { return checkObserved(workload.Stopped) })
	assertPower("stopped")
	t.Logf("Windows powered off and released its local disk map after %s", time.Since(stoppedAt).Round(time.Millisecond))
	assertPackagedVMQuota(t, ctx, r, scope, enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 4096}, "64")
	restart := time.Now()
	az("post", vm.ID(scope)+"/start?api-version="+arm.VirtualMachineAPIVersion, "")
	pollVMWorker(t, ctx, 2*time.Minute, "Windows to restart from the same disk and private address", func() bool { return checkObserved(workload.Running) })
	assertPower("running")
	t.Logf("Windows preserved the machine ID and private address on restart after %s", time.Since(restart).Round(time.Millisecond))
	if fence != nil {
		startPackagedVMHost(t, ctx, r, worker, guests, vmLabSpare, origin, caPEM)
		t.Cleanup(func() { stopPackagedVMHost(t, worker, vmLab, vmLabSpare) })
		waitPackagedVMHost(t, ctx, r, vmLabSpare)
		fence.verify(t, ctx, vmLab, worker, r, api, scope, vm)
		assertPower("running")
	}
	deletedAt := time.Now()
	az("delete", url, "")
	pollVMWorker(t, ctx, 95*time.Second, "VM removal and confirmed disk quota release", func() bool {
		_, _, op, _, _, err := r.readVM(ctx, scope, vm)
		return err == nil && op == nil
	})
	assertPackagedVMQuota(t, ctx, r, scope, enrollment.Capacity{}, "0")
	t.Logf("VM deletion released its disk and quota after %s", time.Since(deletedAt).Round(time.Millisecond))
	az("delete", nicURL, "")
	az("delete", imageURL, "")
	t.Log("the packaged worker completed all observed VM lifecycle operations requested through stock az rest")
}

func setupPackagedVMStore(t *testing.T, endpoint string, scope arm.SubscriptionScope, uri string, fence *packagedVMFence) *Region {
	t.Helper()
	if !strings.HasPrefix(endpoint, "http://127.0.0.1:") {
		t.Fatal("the VM worker test requires disposable loopback etcd")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	var publicKey ed25519.PublicKey
	workers := []string{vmLabPrimary}
	if fence != nil {
		publicKey, workers = fence.fencer, append(workers, vmLabSpare)
	}
	r := &Region{client: client, root: "/test/vm-worker/" + operationID(), name: "local", cell: "cell-1",
		workloads: &workloadControl{defaultPlacement: PlacementPolicy{Pools: []string{"lab"}, Quota: enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 4096}}},
		storage:   &storageControl{sealer: sealer, workers: workers, fencer: publicKey}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, err := client.Delete(ctx, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
		_ = client.Close()
	})
	if _, err := client.Put(t.Context(), r.root+"/cells/"+r.cell+"/metadata", "{}"); err != nil {
		t.Fatal(err)
	}
	r.vms, err = openVMControl(&vmConfig{Images: []vmCatalogImage{{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		URI: uri, SizeGiB: 64, ImageSHA256: os.Getenv("OCEAN_E2E_VM_DISK_PIN"), FirmwareSHA256: os.Getenv("OCEAN_E2E_VM_VARS_PIN")}}}, r.workloads, r.storage)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func startPackagedVMHost(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, guests []lab.GuestStatus, host, origin string, ca []byte) {
	t.Helper()
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	var approved enrollment.Approval
	for _, guest := range guests {
		if guest.Guest.Name != host || !guest.Running {
			continue
		}
		for _, link := range guest.Guest.Interfaces {
			if link.Name == "mgmt0" {
				approved = enrollment.Approval{HostID: host, MAC: link.MAC, Address: link.Address.Addr().String(), Profile: "debian-13",
					Cell: r.cell, Pool: "lab", Roles: []string{"compute"}, MinimumCPU: 3, MinimumMemoryMiB: 5120, RequireKVM: true,
					TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), ExpiresAt: time.Now().Add(time.Hour).UTC()}
			}
		}
	}
	if !approved.Valid() {
		t.Fatal("the packaged VM test requires the qualified lab compute guest")
	}
	if err := r.seedHostInventory(ctx, []enrollment.Approval{approved}); err != nil {
		t.Fatal(err)
	}
	directory := "/var/lib/ocean-agent/" + worker.directory
	const settings = "/etc/ocean-agent/"
	data, _ := json.Marshal(map[string]any{"listenAddress": "127.0.0.1:8081", "enrollment": map[string]string{
		"origin": origin, "hostId": host, "managementInterface": "mgmt0", "caFile": settings + "vm-lab-ca.pem",
		"tokenFile": directory + "/join-token", "stateDirectory": directory,
	}})
	worker.run(ctx, host, "sudo install -d -o ocean-agent -g ocean-agent -m 0700 "+directory, nil)
	for name, value := range map[string][]byte{"config.json": data, "vm-lab-ca.pem": ca} {
		worker.run(ctx, host, "sudo tee "+settings+name+" >/dev/null", bytes.NewReader(value))
	}
	worker.run(ctx, host, "sudo -u ocean-agent sh -c 'umask 077; cat >"+directory+"/join-token'", strings.NewReader(token))
	worker.run(ctx, host, "set -eu\n"+packagedDirectoryWorker+`
sudo loginctl enable-linger ocean-agent
sudo systemctl start "user@$uid.service"
worker systemctl --user daemon-reload
worker systemctl --user restart ocean-agent.service
sudo systemctl daemon-reload
sudo systemctl start ocean-vm-agent.service`, nil)
}

func waitPackagedVMHost(t *testing.T, ctx context.Context, r *Region, host string) {
	t.Helper()
	pollVMWorker(t, ctx, 60*time.Second, host+" to advertise KVM availability", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", host))
		var status enrollment.Availability
		return err == nil && len(live.Kvs) == 1 && json.Unmarshal(live.Kvs[0].Value, &status) == nil && status.VMRuntime
	})
}

func stopPackagedVMHost(t *testing.T, worker directoryKVMHosts, vmLab *lab.Lab, host string) {
	t.Helper()
	states, err := vmLab.Status()
	if err != nil {
		t.Error(err)
		return
	}
	for _, state := range states {
		if state.Guest.Name != host || !state.Running {
			continue
		}
		cleanup, stop := context.WithTimeout(context.Background(), 105*time.Second)
		defer stop()
		if t.Failed() {
			output, _ := worker.ssh(cleanup, host, "sudo journalctl -u ocean-vm-agent.service --no-pager -n 35", nil)
			t.Logf("packaged VM worker %s journal: %s", host, output)
		}
		if output, err := worker.ssh(cleanup, host, "sudo systemctl stop ocean-vm-agent.service", nil); err != nil {
			t.Errorf("stop packaged worker %s: %v: %s", host, err, output)
		}
	}
}

func assertPackagedVMQuota(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, capacity enrollment.Capacity, diskGiB string) {
	t.Helper()
	usage, err := r.counter(ctx, r.armPrefix(scope)+"placement-usage")
	if err != nil || usage.used != capacity {
		t.Fatalf("incorrect VM CPU or memory quota usage: %+v: %v", usage.used, err)
	}
	disk, err := r.client.Get(ctx, r.armPrefix(scope)+"vm-disk-usage-gib")
	if err != nil || len(disk.Kvs) != 1 || string(disk.Kvs[0].Value) != diskGiB {
		t.Fatalf("incorrect VM disk quota usage, expected %s GiB: %v", diskGiB, err)
	}
}

func vmWorkerCLI(t *testing.T, ctx context.Context, origin, caFile string) func(string, string, string, string, string) []byte {
	t.Helper()
	az := os.Getenv("OCEAN_E2E_VM_AZ")
	if az == "" {
		t.Fatal("the packaged VM worker test requires the pinned Azure CLI")
	}
	configDir := t.TempDir()
	environment := append(os.Environ(), "AZURE_CONFIG_DIR="+configDir, "REQUESTS_CA_BUNDLE="+caFile, "AZURE_CORE_COLLECT_TELEMETRY=no")
	version := exec.CommandContext(ctx, az, "version", "--query", `"azure-cli"`, "--output", "tsv")
	version.Env = environment
	if output, err := version.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "2.93.0" {
		t.Fatalf("the VM test requires Azure CLI 2.93.0: %v: %s", err, output)
	}
	return func(method, path, body, token, expectedError string) []byte {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", origin + path, "--skip-authorization-header", "--headers",
			"Authorization=Bearer " + token, "--only-show-errors", "--output", "json"}
		if body != "" {
			args = append(args, "--body", body)
		}
		command := exec.CommandContext(ctx, az, args...)
		command.Env = environment
		output, err := command.CombinedOutput()
		if expectedError != "" {
			if err == nil || !bytes.Contains(output, []byte(expectedError)) {
				t.Fatalf("az rest %s expected %s: %v: %s", method, expectedError, err, output)
			}
			return output
		}
		if err != nil {
			t.Fatalf("az rest %s failed: %v: %s", method, err, output)
		}
		return output
	}
}

func pollVMWorker(t *testing.T, ctx context.Context, timeout time.Duration, description string, probe func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for ctx.Err() == nil {
		if probe() {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("timed out waiting for %s", description)
	}
	t.Fatalf("canceled while waiting for %s", description)
}
