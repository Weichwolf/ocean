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
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Minute)
	defer cancel()
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	const imageURI = "https://images.ocean.test/server-core.vhd"
	r := setupPackagedVMStore(t, endpoint, scope, imageURI)
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
		Inventory: r, Operations: r, Roles: r, VirtualMachines: r, Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			if request.Header.Get("Authorization") != "Bearer vm-worker-lab" {
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Members: []string{"operator"},
			}}, nil
		}}
	api.Config.Handler = authority.Handler(regional.Handler(http.NotFoundHandler()))
	api.StartTLS()
	worker := directoryKVMHosts{root: root, state: state, directory: "vm-worker-" + scope.TenantID[:8], t: t}
	startPackagedVMHost(t, ctx, r, worker, guests, directoryGuestOrigin(t, api), caPEM)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 95*time.Second)
		defer stop()
		if t.Failed() {
			output, _ := worker.ssh(cleanup, vmLabPrimary, "sudo journalctl -u ocean-vm-agent.service --no-pager -n 35", nil)
			t.Logf("packaged VM worker journal: %s", output)
		}
		if output, err := worker.ssh(cleanup, vmLabPrimary, "sudo systemctl stop ocean-vm-agent.service", nil); err != nil {
			t.Errorf("stop packaged worker: %v: %s", err, output)
		}
	}()
	pollVMWorker(t, ctx, 45*time.Second, "the packaged worker to advertise KVM availability", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", vmLabPrimary))
		var status enrollment.Availability
		return err == nil && len(live.Kvs) == 1 && json.Unmarshal(live.Kvs[0].Value, &status) == nil && status.VMRuntime
	})
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
	az := vmWorkerCLI(t, ctx, api.URL, caFile)
	image, nic, vm := address(arm.VMImageType, "core"), address(arm.VMNetworkInterfaceType, "primary"), address(arm.VirtualMachineType, "server-core")
	az("put", image.ID(scope)+"?api-version="+arm.VMImageAPIVersion, fmt.Sprintf(`{"location":"local","properties":{"hyperVGeneration":"V2","storageProfile":{"osDisk":{"osType":"Windows","osState":"Specialized","blobUri":%q}}}}`, imageURI))
	az("put", nic.ID(scope)+"?api-version="+arm.VMNetworkAPIVersion,
		fmt.Sprintf(`{"location":"local","properties":{"ipConfigurations":[{"name":"primary","properties":{"subnet":{"id":%q},"privateIPAllocationMethod":"Dynamic"}}]}}`, subnet.ID(scope)))
	url := vm.ID(scope) + "?api-version=" + arm.VirtualMachineAPIVersion
	input := fmt.Sprintf(`{"location":"local","properties":{"hardwareProfile":{"vmSize":"Standard_B2s"},"storageProfile":{"imageReference":{"id":%q},"osDisk":{"name":"boot-disk","createOption":"FromImage","deleteOption":"Delete","managedDisk":{"storageAccountType":"Standard_LRS"}}},"networkProfile":{"networkInterfaces":[{"id":%q}]}}}`,
		image.ID(scope), nic.ID(scope))
	createdAt := time.Now()
	az("put", url, input)
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
	worker.run(ctx, vmLabPrimary, "set -eu\nsudo systemctl is-active ocean-vm-agent.service\n"+
		"pid=$(pgrep -u ocean-vm -f 'qemu-system-x86_64.*ocean-"+vmID+"-')\n"+
		"test \"$(ps -p \"$pid\" -o ni= | tr -d ' ')\" = 10\n"+
		"sudo nsenter -t \"$pid\" -n ip -o link show ocean0", nil)
	checkObserved := func(observed string) bool {
		_, record, op, _, _, err := r.readVM(ctx, scope, vm)
		return err == nil && op != nil && op.Status == arm.OperationSucceeded && record.Observed == observed && record.MachineID == vmID
	}
	az("post", vm.ID(scope)+"/powerOff?api-version="+arm.VirtualMachineAPIVersion, "")
	pollVMWorker(t, ctx, 95*time.Second, "the packaged worker to stop and detach the Windows guest", func() bool { return checkObserved(workload.Stopped) })
	assertPower("stopped")
	restart := time.Now()
	az("post", vm.ID(scope)+"/start?api-version="+arm.VirtualMachineAPIVersion, "")
	pollVMWorker(t, ctx, 2*time.Minute, "Windows to restart from the same disk and private address", func() bool { return checkObserved(workload.Running) })
	assertPower("running")
	t.Logf("Windows preserved the machine ID and private address on restart after %s", time.Since(restart).Round(time.Millisecond))
	az("delete", url, "")
	pollVMWorker(t, ctx, 95*time.Second, "VM removal and confirmed disk quota release", func() bool {
		_, _, op, _, _, err := r.readVM(ctx, scope, vm)
		return err == nil && op == nil
	})
	az("delete", nic.ID(scope)+"?api-version="+arm.VMNetworkAPIVersion, "")
	az("delete", image.ID(scope)+"?api-version="+arm.VMImageAPIVersion, "")
	t.Log("the packaged worker completed all observed VM lifecycle operations requested through stock az rest")
}

func setupPackagedVMStore(t *testing.T, endpoint string, scope arm.SubscriptionScope, uri string) *Region {
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
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &Region{client: client, root: "/test/vm-worker/" + operationID(), name: "local", cell: "cell-1",
		workloads: &workloadControl{defaultPlacement: PlacementPolicy{Pools: []string{"lab"}, Quota: enrollment.Capacity{CPUMillis: 2000, MemoryMiB: 4096}}},
		storage:   &storageControl{sealer: sealer, workers: []string{vmLabPrimary}, fencer: publicKey}}
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

func startPackagedVMHost(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, guests []lab.GuestStatus, origin string, ca []byte) {
	t.Helper()
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	var approved enrollment.Approval
	for _, guest := range guests {
		if guest.Guest.Name != vmLabPrimary || !guest.Running {
			continue
		}
		for _, link := range guest.Guest.Interfaces {
			if link.Name == "mgmt0" {
				approved = enrollment.Approval{HostID: vmLabPrimary, MAC: link.MAC, Address: link.Address.Addr().String(), Profile: "debian-13",
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
		"origin": origin, "hostId": vmLabPrimary, "managementInterface": "mgmt0", "caFile": settings + "vm-lab-ca.pem",
		"tokenFile": directory + "/join-token", "stateDirectory": directory,
	}})
	worker.run(ctx, vmLabPrimary, "sudo install -d -o ocean-agent -g ocean-agent -m 0700 "+directory, nil)
	for name, value := range map[string][]byte{"config.json": data, "vm-lab-ca.pem": ca} {
		worker.run(ctx, vmLabPrimary, "sudo tee "+settings+name+" >/dev/null", bytes.NewReader(value))
	}
	worker.run(ctx, vmLabPrimary, "sudo -u ocean-agent sh -c 'umask 077; cat >"+directory+"/join-token'", strings.NewReader(token))
	worker.run(ctx, vmLabPrimary, "set -eu\n"+packagedDirectoryWorker+`
sudo loginctl enable-linger ocean-agent
sudo systemctl start "user@$uid.service"
worker systemctl --user daemon-reload
worker systemctl --user restart ocean-agent.service
sudo systemctl daemon-reload
sudo systemctl start ocean-vm-agent.service`, nil)
}

func vmWorkerCLI(t *testing.T, ctx context.Context, origin, caFile string) func(string, string, string) []byte {
	t.Helper()
	az := os.Getenv("OCEAN_E2E_VM_AZ")
	if az == "" {
		t.Fatal("the packaged VM worker test requires the pinned Azure CLI")
	}
	configDir := t.TempDir()
	return func(method, path, body string) []byte {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", origin + path, "--skip-authorization-header", "--headers",
			"Authorization=Bearer vm-worker-lab", "--only-show-errors", "--output", "json"}
		if body != "" {
			args = append(args, "--body", body)
		}
		command := exec.CommandContext(ctx, az, args...)
		command.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+configDir, "REQUESTS_CA_BUNDLE="+caFile, "AZURE_CORE_COLLECT_TELEMETRY=no")
		output, err := command.CombinedOutput()
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
