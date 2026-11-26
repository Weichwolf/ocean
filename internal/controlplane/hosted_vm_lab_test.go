//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedVMLabStorage = "rbd --conf /etc/ocean-agent/ceph.conf --id ocean-vm-worker-lab --keyring /etc/ocean-agent/ceph.key"

func TestHostedVMOffboarding(t *testing.T) {
	state, archive, cli := os.Getenv("OCEAN_E2E_VM_LINUX_STATE"), os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if state == "" || archive == "" || cli == "" || os.Getenv("OCEAN_E2E_VM_LINUX_DISK_PIN") == "" || os.Getenv("OCEAN_E2E_VM_LINUX_VARS_PIN") == "" {
		t.Skip("requires the packaged Debian VM lab, pinned image, etcd archive and stock Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
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
	branch := "hosted-vm-" + operationID()[:12]
	worker := directoryKVMHosts{root: root, state: state, directory: branch, t: t}
	probe := packagedDesktopSSH(t, state, guests)
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	catalog := vmCatalogImage{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, URI: "https://images.ocean.test/debian-desktop.raw", SizeGiB: 8,
		OSType: workload.VMLinux, ImageSHA256: os.Getenv("OCEAN_E2E_VM_LINUX_DISK_PIN"), FirmwareSHA256: os.Getenv("OCEAN_E2E_VM_LINUX_VARS_PIN")}
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-vm")
	secret, public := hostedSMBTestFencer(t)
	clear(secret)
	cfg.Storage.FencePublicKeyFile = public
	cfg.VirtualMachines = &vmConfig{Images: []vmCatalogImage{catalog}}
	r := openHostedLabRegion(t, ctx, cfg)
	seedHostedLabTenant(t, ctx, r, tenant)
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, scope.TenantID)
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate())
	localConfig, cert := identityFor(hostedSuspensionHost)
	host := registerHostedOffboardingWorker(t, ctx, r, cert)
	lease, err := r.client.Grant(ctx, 480)
	if err != nil {
		t.Fatal(err)
	}
	available := enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles,
		Capacity: enrollment.Capacity{CPUMillis: 3000, MemoryMiB: 6144}, VMRuntime: true}
	availability, err := json.Marshal(available)
	if err != nil {
		t.Fatal(err)
	}
	key := r.hostKey("live", host.HostID)
	if _, err := r.client.Put(ctx, key, string(availability), clientv3.WithLease(lease.ID)); err != nil {
		t.Fatal(err)
	}
	var disk string
	t.Cleanup(func() {
		if disk == "" {
			return
		}
		clean, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		image := "ocean/" + disk
		if out, err := worker.ssh(clean, vmLabPrimary, "if sudo "+hostedVMLabStorage+" info "+image+" >/dev/null 2>&1; then sudo "+hostedVMLabStorage+" rm "+image+"; fi", nil); err != nil {
			t.Errorf("clean the disposable VM image: %v: %s", err, out)
		}
	})
	unit := stageHostedVMWorker(t, ctx, worker, localConfig)
	tenantCall := func(method, path, body, expected string) []byte {
		t.Helper()
		return az(method, path, body, sign(tenant.TenantID, operatorClient, tenant.Administrator, origin), expected)
	}
	address, url := createHostedVM(t, ctx, r, scope, catalog, tenantCall)
	_, record, _, _, _, err := r.readVM(ctx, scope, address)
	if err != nil || !record.Disk.Valid() {
		t.Fatalf("read the accepted VM disk assignment: %v", err)
	}
	disk = record.Disk.ID
	pollVMWorker(t, ctx, 3*time.Minute, "the hosted VM to boot from encrypted Ceph storage", func() bool {
		_, current, op, _, _, err := r.readVM(ctx, scope, address)
		return err == nil && op != nil && op.Status == arm.OperationSucceeded && current.Observed == workload.Running
	})
	checkpoint := operationID()
	if out, err := probe.run(ctx, "printf %s '"+checkpoint+"' >~/.ocean-hosted-checkpoint && sync ~/.ocean-hosted-checkpoint", nil); err != nil {
		t.Fatalf("write and flush the VM checkpoint: %v: %s", err, out)
	}
	worker.run(ctx, "farm-1-node-07", "nc -z -w 3 10.232.1.20 3389", nil)
	before := readHostedVMTask(t, ctx, r, host.HostID, cert, workload.Running)
	defer clear(before.VolumeKey)
	if len(before.VolumeKey) != storage.KeySize || before.Network == nil || before.Disk.ID != disk {
		t.Fatal("the running assignment did not have its original disk and network")
	}
	worker.run(ctx, vmLabPrimary, "set -eu\npid=$(sudo systemctl show -P MainPID "+unit+")\n"+
		"sudo nsenter -t \"$pid\" -m findmnt -rn --mountpoint /run/ocean-storage/mounts/"+disk+"\n"+
		"sudo test -e /dev/mapper/ocean-"+disk, nil)
	report := workload.VMReport{AssignmentID: before.AssignmentID, State: workload.Suspended, DiskReleased: true}
	if err := r.ReportVirtualMachine(ctx, host.HostID, cert, report); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("an active tenant accepted a suspension report: %v", err)
	}
	worker.run(ctx, vmLabPrimary, "sudo systemctl kill --signal=STOP --kill-whom=main "+unit, nil)
	started := time.Now()
	offboard := "/ocean/tenants/" + tenant.TenantID + "/offboarding?api-version=2026-11-01"
	az("put", offboard, fmt.Sprintf(`{"subscriptionId":%q}`, scope.SubscriptionID), sign(operatorRealm, operatorClient, operator, origin), "")
	tenantCall("get", url, "", "InvalidAuthenticationToken")
	if old, err := r.HostVirtualMachineTasks(ctx, host.HostID, cert, "", false); err != nil || len(old.Tasks) != 0 {
		t.Fatalf("an older worker retained its running task: %v", err)
	}
	withdraw := readHostedVMTask(t, ctx, r, host.HostID, cert, workload.Suspended)
	if withdraw.AssignmentID != before.AssignmentID || withdraw.Disk != before.Disk || len(withdraw.VolumeKey) != 0 || withdraw.Network != nil {
		t.Fatal("withdrawal changed the VM identity or exposed boot material")
	}
	stale := report
	stale.Generation = operationID()
	if err := r.ReportVirtualMachine(ctx, host.HostID, cert, stale); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("accepted a stale VM generation: %v", err)
	}
	attached := report
	attached.DiskReleased = false
	if err := r.ReportVirtualMachine(ctx, host.HostID, cert, attached); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("accepted a suspension report without disk detachment: %v", err)
	}
	if err := r.ReportVirtualMachine(ctx, host.HostID, cert, workload.VMReport{AssignmentID: report.AssignmentID, State: workload.Running}); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("accepted a running VM report after suspension: %v", err)
	}
	if err := r.ReportVirtualMachine(ctx, host.HostID, []byte("foreign certificate"), report); !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("accepted withdrawal with the wrong host identity: %v", err)
	}
	receipt := r.hostedVMReceiptKey(scope, before.AssignmentID)
	if rows, err := r.client.Get(ctx, receipt, clientv3.WithCountOnly()); err != nil || rows.Count != 0 {
		t.Fatalf("recorded shutdown while the agent was paused: %v", err)
	}
	worker.run(ctx, "farm-1-node-07", "nc -z -w 3 10.232.1.20 3389", nil)
	worker.run(ctx, vmLabPrimary, "sudo systemctl kill --signal=CONT --kill-whom=main "+unit, nil)
	pollVMWorker(t, ctx, 45*time.Second, "the certified worker to acknowledge VM shutdown and disk detachment", func() bool {
		rows, err := r.client.Get(ctx, receipt)
		return err == nil && len(rows.Kvs) == 1 && string(rows.Kvs[0].Value) == host.HostID
	})
	elapsed := time.Since(started)
	verifyHostedVMSuspension(t, ctx, r, worker, scope, address, before, host.HostID, unit)
	// Offline inspection uses the test copy of the key. Stop reconciliation so
	// it cannot unmap the temporary read-only device on this same host.
	worker.run(ctx, vmLabPrimary, "sudo systemctl stop "+unit, nil)
	verifyHostedVMCheckpoint(ctx, worker, before, checkpoint)
	t.Logf("The certified VM worker withdrew QEMU, the private interface and the encrypted disk in %d ms. A read-only recovery found the original flushed checkpoint.", elapsed.Milliseconds())
}

func createHostedVM(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, catalog vmCatalogImage,
	az func(string, string, string, string) []byte) (arm.ResourceAddress, string) {
	t.Helper()
	address := func(kind, name string) arm.ResourceAddress {
		return arm.ResourceAddress{Group: "retained-fixture", Path: kind + "/" + name}
	}
	vnet := address("Microsoft.Network/virtualNetworks", "private")
	subnet := arm.ResourceAddress{Group: vnet.Group, Path: vnet.Path + "/subnets/workload"}
	properties := fmt.Sprintf(`{"addressSpace":{"addressPrefixes":["10.232.1.16/28"]},"subnets":[{"name":"workload","id":%q,"properties":{"addressPrefix":"10.232.1.16/28"}}]}`, subnet.ID(scope))
	if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: vnet, Location: r.name, APIVersion: "2025-07-01", Properties: json.RawMessage(properties)}); err != nil {
		t.Fatal(err)
	}
	image, nic, vm := address(arm.VMImageType, "debian"), address(arm.VMNetworkInterfaceType, "primary"), address(arm.VirtualMachineType, "hosted")
	az("put", image.ID(scope)+"?api-version="+arm.VMImageAPIVersion,
		fmt.Sprintf(`{"location":%q,"properties":{"hyperVGeneration":"V2","storageProfile":{"osDisk":{"osType":"Linux","osState":"Specialized","blobUri":%q}}}}`, r.name, catalog.URI), "")
	az("put", nic.ID(scope)+"?api-version="+arm.VMNetworkAPIVersion,
		fmt.Sprintf(`{"location":%q,"properties":{"ipConfigurations":[{"name":"primary","properties":{"subnet":{"id":%q},"privateIPAllocationMethod":"Dynamic"}}]}}`, r.name, subnet.ID(scope)), "")
	url := vm.ID(scope) + "?api-version=" + arm.VirtualMachineAPIVersion
	az("put", url, fmt.Sprintf(`{"location":%q,"properties":{"hardwareProfile":{"vmSize":"Standard_B1s"},"storageProfile":{"imageReference":{"id":%q},"osDisk":{"name":"boot-disk","createOption":"FromImage","deleteOption":"Delete","managedDisk":{"storageAccountType":"Standard_LRS"}}},"networkProfile":{"networkInterfaces":[{"id":%q}]}}}`,
		r.name, image.ID(scope), nic.ID(scope)), "")
	return vm, url
}

func stageHostedVMWorker(t *testing.T, ctx context.Context, worker directoryKVMHosts, localConfig string) string {
	t.Helper()
	remote, unit := "/var/tmp/"+worker.directory, worker.directory+".service"
	run := func(command string, input io.Reader) { worker.run(ctx, vmLabPrimary, command, input) }
	run("set -eu\nsudo test -c /dev/kvm\nsudo test -f /etc/ocean-agent/config.json\n"+
		"sudo test -f /etc/ocean-agent/vm.json\nsudo test ! -e /run/ocean-vm/ready\n"+
		"sudo install -d -m 0755 "+remote+"\nsudo install -d -o ocean-agent -g ocean-agent -m 0700 "+remote+"/identity", nil)
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 115*time.Second)
		defer stop()
		if t.Failed() {
			out, _ := worker.ssh(clean, vmLabPrimary, "sudo journalctl -u "+unit+" --no-pager -n 35", nil)
			t.Logf("hosted VM worker journal:\n%s", out)
		}
		script := "set -eu\nif test \"$(sudo systemctl show -P LoadState " + unit + ")\" = loaded; then " +
			"sudo systemctl kill --signal=CONT --kill-whom=main " + unit + " || true; sudo systemctl stop " + unit + "; fi\nsudo rm -rf -- " + remote
		if out, err := worker.ssh(clean, vmLabPrimary, script, nil); err != nil {
			t.Errorf("stop the disposable VM worker: %v: %s", err, out)
		}
	})
	stageHostedVolumeIdentity(t, localConfig, remote, run)
	bin, err := os.Open(filepath.Join(worker.root, "bin/ocean-network-agent"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bin.Close() }()
	run("sudo install -m 0755 /dev/stdin "+remote+"/agent", bin)
	run("sudo systemd-run --quiet --unit="+unit+" --property=Nice=10 --property=KillMode=mixed --property=TimeoutStopSec=100s "+
		"--property=BindReadOnlyPaths="+remote+"/config.json:/etc/ocean-agent/config.json "+remote+"/agent -mode vm", nil)
	return unit
}

func readHostedVMTask(t *testing.T, ctx context.Context, r *Region, host string, cert []byte, state string) workload.VMTask {
	t.Helper()
	page, err := r.HostVirtualMachineTasks(ctx, host, cert, "", true)
	if err != nil || len(page.Tasks) != 1 || page.Tasks[0].State != state || page.Next != "" {
		t.Fatalf("expect one %s VM task: %v", state, err)
	}
	return page.Tasks[0]
}

func verifyHostedVMSuspension(t *testing.T, ctx context.Context, r *Region, worker directoryKVMHosts, scope arm.SubscriptionScope,
	address arm.ResourceAddress, task workload.VMTask, host, unit string) {
	t.Helper()
	disk := task.Disk.ID
	namespace := fmt.Sprintf("ov%x", sha256.Sum256([]byte(task.MachineID)))[:15]
	worker.run(ctx, vmLabPrimary, "set -eu\npid=$(sudo systemctl show -P MainPID "+unit+")\n"+
		"if pgrep -u ocean-vm -f 'qemu-system-x86_64.*ocean-"+task.MachineID+"-'; then exit 1; fi\n"+
		"sudo nsenter -t \"$pid\" -m test ! -e /run/netns/"+namespace+"\nsudo test ! -e /run/ocean-vm/locals/"+task.MachineID+".json\n"+
		"sudo test ! -e /dev/mapper/ocean-"+disk+"\n"+
		"if sudo nsenter -t \"$pid\" -m findmnt -rn --mountpoint /run/ocean-storage/mounts/"+disk+"; then exit 1; fi\n"+
		"sudo "+hostedVMLabStorage+" device list --format json | python3 -c 'import json, sys; assert all(m[\"name\"] != sys.argv[1] for m in json.load(sys.stdin))' "+disk, nil)
	worker.run(ctx, "farm-1-node-07", "! nc -z -w 2 10.232.1.20 3389", nil)
	_, record, op, _, _, err := r.readVM(ctx, scope, address)
	if err != nil || op == nil || op.ID != task.Revision || record.Reservation.Generation != task.Generation ||
		record.Disk != task.Disk || len(record.Envelope) == 0 || record.Desired != workload.Running {
		t.Fatalf("shutdown unexpectedly changed the VM manifest, disk or operation: %v", err)
	}
	assertPackagedVMQuota(t, ctx, r, scope, record.Reservation.Resources, fmt.Sprint(task.Disk.SizeGiB))
	rows, err := r.client.Get(ctx, r.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	matches := 0
	for _, row := range rows.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(row.Value, &event); err != nil {
			t.Fatal(err)
		}
		if event.Actor == host && event.Target == address.ID(scope) && event.Action == "Ocean.Hosted/offboarding/stopVM" && event.Outcome == workload.Suspended {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("expected one attributed VM shutdown audit event, got %d", matches)
	}
}

func verifyHostedVMCheckpoint(ctx context.Context, worker directoryKVMHosts, task workload.VMTask, checkpoint string) {
	path := "/var/tmp/" + worker.directory
	mapper := "ocean-" + task.Disk.ID + "-verify"
	script := fmt.Sprintf(`set -eu
sudo install -d -m 0700 %[1]s/disk %[1]s/guest
device=$(sudo %[2]s device map --read-only --options ms_mode=secure,lock_timeout=8 ocean/%[3]s)
loop=
cleanup() {
    result=$?
    trap - EXIT
    if mountpoint -q %[1]s/guest; then sudo umount %[1]s/guest || result=1; fi
    if test -n "$loop"; then sudo losetup -d "$loop" || result=1; fi
    if mountpoint -q %[1]s/disk; then sudo umount %[1]s/disk || result=1; fi
    if sudo test -e /dev/mapper/%[4]s; then sudo cryptsetup close %[4]s || result=1; fi
    sudo %[2]s device unmap "$device" || result=1
    exit "$result"
}
trap cleanup EXIT
sudo cryptsetup isLuks --type luks2 "$device"
sudo cryptsetup open --readonly --type luks2 --key-file - "$device" %[4]s
sudo mount -t ext4 -o ro,noload /dev/mapper/%[4]s %[1]s/disk
loop=$(sudo losetup --find --show --read-only --partscan %[1]s/disk/disk.raw)
sudo udevadm settle
partition=$(sudo lsblk -lnpo NAME,FSTYPE "$loop" | awk '$2=="ext4" {print $1}')
sudo test -b "$partition"
sudo mount -t ext4 -o ro,noload "$partition" %[1]s/guest
printf '%%s' '%[5]s' | sudo cmp -s - %[1]s/guest/home/debian/.ocean-hosted-checkpoint
`, path, hostedVMLabStorage, task.Disk.ID, mapper, checkpoint)
	worker.run(ctx, vmLabPrimary, script, bytes.NewReader(task.VolumeKey))
}
