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

func TestHostedDirectoryOffboarding(t *testing.T) {
	state, image := os.Getenv("OCEAN_E2E_PACKAGED_DIRECTORY_STATE"), os.Getenv("OCEAN_E2E_SAMBA_IMAGE")
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if state == "" || image == "" || archive == "" || cli == "" {
		t.Skip("requires the disposable three-node Samba lab, pinned image, etcd archive and stock Azure CLI")
	}
	if digest, ok := strings.CutPrefix(image, "sha256:"); !ok || !directoryLabDigest(digest) {
		t.Fatal("use a pinned Samba image ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := workspace.Status()
	if err != nil || len(nodes) != 3 || nodes[2].Guest.Name != packagedDirectoryClient {
		t.Fatalf("read the disposable three-node directory lab: %v", err)
	}
	for _, node := range nodes {
		if !node.Running {
			t.Fatalf("the lab guest %s is powered off", node.Guest.Name)
		}
	}
	worker := directoryKVMHosts{root: root, state: state, directory: "hosted-directory-" + operationID()[:12], t: t}
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-directory")
	controller := true
	cfg.OperationController = &controller
	cfg.ManagedDirectories = &enrollment.Capacity{CPUMillis: 600, MemoryMiB: 704}
	r := openHostedLabRegion(t, ctx, cfg)
	tenant, subnet := seedDirectoryTenantNetwork(t, ctx, r, "Hosted directory fixture")
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, scope.TenantID)
	approvals := hostedLabInventory(cfg)
	for i, approval := range approvals {
		for _, nic := range nodes[i].Guest.Interfaces {
			if nic.Name == "mgmt0" {
				approval.MAC, approval.Address, approval.Profile = nic.MAC, nic.Address.Addr().String(), "debian-13"
				approval.MinimumMemoryMiB = 832
			}
		}
		approvals[i] = approval
	}
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate(), approvals...)
	type enrolledController struct {
		guest string
		cert  []byte
	}
	agents := make(map[string]enrolledController)
	runtimes := make(map[string]string)
	t.Cleanup(func() {
		for guest, name := range runtimes {
			cleanupHostedDirectoryRuntime(t, worker, guest, name)
		}
	})
	for i, approval := range approvals {
		path, cert := identityFor(approval.HostID)
		registerNamedHostedLabWorker(t, ctx, r, approval.HostID, cert)
		guest := nodes[i].Guest.Name
		stageHostedDirectoryWorker(t, ctx, worker, guest, path, image)
		agents[approval.HostID] = enrolledController{guest: guest, cert: cert}
	}
	const domain = "ad.hosted.test"
	dirPath := "/ocean/tenants/" + scope.TenantID + "/directory?api-version=2026-11-01"
	tenantCall := func(method, body, expected string) []byte {
		t.Helper()
		return az(method, dirPath, body, sign(tenant.TenantID, operatorClient, tenant.Administrator, origin), expected)
	}
	request, err := json.Marshal(identity.DirectorySpec{DNSName: domain, NetBIOSName: "OCEANHOSTED", SubnetID: subnet})
	if err != nil {
		t.Fatal(err)
	}
	tenantCall("put", string(request), "")
	var ready identity.ManagedDirectory
	pollVMWorker(t, ctx, 2*time.Minute, "both hosted Samba controllers to become ready", func() bool {
		result, err := r.LookupManagedDirectory(ctx, tenant)
		if err == nil && result != nil && len(result.Controllers) == 2 && result.Controllers[0].Ready && result.Controllers[1].Ready && !result.ProvisionedAt.IsZero() {
			ready = *result
			return true
		}
		return false
	})
	placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
	rows, err := r.client.Get(ctx, placementKey)
	var placement directoryPlacement
	if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placement) != nil || placement.DirectoryID != ready.ID ||
		placement.Controllers[0].HostID == placement.Controllers[1].HostID {
		t.Fatalf("read the distinct hosted Samba controller placements: %v", err)
	}
	password, err := r.workloads.sealer.Open(nil, nil, placement.Bootstrap, placement.bootstrapLabel(placementKey))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	readyChecksums := [2]string{}
	for i, controller := range placement.Controllers {
		agent := agents[controller.HostID]
		if agent.guest == "" {
			t.Fatal("the directory used a host outside this fixture")
		}
		runtime := hostedDirectoryRuntime(scope, controller)
		runtimes[agent.guest] = runtime
		readiness := ready.Controllers[i]
		readyChecksums[i] = worker.probePackagedDirectory(ctx, readiness.DNSName, readiness.PrivateIPv4.String(), domain, password).PolicySHA256
		if err := r.ReportDirectorySuspension(ctx, controller.HostID, agent.cert, scope.TenantID, controller.Generation); !errors.Is(err, enrollment.ErrDirectoryAssignmentChanged) {
			t.Fatalf("an active directory accepted a suspension receipt: %v", err)
		}
		worker.run(ctx, agent.guest, packagedDirectoryWorker+"worker systemctl --user kill --signal=STOP --kill-whom=main "+worker.directory+"-agent.service", nil)
	}
	if readyChecksums[0] != readyChecksums[1] {
		t.Fatal("the two native clients retrieved different SYSVOL policy files")
	}
	started := time.Now()
	offboard := "/ocean/tenants/" + scope.TenantID + "/offboarding?api-version=2026-11-01"
	az("put", offboard, fmt.Sprintf(`{"subscriptionId":%q}`, scope.SubscriptionID), sign(operatorRealm, operatorClient, operator, origin), "")
	tenantCall("get", "", "InvalidAuthenticationToken")
	for i, controller := range placement.Controllers {
		agent := agents[controller.HostID]
		if old, err := r.HostAssignments(ctx, controller.HostID, agent.cert, "", false); err != nil || len(old.Assignments) != 0 {
			t.Fatalf("the network or legacy worker retained a suspended task: %v", err)
		}
		page, err := r.HostAssignments(ctx, controller.HostID, agent.cert, "", true)
		if err != nil || len(page.Assignments) != 1 || page.Assignments[0] != (enrollment.Assignment{ID: controller.ID, Generation: controller.Generation,
			TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, DirectorySuspended: true}) {
			t.Fatalf("the worker did not receive its exact withdrawal task: %v", err)
		}
		if _, err := r.HostDirectoryBootstrap(ctx, controller.HostID, agent.cert, scope.TenantID, controller.Generation); !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatalf("a suspended controller could request a bootstrap secret: %v", err)
		}
		other := placement.Controllers[1-i]
		if err := r.ReportDirectorySuspension(ctx, controller.HostID, agent.cert, scope.TenantID, other.Generation); !errors.Is(err, enrollment.ErrHostDenied) {
			t.Fatalf("a host could acknowledge its peer's controller: %v", err)
		}
		key := r.hostedDirectoryReceiptKey(scope, controller.Generation)
		if receipt, err := r.client.Get(ctx, key, clientv3.WithCountOnly()); err != nil || receipt.Count != 0 {
			t.Fatalf("recorded a controller receipt before the agent resumed: %v", err)
		}
	}
	for _, agent := range agents {
		worker.run(ctx, agent.guest, packagedDirectoryWorker+"worker systemctl --user kill --signal=CONT --kill-whom=main "+worker.directory+"-agent.service", nil)
	}
	pollVMWorker(t, ctx, 55*time.Second, "both certified Samba controller withdrawals", func() bool {
		for _, controller := range placement.Controllers {
			rows, err := r.client.Get(ctx, r.hostedDirectoryReceiptKey(scope, controller.Generation))
			if err != nil || len(rows.Kvs) != 1 || string(rows.Kvs[0].Value) != controller.HostID {
				return false
			}
		}
		return true
	})
	elapsed := time.Since(started)
	for _, controller := range placement.Controllers {
		agent := agents[controller.HostID]
		runtime := hostedDirectoryRuntime(scope, controller)
		worker.run(ctx, agent.guest, "set -eu\n"+packagedDirectoryWorker+`
name=`+runtime+`
if worker podman container exists "$name" || worker podman container exists "$name-restore"; then exit 1; fi
if worker podman secret inspect "$name" >/dev/null 2>&1; then exit 1; fi
test ! -e "/run/ocean-workload-network/$name.ready"
test ! -e "/run/ocean-workload-network/$name.network"
volume=$(worker podman volume inspect --format '{{.Mountpoint}}' "$name")
worker podman unshare test -s "$volume/controller.json"
`, nil)
		verifyHostedDirectoryBlocked(ctx, worker, domain, controller.PrivateIPv4.String(), password)
		if err := r.ReportDirectorySuspension(ctx, controller.HostID, agent.cert, scope.TenantID, controller.Generation); err != nil {
			t.Fatalf("the certified withdrawal could not be retried: %v", err)
		}
	}
	verifyHostedDirectoryAudit(t, ctx, r, scope, placement)
	t.Logf("Both native Samba controllers were withdrawn and attested after %d ms. Fresh Kerberos, LDAP, DNS and SYSVOL access failed, and both directory volumes were retained.", elapsed.Milliseconds())
}

func hostedDirectoryRuntime(scope arm.SubscriptionScope, controller Reservation) string {
	hash := sha256.Sum256([]byte(scope.TenantID + "/" + scope.SubscriptionID + "/" + controller.ID + "/" + controller.Generation))
	return fmt.Sprintf("ocean-%x", hash[:16])
}

func stageHostedDirectoryWorker(t *testing.T, ctx context.Context, worker directoryKVMHosts, guest, localConfig, image string) {
	t.Helper()
	remote := "/var/tmp/" + worker.directory
	agent, network := worker.directory+"-agent.service", worker.directory+"-network.service"
	run := func(command string, input io.Reader) { worker.run(ctx, guest, "cd /\n"+command, input) }
	run("set -eu\n"+packagedDirectoryWorker+`
worker podman image exists `+image+`
test -z "$(worker podman ps -q --filter label=ocean.directory-controller)"
sudo test -f /etc/ocean-agent/config.json
sudo test -f /etc/ocean-agent/workload-network.json
sudo install -d -m 0755 `+remote+`
sudo install -d -o ocean-agent -g ocean-agent -m 0700 `+remote+`/identity
if worker systemctl --user is-active --quiet ocean-agent.service; then sudo touch `+remote+`/previous-agent; fi
if sudo systemctl is-active --quiet ocean-container-network.service; then sudo touch `+remote+`/previous-network; fi
worker systemctl --user stop ocean-agent.service
sudo systemctl stop ocean-container-network.service
`, nil)
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 40*time.Second)
		defer stop()
		if t.Failed() {
			out, _ := worker.ssh(clean, guest, packagedDirectoryWorker+"sudo journalctl _UID=\"$uid\" _SYSTEMD_USER_UNIT="+agent+" --no-pager -n 12\nsudo journalctl -u "+network+" --no-pager -n 12", nil)
			t.Logf("hosted directory worker %s:\n%s", guest, out)
		}
		script := "set -eu\n" + packagedDirectoryWorker +
			"if test \"$(worker systemctl --user show -P LoadState " + agent + ")\" = loaded; then " +
			"worker systemctl --user kill --signal=CONT --kill-whom=main " + agent + " || true; worker systemctl --user stop " + agent + "; fi\n" +
			"if test \"$(sudo systemctl show -P LoadState " + network + ")\" = loaded; then sudo systemctl stop " + network + "; fi\n" +
			"if sudo test -f " + remote + "/previous-network; then sudo systemctl start ocean-container-network.service; fi\n" +
			"if sudo test -f " + remote + "/previous-agent; then worker systemctl --user start ocean-agent.service; fi\n" +
			"sudo rm -rf -- " + remote
		if out, err := worker.ssh(clean, guest, script, nil); err != nil {
			t.Errorf("restore the directory worker %s: %v: %s", guest, err, out)
		}
	})
	stageHostedVolumeIdentity(t, localConfig, remote, run)
	run(`sudo python3 - `+remote+`/config.json `+image+` <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text())
data['listenAddress'] = '127.0.0.1:19081'
data['enrollment']['managementInterface'] = 'mgmt0'
data['enrollment']['directoryImage'] = sys.argv[2]
path.write_text(json.dumps(data))
PY`, nil)
	for _, binary := range []string{"ocean-agent", "ocean-network-agent"} {
		data, err := os.ReadFile(filepath.Join(worker.root, "bin", binary))
		if err != nil {
			t.Fatal(err)
		}
		run("sudo install -m 0755 /dev/stdin "+remote+"/"+binary, bytes.NewReader(data))
	}
	run("set -eu\n"+packagedDirectoryWorker+
		"worker systemd-run --user --quiet --unit="+agent+" --property=Nice=10 --property=Delegate=yes --property=KillMode=process "+remote+"/ocean-agent -config "+remote+"/config.json\n"+
		"sudo systemd-run --quiet --unit="+network+" --property=Nice=10 --property=KillMode=mixed --property=TimeoutStopSec=12s "+
		"--property=BindReadOnlyPaths="+remote+"/config.json:/etc/ocean-agent/config.json "+remote+"/ocean-network-agent -mode containers", nil)
}

func cleanupHostedDirectoryRuntime(t *testing.T, worker directoryKVMHosts, guest, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := "set -eu\n" + packagedDirectoryWorker + "worker podman rm --force --ignore " + name + " " + name + "-restore\n" +
		"worker podman secret rm --ignore " + name + "\n" +
		"if worker podman volume exists " + name + "; then worker podman volume rm " + name + "; else test \"$?\" -eq 1; fi"
	if out, err := worker.ssh(ctx, guest, command, nil); err != nil {
		t.Errorf("clean the disposable directory runtime on %s: %v: %s", guest, err, out)
	}
}

func verifyHostedDirectoryBlocked(ctx context.Context, worker directoryKVMHosts, domain, address string, password []byte) {
	script := fmt.Sprintf(`set -eu
dir=$(mktemp -d)
trap 'rm -r -- "$dir"' EXIT
export KRB5_CONFIG="$dir/krb5.conf" KRB5CCNAME="FILE:$dir/cache"
realm=%s
address=%s
printf '[libdefaults]\n default_realm = %%s\n dns_lookup_kdc = false\n dns_uri_lookup = false\n[realms]\n %%s = {\n  kdc = %%s\n }\n' "$realm" "$realm" "$address" >"$KRB5_CONFIG"
if timeout 8 kinit "Administrator@$realm" >/dev/null 2>&1; then exit 1; fi
if timeout 3 dig @"$address" +short +time=1 +tries=1 SOA %s | grep -Eq '^[a-zA-Z0-9-]+\.'; then exit 1; fi
for port in 88 389 445; do
	if nc -z -w 1 "$address" "$port"; then exit 1; fi
done
`, strings.ToUpper(domain), address, domain)
	worker.run(ctx, packagedDirectoryClient, script, bytes.NewReader(append(bytes.Clone(password), '\n')))
}

func verifyHostedDirectoryAudit(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, placement directoryPlacement) {
	t.Helper()
	rows, err := r.client.Get(ctx, r.armPrefix(scope)+"audit/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, row := range rows.Kvs {
		var event arm.AuditEvent
		if err := json.Unmarshal(row.Value, &event); err != nil {
			t.Fatal(err)
		}
		if event.Action == "Ocean.Hosted/offboarding/stopDirectoryController" && event.Outcome == workload.Suspended &&
			event.Target == "/ocean/tenants/"+scope.TenantID+"/directory" {
			counts[event.Actor]++
		}
	}
	for _, controller := range placement.Controllers {
		if counts[controller.HostID] != 1 {
			t.Fatalf("expected one attributed directory withdrawal for %s", controller.HostID)
		}
	}
}
