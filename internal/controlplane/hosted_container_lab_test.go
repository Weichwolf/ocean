//go:build e2e

package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/nodeagent"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const hostedSuspensionHost = "worker-a"

func TestHostedContainerOffboarding(t *testing.T) {
	archive := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	cli := os.Getenv("OCEAN_E2E_HOSTED_AZ")
	image := os.Getenv("OCEAN_E2E_HOSTED_PODMAN_IMAGE")
	if archive == "" || cli == "" || image == "" {
		t.Skip("requires the pinned etcd archive, stock Azure CLI and a local Debian container image")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 95*time.Second)
	defer cancel()
	if err := nodeagent.CheckRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	base, cert, certKey, etcd, _ := prepareSMBRecoveryEtcd(t, ctx, archive, dir)
	regional, _, _ := startSMBRecoveryEtcd(t, ctx, base, cert, certKey, etcd, filepath.Join(dir, "region"), nil)
	ledger, id, _ := startSMBRecoveryEtcd(t, ctx, base, cert, certKey, etcd, filepath.Join(dir, "ledger"), nil)
	wrapping := filepath.Join(dir, "wrap.key")
	key := make([]byte, storage.KeySize)
	rand.Read(key)
	if err := os.WriteFile(wrapping, key, 0600); err != nil {
		t.Fatal(err)
	}
	clear(key)
	cfg := regionConfig{Name: "hosted-container", InitialCell: "cell-1", Etcd: regional, DeletionLedgerEtcd: &ledger,
		HostedWorkplace: &hostedRegionPolicy{Country: "DE", OperatorPools: map[string]string{"primary": "DE"},
			DeletionLedger: &hostedLedgerPolicy{OperatorPool: "primary", ClusterID: fmt.Sprintf("%x", id), Endpoints: ledger.Endpoints}},
		Workloads: &workloadConfig{SecretsKeyFile: wrapping, DefaultPlacement: PlacementPolicy{Pools: []string{"primary"},
			Quota: enrollment.Capacity{CPUMillis: 4000, MemoryMiB: 2048}}},
		Storage: &storageConfig{KeyFile: wrapping, Workers: []string{hostedSuspensionHost, "worker-b"}}}
	r, err := openRegion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.close() }()
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	tenant, neighbor := seedHostedRestoreTenant(t, ctx, r), seedHostedRestoreTenant(t, ctx, r)
	if tenant.TenantID > neighbor.TenantID {
		tenant, neighbor = neighbor, tenant
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	neighborScope := arm.SubscriptionScope{TenantID: neighbor.TenantID, SubscriptionID: neighbor.SubscriptionID}
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.TenantID, neighbor.TenantID)
	origin, _, az, identityFor := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate())
	agentConfig, hostCert := identityFor(hostedSuspensionHost)
	host := seedHostedPlacementWorker(t, ctx, r, hostedSuspensionHost, "primary")
	host.Certificate = hostCert
	if _, err := r.client.Do(ctx, putJSON(r.hostKey("registered", host.HostID), host)); err != nil {
		t.Fatal(err)
	}

	var names []string
	var records []containerRecord
	for i := range 17 {
		kind := workload.ContainerGroupType
		if i == 0 {
			kind = functions.SiteType
		}
		record := seedHostedContainer(t, ctx, r, scope, tenant.Administrator, kind, i)
		records = append(records, record)
		name := hostedContainerName(scope, record)
		names = append(names, name)
		runHostedContainer(t, ctx, image, name)
	}
	functionName := names[0]
	for _, suffix := range []string{"-telemetry", "-storage"} {
		runHostedContainer(t, ctx, image, functionName+suffix)
		names = append(names, functionName+suffix)
	}
	otherName := hostedContainerName(neighborScope, seedHostedContainer(t, ctx, r, neighborScope, neighbor.Administrator, workload.ContainerGroupType, 0))
	runHostedContainer(t, ctx, image, otherName)
	volume := records[0].Volume.ID
	mounts, err := r.HostVolumeMounts(ctx, host.HostID, host.Certificate)
	if err != nil || len(mounts) != 1 || len(mounts[0].VolumeKey) != storage.KeySize || mounts[0].Remove {
		t.Fatalf("active host volume authorization is unavailable: %v", err)
	}
	clear(mounts[0].VolumeKey)
	record := records[0]
	report := workload.Report{AssignmentID: workload.AssignmentID{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		ID: record.Reservation.ID, Generation: record.Reservation.Generation, Revision: record.Operation}, State: workload.Suspended}
	if err := r.ReportContainerTask(ctx, host.HostID, host.Certificate, report); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("an active tenant accepted a suspension receipt: %v", err)
	}
	worker, stop := context.WithCancel(ctx)
	exited := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		defer close(exited)
		exited <- nodeagent.RunContainerOffboardingE2E(worker, agentConfig, slog.New(slog.NewTextHandler(io.Discard, nil)), ready)
	}()
	defer func() {
		stop()
		if err := <-exited; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case err := <-exited:
		t.Fatalf("the enrolled worker did not read the active assignment: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	path := "/ocean/tenants/" + tenant.TenantID + "/offboarding?api-version=2026-11-01"
	started := time.Now().UTC()
	az("put", path, fmt.Sprintf(`{"subscriptionId":%q}`, tenant.SubscriptionID), sign(operatorRealm, operatorClient, operator, origin), "")
	mounts, err = r.HostVolumeMounts(ctx, host.HostID, host.Certificate)
	if err != nil || len(mounts) != 1 || mounts[0].VolumeID != volume || !mounts[0].Suspend || !mounts[0].Remove || len(mounts[0].VolumeKey) != 0 {
		t.Fatalf("suspension did not withdraw the volume mount without a key: %v", err)
	}
	page, err := r.HostContainerTasks(ctx, host.HostID, host.Certificate, "", true)
	if err != nil || len(page.Tasks) != 0 || page.Next == "" {
		t.Fatalf("expected a filtered network page with continuation: %v", err)
	}
	page, err = r.HostContainerTasks(ctx, host.HostID, host.Certificate, page.Next, true)
	if err != nil || len(page.Tasks) != 1 || page.Tasks[0].TenantID != neighborScope.TenantID || page.Next != "" {
		t.Fatalf("filtered pages hid the adjacent tenant network assignment: %v", err)
	}
	stale := report
	stale.Generation = operationID()
	if err := r.ReportContainerTask(ctx, host.HostID, host.Certificate, stale); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("a stale generation accepted a suspension receipt: %v", err)
	}
	stale = report
	stale.State = workload.Running
	if err := r.ReportContainerTask(ctx, host.HostID, host.Certificate, stale); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("a suspended tenant accepted a late running report: %v", err)
	}
	count := func() int {
		rows, err := r.ListActivity(ctx, scope, "", arm.ActivityFilter{Start: started, End: time.Now().UTC()}, 64)
		if err != nil {
			return -1
		}
		observed := 0
		for _, row := range rows {
			if row.Actor == host.HostID && row.Action == "Ocean.Hosted/offboarding/stopContainer" && row.Outcome == workload.Suspended {
				observed++
			}
		}
		return observed
	}
	pollVMWorker(t, ctx, 35*time.Second, "all container suspension receipts", func() bool { return count() == len(records) })
	retained := t.TempDir()
	for _, name := range names {
		if state := hostedPodman(t, ctx, "inspect", "--format", "{{.State.Running}}", name); state != "false" {
			t.Fatal("a suspended runtime container remained running")
		}
		checkpoint := filepath.Join(retained, name)
		hostedPodman(t, ctx, "cp", name+":/ocean-fixture", checkpoint)
		if data, err := os.ReadFile(checkpoint); err != nil || string(data) != "hosted-suspension-fixture\n" {
			t.Fatalf("suspension changed the container's writable data: %v", err)
		}
	}
	if state := hostedPodman(t, ctx, "inspect", "--format", "{{.State.Running}}", otherName); state != "true" {
		t.Fatal("suspension stopped the adjacent tenant")
	}
	if err := r.ReportContainerTask(ctx, host.HostID, host.Certificate, report); err != nil || count() != len(records) {
		t.Fatalf("a repeated suspension receipt changed the audit evidence: %v", err)
	}
	grant, err := r.client.Get(ctx, r.writerKey(scope, volume))
	if err != nil || len(grant.Kvs) != 1 {
		t.Fatalf("suspension removed the regional writer grant: %v", err)
	}
	t.Logf("Azure CLI 2.93.0 suspended %d workload groups. The enrolled Podman reconciler stopped %d processes, preserved their writable layers and left an adjacent tenant running. Every group produced one generation-bound receipt. Verification took %d ms.", len(records), len(names), time.Since(started).Milliseconds())
}

func seedHostedContainer(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, actor, kind string, index int) containerRecord {
	t.Helper()
	address := arm.ResourceAddress{Group: "retained-fixture", Path: kind + fmt.Sprintf("/hosted-container-%02d", index)}
	key := r.containerKey(scope, address)
	op := arm.Operation{ID: operationID(), Kind: createContainer, Group: address.Group, Actor: actor, Status: arm.OperationInProgress, StartedAt: time.Now().UTC()}
	record := containerRecord{Address: address, Reservation: Reservation{PlacementRequest: PlacementRequest{ID: fmt.Sprintf("container-%02d", index)},
		HostID: hostedSuspensionHost, Generation: operationID()}, Desired: workload.Running, Observed: workload.Running,
		PublicIP: netip.AddrFrom4([4]byte{198, 51, 100, byte(index + 1)}), Port: 80, Operation: op.ID}
	config := workload.ContainerGroup{Location: r.name, Properties: workload.ContainerGroupProperties{RestartPolicy: "Always",
		Containers: []workload.Container{{Name: "fixture"}}}}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	record.Config = r.workloads.sealer.Seal(nil, nil, encoded, r.containerBinding(scope, record))
	if kind == functions.SiteType {
		account := arm.ResourceAddress{Group: address.Group, Path: storage.AccountType + "/fixture"}
		share := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/fixture"}
		record.Volume = &volumeBinding{ID: "vol-" + operationID(), Share: share}
		sh := storageShareRecord{Address: share, Account: account, Scope: scope, Volume: storage.Volume{ID: record.Volume.ID, SizeMiB: 1024}}
		shareKey := r.shareKey(scope, share)
		sh.Envelope = r.storage.sealer.Seal(nil, nil, make([]byte, storage.KeySize), []byte(shareKey+"/"+sh.Volume.ID))
		if _, err := r.client.Txn(ctx).Then(putJSON(shareKey, sh), putJSON(r.writerKey(scope, sh.Volume.ID), writerFor(record))).Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: address, Location: r.name, APIVersion: workload.ContainerGroupAPIVersion}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Txn(ctx).Then(putJSON(key, record), putJSON(r.operationKey(scope, op.ID), op),
		clientv3.OpPut(r.hostContainerKey(scope, hostedSuspensionHost, record.Reservation.ID), key)).Commit(); err != nil {
		t.Fatal(err)
	}
	return record
}

func hostedContainerName(scope arm.SubscriptionScope, record containerRecord) string {
	hash := sha256.Sum256([]byte(scope.TenantID + "/" + scope.SubscriptionID + "/" + record.Reservation.ID + "/" + record.Reservation.Generation))
	return fmt.Sprintf("ocean-%x", hash[:16])
}

func runHostedContainer(t *testing.T, ctx context.Context, image, name string) {
	t.Helper()
	hostedPodman(t, ctx, "run", "--pull=never", "--network=none", "--detach", "--name", name,
		"--", image, "/bin/sh", "-ec", "trap 'exit 0' TERM; echo hosted-suspension-fixture > /ocean-fixture; while :; do sleep 1; done")
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		hostedPodman(t, stop, "rm", "--force", "--ignore", "--time", "1", name)
	})
	if hostedPodman(t, ctx, "inspect", "--format", "{{.State.Running}}", name) != "true" {
		t.Fatal("the fixture container did not start")
	}
}

func hostedPodman(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "nice", append([]string{"-n", "10", "/usr/bin/podman"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Podman %s failed: %v", args[0], err)
	}
	return strings.TrimSpace(string(out))
}
