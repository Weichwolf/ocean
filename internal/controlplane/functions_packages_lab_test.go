//go:build e2e

package controlplane

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalFunctionPackages(t *testing.T) {
	if os.Getenv("OCEAN_E2E_FUNCTIONS_PACKAGE_STORE") != "1" {
		t.Skip("requires the disposable regional etcd cluster")
	}
	r := openLabRegion(t)
	r.root = "/ocean/v1/regions/function-packages-" + operationID()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var key [32]byte
	rand.Read(key[:])
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	r.workloads = &workloadControl{sealer: sealer}
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	archive := functionArchiveFixture(t)
	defer clear(archive)
	type publication struct {
		ref functions.PackageReference
		err error
	}
	published := make(chan publication, 2)
	for range 2 {
		go func() {
			ref, err := r.storeFunctionPackage(ctx, scope, archive)
			published <- publication{ref, err}
		}()
	}
	first, second := <-published, <-published
	if first.err != nil || second.err != nil || first.ref != second.ref || !first.ref.Valid() {
		t.Fatalf("concurrent publication did not converge: %v, %v", first.err, second.err)
	}
	warm, err := r.storeFunctionPackage(ctx, scope, archive)
	if err != nil || warm != first.ref {
		t.Fatalf("verified replay did not return the existing package: %v", err)
	}
	assertPackage := func() {
		t.Helper()
		body, err := r.loadFunctionPackage(ctx, scope, first.ref)
		defer clear(body)
		if err != nil || !bytes.Equal(body, archive) {
			t.Fatalf("the regional reader did not recover exact ZIP bytes: %v", err)
		}
	}
	assertPackage()
	testAssignedFunctionPackage(t, ctx, r, scope, first.ref, archive)
	foreign := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	if _, err := r.loadFunctionPackage(ctx, foreign, first.ref); !errors.Is(err, arm.ErrLinkedResourceMissing) {
		t.Fatalf("a package crossed subscription scope: %v", err)
	}
	manifest, err := r.client.Get(ctx, r.functionPackageKey(scope, first.ref.SHA256))
	if err != nil || len(manifest.Kvs) != 1 {
		t.Fatalf("the verified manifest is missing: %v", err)
	}
	winner, err := decodeFunctionPackageManifest(manifest.Kvs[0].Value, first.ref)
	if err != nil {
		t.Fatal(err)
	}
	base := r.functionPackageChunks(functionPackageStage{Scope: scope, Package: first.ref, Upload: winner.Upload})
	chunks, err := r.client.Get(ctx, r.armPrefix(scope)+"function-package-data/", clientv3.WithPrefix())
	expected := (first.ref.Bytes + functionPackageChunkSize - 1) / functionPackageChunkSize
	if err != nil || len(chunks.Kvs) != expected {
		t.Fatalf("a losing publication retained partial chunks: %v", err)
	}
	for _, item := range chunks.Kvs {
		if bytes.Contains(item.Value, archive[:128]) || item.Lease != 0 {
			t.Fatal("a published package chunk contains plaintext or retains a staging lease")
		}
	}
	if stages, err := r.client.Get(ctx, r.functionPackageStageKey(""), clientv3.WithPrefix(), clientv3.WithCountOnly()); err != nil || stages.Count != 0 {
		t.Fatalf("a completed publisher left a stage marker: %v", err)
	}

	abandoned := functionPackageStage{Scope: scope, Package: first.ref, Upload: operationID()}
	marker := r.functionPackageStageKey(abandoned.Upload)
	staleChunk := functionPackageChunkKey(r.functionPackageChunks(abandoned), 0)
	lease, err := r.client.Grant(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Txn(ctx).Then(putJSON(marker, abandoned), clientv3.OpPut(staleChunk, "disposable staging data"),
		clientv3.OpPut(r.functionPackageLeaseKey(abandoned.Upload), abandoned.Upload, clientv3.WithLease(lease.ID))).Commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.reapFunctionPackageStages(ctx); err != nil {
		t.Fatal(err)
	}
	if active, err := r.client.Get(ctx, staleChunk); err != nil || len(active.Kvs) != 1 {
		t.Fatalf("reaping removed an upload that still holds a lease: %v", err)
	}
	if _, err := r.client.Revoke(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.reapFunctionPackageStages(ctx); err != nil {
		t.Fatal(err)
	}
	if stale, err := r.client.Get(ctx, staleChunk); err != nil || len(stale.Kvs) != 0 {
		t.Fatalf("reaping retained an abandoned upload: %v", err)
	}
	assertPackage()

	key1, key2 := functionPackageChunkKey(base, 0), functionPackageChunkKey(base, 1)
	if !bytes.Equal(chunks.Kvs[0].Key, []byte(key1)) || !bytes.Equal(chunks.Kvs[1].Key, []byte(key2)) {
		t.Fatal("the package chunks have unexpected keys")
	}
	if _, err := r.client.Put(ctx, key1, string(chunks.Kvs[1].Value)); err != nil {
		t.Fatal(err)
	}
	if archive, err := r.loadFunctionPackage(ctx, scope, first.ref); err == nil || len(archive) != 0 {
		t.Fatal("a ciphertext copied to the wrong chunk position produced a package")
	}
	t.Logf("Live etcd published a %d-byte prebuilt ZIP as %d sealed chunks. Duplicate uploads converged, only the current certified placement could fetch it, and an expired stage was reclaimed.", first.ref.Bytes, expected)
}

func testAssignedFunctionPackage(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, ref functions.PackageReference, expected []byte) {
	t.Helper()
	const host = "zip-worker"
	cert := []byte("disposable enrolled compute certificate")
	lease, err := r.client.Grant(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := r.client.Revoke(ctx, lease.ID); err != nil {
			t.Error(err)
		}
	}()
	assigned := workload.AssignmentID{ID: operationID(), Generation: operationID(), Revision: operationID(),
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID}
	address := arm.ResourceAddress{Group: "zip-lab", Path: functions.SiteType + "/native"}
	record := containerRecord{
		Address: address, Desired: workload.Running, Observed: workload.Running, Operation: assigned.Revision,
		Reservation: Reservation{PlacementRequest: PlacementRequest{ID: assigned.ID}, Generation: assigned.Generation, HostID: host},
	}
	const appHost = "native.functions.test"
	config := workload.ContainerGroup{Location: r.name, Properties: workload.ContainerGroupProperties{
		Containers: []workload.Container{{Name: "native"}}},
		Function: &workload.FunctionApp{PlanID: "/serverfarms/native", PublicHost: appHost, Runtime: functions.Runtime{Account: "nativefixture"}}}
	if err := r.sealFunctionConfig(scope, &record, config); err != nil {
		t.Fatal(err)
	}
	recordKey := r.containerKey(scope, address)
	identity := enrollment.Host{HostID: host, Cell: "cell-1", Pool: "lab", Roles: []string{"compute"}, Certificate: cert}
	live := enrollment.Availability{HostID: host, Cell: identity.Cell, Pool: identity.Pool, Roles: identity.Roles}
	liveData, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := arm.Operation{ID: assigned.Revision, Kind: createContainer, Group: address.Group, Actor: "owner", Status: arm.OperationSucceeded,
		StartedAt: now, FinishedAt: &now}
	resource := projectContainer(config, record, now, now, arm.OperationSucceeded)
	if _, err := r.client.Txn(ctx).Then(putJSON(recordKey, record), clientv3.OpPut(r.hostContainerKey(scope, host, assigned.ID), recordKey),
		putJSON(r.hostKey("registered", host), identity), clientv3.OpPut(r.hostKey("live", host), string(liveData), clientv3.WithLease(lease.ID)),
		putJSON(r.operationKey(scope, source.ID), source), putJSON(r.inventoryPrefix(scope)+address.Key(), resource),
		clientv3.OpPut(r.functionNameKey(appHost), recordKey)).Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DeployFunctionZIP(ctx, scope, "owner", appHost, []byte("invalid ZIP")); !errors.Is(err, functions.ErrInvalidZIPPackage) {
		t.Fatalf("invalid content started publication: %v", err)
	}
	accepted, err := r.DeployFunctionZIP(ctx, scope, "owner", appHost, expected)
	if err != nil || accepted.Status != functions.DeploymentPending || accepted.Complete || accepted.ID == "" {
		t.Fatalf("ZIP upload did not create a pending operation: %v", err)
	}
	replay, err := r.DeployFunctionZIP(ctx, scope, "owner", appHost, expected)
	if err != nil || replay != accepted {
		t.Fatalf("a replayed ZIP upload duplicated its pending operation: %v", err)
	}
	assigned.Revision = accepted.ID
	data, err := r.HostFunctionPackage(ctx, host, cert, assigned)
	defer clear(data)
	if err != nil || !bytes.Equal(data, expected) {
		t.Fatalf("could not fetch the approved archive for the assigned worker: %v", err)
	}
	stale := assigned
	stale.Revision = operationID()
	if data, err := r.HostFunctionPackage(ctx, host, cert, stale); len(data) != 0 || !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("a stale assignment retrieved its package: %v", err)
	}
	if data, err := r.HostFunctionPackage(ctx, host, []byte("different enrolled certificate"), assigned); len(data) != 0 || !errors.Is(err, enrollment.ErrHostDenied) {
		t.Fatalf("a foreign certificate retrieved the package: %v", err)
	}
	assertStatus := func(id string, expected int) {
		t.Helper()
		status, err := r.FunctionZIPStatus(ctx, scope, appHost)
		if err != nil || status.ID != id || status.Status != expected || status.Complete != (expected != functions.DeploymentPending) {
			t.Fatalf("the SCM status did not match the worker operation: %v", err)
		}
	}
	assertStatus(assigned.Revision, functions.DeploymentPending)
	report := workload.Report{AssignmentID: assigned, State: workload.Running}
	if err := r.ReportContainerTask(ctx, host, cert, report); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("Running without indexed Functions acknowledged deployment: %v", err)
	}
	report.State = workload.Failed
	if err := r.ReportContainerTask(ctx, host, cert, report); err != nil {
		t.Fatal(err)
	}
	assertStatus(assigned.Revision, functions.DeploymentFailed)
	_, restored, rollback, _, err := r.readContainer(ctx, scope, address)
	if err != nil || rollback == nil || rollback.Kind != rollbackFunctionZIP || rollback.Status != arm.OperationInProgress {
		t.Fatalf("the failed deployment did not schedule restoration: %v", err)
	}
	prior, err := r.decryptContainer(scope, restored)
	if err != nil || prior.Function == nil || prior.Function.Runtime.Package != nil || prior.Function.Runtime.Configuration != rollback.ID {
		t.Fatalf("rollback did not restore the previous Functions configuration: %v", err)
	}
	report.Revision, report.State, report.FunctionReady = rollback.ID, workload.Running, true
	if err := r.ReportContainerTask(ctx, host, cert, report); err != nil {
		t.Fatal(err)
	}
	next, err := r.DeployFunctionZIP(ctx, scope, "owner", appHost, expected)
	if err != nil || next.ID == accepted.ID {
		t.Fatalf("a failed deployment could not be retried: %v", err)
	}
	report.Revision = next.ID
	if err := r.ReportContainerTask(ctx, host, cert, report); err != nil {
		t.Fatal(err)
	}
	assertStatus(next.ID, functions.DeploymentSucceeded)
	_, ready, job, _, err := r.readContainer(ctx, scope, address)
	if err != nil || job == nil || job.Status != arm.OperationSucceeded {
		t.Fatalf("the package did not become the active configuration: %v", err)
	}
	active, err := r.decryptContainer(scope, ready)
	if err != nil || active.Function == nil || active.Function.Runtime.Package == nil || *active.Function.Runtime.Package != ref {
		t.Fatalf("verified publication activated an unexpected package: %v", err)
	}
}

func functionArchiveFixture(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	host, err := writer.Create("host.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(host, `{"version":"2.0"}`); err != nil {
		t.Fatal(err)
	}
	file, err := writer.CreateHeader(&zip.FileHeader{Name: "hello/prebuilt.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2<<20)
	rand.Read(payload)
	defer clear(payload)
	if _, err := file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}
