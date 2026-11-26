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
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalFunctionPackages(t *testing.T) {
	if os.Getenv("OCEAN_E2E_FUNCTIONS_PACKAGE_STORE") != "1" {
		t.Skip("requires the disposable regional etcd cluster")
	}
	r := regionalFunctionsFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
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

func regionalFunctionsFixture(t *testing.T) *Region {
	t.Helper()
	r := openLabRegion(t)
	r.root = "/ocean/v1/regions/functions-lab-" + operationID()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := r.client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
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
	return r
}

func TestRegionalFunctionSlotSwap(t *testing.T) {
	if os.Getenv("OCEAN_E2E_FUNCTIONS_PACKAGE_STORE") != "1" {
		t.Skip("requires the disposable regional etcd cluster")
	}
	r := regionalFunctionsFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	scope := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	app := arm.ResourceAddress{Group: "zip-lab", Path: functions.SiteType + "/native"}
	slot := arm.ResourceAddress{Group: app.Group, Path: app.Path + "/slots/staging"}
	first := seedFunctionsSlot(t, ctx, r, scope, app, "production")
	second := seedFunctionsSlot(t, ctx, r, scope, slot, "staging")
	handle := functionsSlotLabHandler(t, r, scope, app)
	assertActivation := func(site functionSlotFixture, code functionSlotFixture) *arm.Operation {
		t.Helper()
		state, err := r.functionSlotState(ctx, scope, site.address)
		if err != nil {
			t.Fatal(err)
		}
		current, unchanged := state.config.Function, site.app
		if current.Runtime.Package == nil || *current.Runtime.Package != *code.app.Runtime.Package ||
			!maps.Equal(current.Settings, map[string]string{"OCEAN_STICKY": unchanged.Settings["OCEAN_STICKY"], "OCEAN_SETTING": code.app.Settings["OCEAN_SETTING"]}) ||
			current.Runtime.MasterKey != unchanged.Runtime.MasterKey || current.Runtime.StorageKey != unchanged.Runtime.StorageKey ||
			current.PublicHost != unchanged.PublicHost || state.record.Reservation.SubnetID != site.subnet {
			t.Fatal("slot activation changed its binding or selected the wrong package or settings")
		}
		return state.op
	}
	finish := func(site functionSlotFixture, id, state string, ready bool) error {
		report := workload.Report{AssignmentID: site.assignment, State: state, FunctionReady: ready}
		report.Revision = id
		return r.ReportContainerTask(ctx, site.host, []byte(site.host), report)
	}
	request := operationID()
	res := handle(http.MethodPost, slot.ID(scope)+"/slotsswap", `{"targetSlot":"production","preserveVnet":true}`, request)
	if res.Code != http.StatusAccepted {
		t.Fatalf("slot swap was not accepted: HTTP %d", res.Code)
	}
	operation := res.Header().Get("Azure-AsyncOperation")
	failedID, _, _ := strings.Cut(operation[strings.LastIndexByte(operation, '/')+1:], "?")
	failed, err := r.GetOperation(ctx, scope, failedID)
	if err != nil || failed == nil || failed.Status != arm.OperationInProgress {
		t.Fatalf("the swap did not advertise a pollable regional operation: %v", err)
	}
	if replay, err := r.SwapFunctionSlot(ctx, scope, "owner", slot, request); err != nil || replay.ID != failed.ID {
		t.Fatalf("the in-flight request was not replayed: %v", err)
	}
	if _, err := r.SwapFunctionSlot(ctx, scope, "owner", slot, operationID()); !errors.Is(err, arm.ErrContainerBusy) {
		t.Fatalf("a competing swap was not rejected: %v", err)
	}
	assertActivation(first, second)
	assertActivation(second, first)
	if err := finish(first, failed.ID, workload.Running, false); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("an unindexed worker confirmed the swap: %v", err)
	}
	if err := finish(first, failed.ID, workload.Running, true); err != nil {
		t.Fatal(err)
	}
	if got := assertActivation(first, second); got.Status != arm.OperationInProgress {
		t.Fatal("the swap completed with only one worker ready")
	}
	if err := finish(second, failed.ID, workload.Failed, false); err != nil {
		t.Fatal(err)
	}
	if got, err := r.GetOperation(ctx, scope, failed.ID); err != nil || got == nil || got.Status != arm.OperationFailed {
		t.Fatalf("activation failure did not complete the failed swap: %v", err)
	}
	rollback := assertActivation(first, first)
	if got := assertActivation(second, second); got.ID != rollback.ID || got.Kind != rollbackFunctionSwap || got.Status != arm.OperationInProgress {
		t.Fatal("failed activation did not schedule one rollback for both sites")
	}
	if err := finish(first, failed.ID, workload.Running, true); !errors.Is(err, enrollment.ErrWorkloadChanged) {
		t.Fatalf("a stale worker could still confirm the failed swap: %v", err)
	}
	for _, site := range []functionSlotFixture{first, second} {
		if err := finish(site, rollback.ID, workload.Running, true); err != nil {
			t.Fatal(err)
		}
	}
	request = operationID()
	success, err := r.SwapFunctionSlot(ctx, scope, "owner", slot, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []functionSlotFixture{second, first} {
		if err := finish(site, success.ID, workload.Running, true); err != nil {
			t.Fatal(err)
		}
	}
	if replay, err := r.SwapFunctionSlot(ctx, scope, "owner", slot, request); err != nil || replay.ID != success.ID || replay.Status != arm.OperationSucceeded {
		t.Fatalf("a committed request did not return the original successful swap: %v", err)
	}
	assertActivation(first, second)
	assertActivation(second, first)
	t.Log("Live etcd preserved endpoint bindings and sticky settings, rejected a concurrent request, rolled back both sites after a worker failure, and required two acknowledgments for a successful swap.")
}

func functionsSlotLabHandler(t *testing.T, r *Region, scope arm.SubscriptionScope,
	app arm.ResourceAddress) func(string, string, string, string) *httptest.ResponseRecorder {
	t.Helper()
	const origin = "https://arm.ocean.test"
	s := arm.Server{Origin: origin, FunctionSCMDomain: "scm.ocean.test", FunctionDomain: "functions.ocean.test",
		FunctionSlots: r, Functions: r, FunctionPackages: r, Inventory: r, Operations: r,
		Authenticate: func(context.Context, *http.Request) (identity.ARMPrincipal, error) {
			return identity.ARMPrincipal{Subject: "owner", Subscription: identity.Subscription{
				TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, Members: []string{"owner"}}}, nil
		}}
	h := s.Handler(http.NotFoundHandler())
	call := func(method, path, body, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, origin+path+"?api-version="+functions.APIVersion, strings.NewReader(body))
		if id != "" {
			req.Header.Set("x-ms-client-request-id", id)
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		return response
	}
	listing := call(http.MethodGet, app.ID(scope)+"/slots", "", "")
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), `"name":"native/staging"`) ||
		!strings.Contains(listing.Body.String(), `"name":"native-staging.scm.ocean.test"`) {
		t.Fatalf("slot listing did not project the expected ARM name and SCM hostname: HTTP %d", listing.Code)
	}
	settings := app.ID(scope) + "/config/slotConfigNames"
	write := call(http.MethodPut, settings, `{"properties":{"appSettingNames":["OCEAN_STICKY"]}}`, "")
	read := call(http.MethodGet, settings, "", "")
	if write.Code != http.StatusOK || read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"appSettingNames":["OCEAN_STICKY"]`) {
		t.Fatalf("sticky settings did not round-trip through ARM: HTTP %d, %d", write.Code, read.Code)
	}
	return call
}

type functionSlotFixture struct {
	address    arm.ResourceAddress
	host       string
	subnet     string
	assignment workload.AssignmentID
	app        *workload.FunctionApp
}

func seedFunctionsSlot(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, address arm.ResourceAddress, site string) functionSlotFixture {
	t.Helper()
	archive := functionArchiveFixture(t)
	defer clear(archive)
	ref, err := r.storeFunctionPackage(ctx, scope, archive)
	if err != nil {
		t.Fatal(err)
	}
	host := site + "-worker"
	lease, err := r.client.Grant(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	assigned := workload.AssignmentID{ID: operationID(), Generation: operationID(), Revision: operationID(),
		TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID}
	subnet := "/virtualNetworks/lab/subnets/" + site
	record := containerRecord{Address: address, Desired: workload.Running, Observed: workload.Running, Operation: assigned.Revision,
		Reservation: Reservation{PlacementRequest: PlacementRequest{ID: assigned.ID, SubnetID: subnet}, Generation: assigned.Generation, HostID: host}}
	app := &workload.FunctionApp{PlanID: "/serverfarms/native", PublicHost: site + ".functions.test", Runtime: functions.Runtime{
		Account: site, MasterKey: "master-" + site, StorageKey: "storage-" + site, Package: &ref, Configuration: assigned.Revision},
		Settings: map[string]string{"OCEAN_STICKY": "sticky-" + site, "OCEAN_SETTING": "setting-" + site}}
	config := functionEnvironment(workload.ContainerGroup{Location: r.name, Properties: workload.ContainerGroupProperties{
		Containers: []workload.Container{{Name: site, Properties: workload.ContainerProperties{Image: "pinned-functions-image"}}}}, Function: app})
	if err := r.sealFunctionConfig(scope, &record, config); err != nil {
		t.Fatal(err)
	}
	recordKey := r.containerKey(scope, address)
	identity := enrollment.Host{HostID: host, Cell: "cell-1", Pool: "lab", Roles: []string{"compute"}, Certificate: []byte(host)}
	liveData, err := json.Marshal(enrollment.Availability{HostID: host, Cell: identity.Cell, Pool: identity.Pool, Roles: identity.Roles})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	op := arm.Operation{ID: assigned.Revision, Kind: createContainer, Group: address.Group, Actor: "owner", Status: arm.OperationSucceeded,
		StartedAt: now, FinishedAt: &now}
	resource := projectContainer(config, record, now, now, arm.OperationSucceeded)
	if _, err := r.client.Txn(ctx).Then(putJSON(recordKey, record), clientv3.OpPut(r.hostContainerKey(scope, host, assigned.ID), recordKey),
		putJSON(r.hostKey("registered", host), identity), clientv3.OpPut(r.hostKey("live", host), string(liveData), clientv3.WithLease(lease.ID)),
		putJSON(r.operationKey(scope, op.ID), op), putJSON(r.inventoryPrefix(scope)+address.Key(), resource)).Commit(); err != nil {
		t.Fatal(err)
	}
	return functionSlotFixture{address: address, host: host, subnet: subnet, assignment: assigned, app: app}
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
