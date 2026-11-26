//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/telemetry"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestHostedTelemetryPolicy(t *testing.T) {
	archive, cli := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if archive == "" || cli == "" {
		t.Skip("requires pinned etcd and Azure CLI")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cfg := hostedOffboardingLabConfig(t, ctx, archive, "hosted-telemetry")
	dir := t.TempDir()
	base, cert, key, binary, _ := prepareSMBRecoveryEtcd(t, ctx, archive, dir)
	destination, _, stopTelemetry := startSMBRecoveryEtcd(t, ctx, base, cert, key, binary, filepath.Join(dir, "telemetry"), nil)
	cfg.Telemetry = &telemetryConfig{Etcd: destination, RetentionSeconds: 300}
	if _, err := cfg.telemetryPool(); err == nil {
		t.Fatal("hosted telemetry accepted a destination without a regional approval")
	}
	cfg.HostedWorkplace.OperatorPools["partner"] = "NL"
	cfg.HostedWorkplace.Telemetry = &hostedTelemetryPolicy{OperatorPool: "offsite", Endpoints: destination.Endpoints, RetentionSeconds: 300}
	if _, err := cfg.telemetryPool(); err == nil {
		t.Fatal("hosted telemetry accepted a pool outside the approved sites")
	}
	cfg.HostedWorkplace.Telemetry.OperatorPool = "partner"
	switched := cfg
	store := *cfg.Telemetry
	switched.Telemetry = &store
	store.Etcd.Endpoints = []string{"https://127.0.0.1:1"}
	if _, err := switched.telemetryPool(); err == nil {
		t.Fatal("hosted telemetry accepted an undeclared endpoint")
	}
	legacy := cfg
	topology := *cfg.HostedWorkplace
	topology.Telemetry = nil
	legacy.HostedWorkplace, legacy.Telemetry = &topology, nil
	openHostedLabRegion(t, ctx, legacy)
	r := openHostedLabRegion(t, ctx, cfg)
	missingPolicy, err := openRegion(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = missingPolicy.close() }()
	if err := missingPolicy.bootstrap(ctx); err == nil {
		t.Fatal("a hosted replica omitted the active telemetry approval")
	}
	assertHostedTelemetryPolicyMismatch(t, ctx, cfg)

	makeTenant := func() (identity.TenantReservation, arm.SubscriptionScope, containerRecord) {
		t.Helper()
		tenant := seedHostedRestoreTenant(t, ctx, r)
		scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
		return tenant, scope, seedHostedContainer(t, ctx, r, scope, tenant.Administrator, workload.ContainerGroupType, 0)
	}
	owner, ownerScope, resource := makeTenant()
	neighbor, neighborScope, other := makeTenant()
	quota := enrollment.Capacity{CPUMillis: 4000, MemoryMiB: 2048}
	if err := r.SetPlacementPolicy(ctx, ownerScope, PlacementPolicy{Pools: []string{"primary", "partner"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	operator, operatorClient := operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operator, owner.TenantID, neighbor.TenantID)
	origin, client, az, worker := startHostedRestoreAPI(t, ctx, cfg, cli, operator, operatorClient, issuer.URL, issuer.Certificate())
	workerConfig, workerCert := worker(hostedSuspensionHost)
	host := registerHostedOffboardingWorker(t, ctx, r, workerCert)
	// The telemetry expiry probe can outlast the enrolled fixture's first
	// heartbeat lease. Keep the reporter online throughout the observation.
	live, err := r.client.Get(ctx, r.hostKey("live", host.HostID))
	if err != nil || len(live.Kvs) != 1 || live.Kvs[0].Lease == 0 {
		t.Fatalf("the reporting fixture lacks an active heartbeat lease: %v", err)
	}
	heartbeats, err := r.client.KeepAlive(ctx, clientv3.LeaseID(live.Kvs[0].Lease))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for range heartbeats {
		}
	}()
	post := hostedTelemetryClient(t, ctx, origin, client, workerConfig, host.HostID)

	reader, grant := operationID(), operationID()
	if _, _, err := r.PutAssignment(ctx, ownerScope, arm.RoleAssignment{ID: grant, Group: resource.Address.Group, PrincipalID: reader,
		PrincipalType: "User", RoleID: arm.ReaderRoleID, CreatedBy: owner.Administrator, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	expires := started.Add(18 * time.Second).Truncate(time.Second)
	if expires.Truncate(time.Minute).Add(time.Minute).Sub(expires) < 10*time.Second {
		expires = expires.Add(12 * time.Second)
	}
	early := expires.Add(-5 * time.Minute)
	observe := func(scope arm.SubscriptionScope, container containerRecord, at time.Time, cpu float64) telemetry.Observation {
		return telemetry.Observation{Assignment: telemetry.Assignment{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
			ID: container.Reservation.ID, Generation: container.Reservation.Generation}, Sample: telemetry.Sample{
			ID: telemetryFixtureSampleID(), Time: at.UTC(), Usage: &telemetry.Usage{CPUMillis: cpu, MemoryBytes: 1 << 20}}}
	}
	past := observe(ownerScope, resource, started.Add(-6*time.Minute), 333)
	aging := observe(ownerScope, resource, early, 777)
	current := observe(ownerScope, resource, started, 555)
	blocked := observe(neighborScope, other, started, 999)
	wrongWorkerConfig, _ := worker("worker-b")
	wrongReporter := hostedTelemetryClient(t, ctx, origin, client, wrongWorkerConfig, host.HostID)
	wrongReporter(http.StatusForbidden, current)
	forged := current
	forged.Assignment.Generation = operationID()
	forged.Sample.ID = telemetryFixtureSampleID()
	post(http.StatusNoContent, past, aging, current, blocked, forged)
	assertHostedTelemetryRows(t, ctx, r, ownerScope, resource, 2)
	assertHostedTelemetryRows(t, ctx, r, neighborScope, other, 0)
	if err := r.SetPlacementPolicy(ctx, neighborScope, PlacementPolicy{Pools: []string{"partner"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	post(http.StatusNoContent, blocked)
	assertHostedTelemetryRows(t, ctx, r, neighborScope, other, 0)

	path := resource.Address.ID(ownerScope) + "/providers/Microsoft.Insights/metrics?api-version=2018-01-01&metricnames=CpuUsage"
	az("get", path, "", sign(neighbor.TenantID, operatorClient, neighbor.Administrator, origin), "SubscriptionNotFound")
	readAs := func(principal, want string) []byte {
		return az("get", path, "", sign(owner.TenantID, operatorClient, principal, origin), want)
	}
	assertHostedTelemetryMetric(t, readAs(reader, ""), 555, 777)
	if _, err := r.DeleteAssignment(ctx, ownerScope, resource.Address.Group, grant, owner.Administrator); err != nil {
		t.Fatal(err)
	}
	readAs(reader, "AuthorizationFailed")
	pollVMWorker(t, ctx, time.Until(expires)+10*time.Second, "the observation-time retention boundary", func() bool {
		return !time.Now().Before(expires)
	})
	assertHostedTelemetryMetric(t, readAs(owner.Administrator, ""), 555)
	expiredFromAPI := time.Since(started)
	post(http.StatusNoContent, aging)
	rows := assertHostedTelemetryRows(t, ctx, r, ownerScope, resource, 2)
	if rows.Kvs[0].Lease == 0 || rows.Kvs[0].Lease == rows.Kvs[1].Lease {
		t.Fatal("the delayed observation must have its own expiry bucket")
	}
	pollVMWorker(t, ctx, 70*time.Second, "etcd to expire the bucket for the old observation", func() bool {
		rows, err := r.telemetry.client.Get(ctx, r.armPrefix(ownerScope)+"telemetry/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		return err == nil && rows.Count == 1
	})
	expiredFromStore := time.Since(started)
	remaining := assertHostedTelemetryRows(t, ctx, r, ownerScope, resource, 1)
	if _, err := r.telemetry.client.Revoke(ctx, clientv3.LeaseID(remaining.Kvs[0].Lease)); err != nil {
		t.Fatal(err)
	}
	post(http.StatusServiceUnavailable, current)
	post(http.StatusNoContent, current)
	assertHostedTelemetryRows(t, ctx, r, ownerScope, resource, 1)
	if err := r.SetPlacementPolicy(ctx, ownerScope, PlacementPolicy{Pools: []string{"primary"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	readAs(owner.Administrator, "TelemetryUnavailable")
	if err := r.SetPlacementPolicy(ctx, ownerScope, PlacementPolicy{Pools: []string{"primary", "partner"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	stopTelemetry()
	readAs(owner.Administrator, "TelemetryUnavailable")
	az("get", resource.Address.ID(ownerScope)+"?api-version="+workload.ContainerGroupAPIVersion, "",
		sign(owner.TenantID, operatorClient, owner.Administrator, origin), "")
	az("put", "/subscriptions/"+ownerScope.SubscriptionID+"/resourcegroups/telemetry-outage?api-version=2024-11-01",
		`{"location":"hosted-telemetry"}`, sign(owner.TenantID, operatorClient, owner.Administrator, origin), "")
	t.Logf("Pinned Azure CLI and an enrolled mTLS reporter verified tenant isolation, scoped readers and approved telemetry placement. An older observation left the API after %d ms and the separate store after %d ms. ARM served the workload and created a resource group after the telemetry store stopped.", expiredFromAPI.Milliseconds(), expiredFromStore.Milliseconds())
}

func telemetryFixtureSampleID() string {
	return strings.ReplaceAll(operationID(), "-", "")
}

func assertHostedTelemetryPolicyMismatch(t *testing.T, ctx context.Context, cfg regionConfig) {
	t.Helper()
	policy, regional, proposed := *cfg.HostedWorkplace, *cfg.Telemetry, *cfg.HostedWorkplace.Telemetry
	cfg.HostedWorkplace, cfg.Telemetry, policy.Telemetry = &policy, &regional, &proposed
	regional.RetentionSeconds++
	if _, err := cfg.telemetryPool(); err == nil {
		t.Fatal("accepted retention outside the approved policy")
	}
	proposed.RetentionSeconds++
	replica, err := openRegion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replica.close() }()
	if err := replica.bootstrap(ctx); err == nil {
		t.Fatal("a replica opened with retention differing from the persisted regional policy")
	}
}

func hostedTelemetryClient(t *testing.T, ctx context.Context, origin string, client *http.Client, configPath, host string) func(int, ...telemetry.Observation) {
	t.Helper()
	raw, err := os.ReadFile(configPath)
	var config struct {
		Enrollment struct{ StateDirectory string }
	}
	if err != nil || json.Unmarshal(raw, &config) != nil || config.Enrollment.StateDirectory == "" {
		t.Fatal("invalid enrolled telemetry fixture configuration")
	}
	state := config.Enrollment.StateDirectory
	cert, err := os.ReadFile(filepath.Join(state, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(state, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	baseTransport, ok := client.Transport.(*http.Transport)
	if !ok || baseTransport.TLSClientConfig == nil {
		t.Fatal("missing regional TLS transport")
	}
	transport := baseTransport.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{pair}
	t.Cleanup(transport.CloseIdleConnections)
	reporter := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	return func(want int, observations ...telemetry.Observation) {
		t.Helper()
		raw, err := json.Marshal(telemetry.Batch{Observations: observations})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/ocean/hosts/"+host+"/telemetry", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		reply, err := reporter.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := reply.Body.Close(); err != nil || reply.StatusCode != want {
			t.Fatalf("telemetry reporter status %d, expected %d: %v", reply.StatusCode, want, err)
		}
	}
}

func assertHostedTelemetryRows(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, resource containerRecord, expected int64) *clientv3.GetResponse {
	t.Helper()
	rows, err := r.client.Get(ctx, r.containerKey(scope, resource.Address))
	if err != nil || len(rows.Kvs) != 1 {
		t.Fatal("missing hosted workload fixture")
	}
	prefix := r.telemetryPrefix(scope, resource.Address, rows.Kvs[0].CreateRevision)
	samples, err := r.telemetry.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil || samples.Count != expected {
		t.Fatalf("expected %d stored telemetry observations: %v", expected, err)
	}
	return samples
}

func assertHostedTelemetryMetric(t *testing.T, raw []byte, expected ...float64) {
	t.Helper()
	var output struct {
		Value []struct {
			Timeseries []struct {
				Data []struct{ Average *float64 }
			}
		}
	}
	if err := json.Unmarshal(raw, &output); err != nil || len(output.Value) != 1 || len(output.Value[0].Timeseries) != 1 {
		t.Fatalf("invalid metrics response: %v", err)
	}
	var measurements []float64
	for _, bucket := range output.Value[0].Timeseries[0].Data {
		if bucket.Average != nil {
			measurements = append(measurements, *bucket.Average)
		}
	}
	slices.Sort(measurements)
	if !slices.Equal(measurements, expected) {
		t.Fatalf("unexpected synthetic metric buckets: %v", measurements)
	}
}
