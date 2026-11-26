//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func seedHostedRestoreTenant(t *testing.T, ctx context.Context, r *Region) identity.TenantReservation {
	t.Helper()
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DisplayName: "Hosted restore fixture", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: "retained-fixture", Location: r.name, Tags: map[string]string{}}, tenant.Administrator); err != nil {
		t.Fatal(err)
	}
	return tenant
}

func seedHostedRestoreAssignments(t *testing.T, ctx context.Context, r *Region, tenant, neighbor identity.TenantReservation, quota enrollment.Capacity) {
	t.Helper()
	seedHostedPlacementWorker(t, ctx, r, "worker-a", "primary")
	neighborScope := arm.SubscriptionScope{TenantID: neighbor.TenantID, SubscriptionID: neighbor.SubscriptionID}
	if err := r.SetPlacementPolicy(ctx, neighborScope, PlacementPolicy{Pools: []string{"primary"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	for _, record := range []identity.TenantReservation{tenant, neighbor} {
		scope := arm.SubscriptionScope{TenantID: record.TenantID, SubscriptionID: record.SubscriptionID}
		placement, err := r.ReservePlacement(ctx, scope, PlacementRequest{ID: "fixture-guest", Cell: r.cell, Role: "compute",
			Resources: enrollment.Capacity{CPUMillis: 100, MemoryMiB: 128}})
		if err != nil || placement.HostID != "worker-a" {
			t.Fatalf("failed to seed a tenant assignment in the snapshot: %v", err)
		}
	}
	page, err := r.HostAssignments(ctx, "worker-a", []byte("worker-a"), "")
	if err != nil || len(page.Assignments) != 2 {
		t.Fatalf("expected two host assignments before offboarding: %v", err)
	}
}

func verifyHostedSuspension(t *testing.T, ctx context.Context, cfg regionConfig, source *Region,
	tenant, neighbor identity.TenantReservation, cli string, stopLedger, verifyKeyDenied func()) {
	t.Helper()
	started := time.Now()
	operatorRealm, operatorClient, operator := operationID(), operationID(), operationID()
	issuer, sign := hostedOperatorIssuer(t, operatorRealm, tenant.TenantID, neighbor.TenantID)
	sourceAPI, sourceAz := hostedOperatorLabAPI(t, ctx, source, cli, operatorRealm, operatorClient, issuer)
	operatorToken := sign(operatorRealm, operatorClient, operator, sourceAPI.URL)
	tenantToken := sign(tenant.TenantID, operatorClient, tenant.Administrator, sourceAPI.URL)
	groups := func(sub string) string { return "/subscriptions/" + sub + "/resourcegroups?api-version=2024-11-01" }
	offboard := "/ocean/tenants/" + tenant.TenantID + "/offboarding?api-version=2026-11-01"
	input := fmt.Sprintf(`{"subscriptionId":%q}`, tenant.SubscriptionID)
	if out := sourceAz("get", groups(tenant.SubscriptionID), "", tenantToken, ""); !bytes.Contains(out, []byte("retained-fixture")) {
		t.Fatal("tenant could not access its resource group before the decision")
	}
	sourceAz("put", offboard, input, tenantToken, "AuthorizationFailed")
	sourceAz("put", offboard, fmt.Sprintf(`{"subscriptionId":%q}`, neighbor.SubscriptionID), operatorToken, "ResourceNotFound")
	sourceAz("get", offboard, "", operatorToken, "ResourceNotFound")
	check := func(raw []byte) identity.HostedOffboarding {
		t.Helper()
		var got identity.HostedOffboarding
		if err := json.Unmarshal(raw, &got); err != nil || !got.Valid(tenant.TenantID) || got.SubscriptionID != tenant.SubscriptionID || got.Actor != operator {
			t.Fatalf("invalid audited offboarding decision: %v", err)
		}
		return got
	}
	decision := check(sourceAz("put", offboard, input, operatorToken, ""))
	retry := check(sourceAz("put", offboard, input, operatorToken, ""))
	if !retry.DecidedAt.Equal(decision.DecidedAt) {
		t.Fatal("repeated suspension replaced the original decision")
	}
	sourceAz("get", groups(tenant.SubscriptionID), "", tenantToken, "InvalidAuthenticationToken")
	verifyKeyDenied()

	restored, err := openRegion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.close() }()
	_, rawSub := restored.tenantKeys(tenant.TenantID)
	marker := restored.offboardingMarker(tenant.TenantID)
	before, err := restored.client.Txn(ctx).Then(clientv3.OpGet(rawSub, clientv3.WithCountOnly()),
		clientv3.OpGet(marker, clientv3.WithCountOnly())).Commit()
	if err != nil || before.Responses[0].GetResponseRange().Count != 1 || before.Responses[1].GetResponseRange().Count != 0 {
		t.Fatalf("test requires a pre-suspension subscription from the snapshot: %v", err)
	}
	origin, apiClient, az, _ := startHostedRestoreAPI(t, ctx, cfg, cli, operatorRealm, operatorClient, issuer.URL, issuer.Certificate())
	after, err := restored.client.Get(ctx, marker)
	if err != nil || len(after.Kvs) != 1 || !check(after.Kvs[0].Value).DecidedAt.Equal(decision.DecidedAt) {
		t.Fatalf("the restoration did not replay the independent decision: %v", err)
	}
	if err := restored.ready(ctx); err != nil {
		t.Fatal(err)
	}
	workerKey := restored.hostReservationKey(arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}, "worker-a", "fixture-guest")
	priorTask, err := restored.client.Get(ctx, workerKey, clientv3.WithCountOnly())
	if err != nil || priorTask.Count != 1 {
		t.Fatalf("the old snapshot did not preserve the suspended tenant's assignment: %v", err)
	}
	page, err := restored.HostAssignments(ctx, "worker-a", []byte("worker-a"), "")
	if err != nil || len(page.Assignments) != 1 || page.Assignments[0].TenantID != neighbor.TenantID {
		t.Fatalf("replayed suspension did not withhold the old host assignment: %v", err)
	}
	az("get", groups(tenant.SubscriptionID), "", sign(tenant.TenantID, operatorClient, tenant.Administrator, origin), "InvalidAuthenticationToken")
	neighborToken := sign(neighbor.TenantID, operatorClient, neighbor.Administrator, origin)
	if out := az("get", groups(neighbor.SubscriptionID), "", neighborToken, ""); !bytes.Contains(out, []byte("retained-fixture")) {
		t.Fatal("replay incorrectly blocked the neighboring tenant")
	}
	check(az("get", offboard, "", sign(operatorRealm, operatorClient, operator, origin), ""))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/"+tenant.TenantID+"/oauth2/v2.0/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reply, err := apiClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(reply.Body, 4096))
	if closeErr := reply.Body.Close(); closeErr != nil || readErr != nil || reply.StatusCode != http.StatusUnauthorized || !bytes.Contains(contents, []byte("invalid_grant")) {
		t.Fatalf("suspended OAuth grant reached the issuer: %v %v", readErr, closeErr)
	}
	verifyHostedTenantExport(t, ctx, restored, az, origin, tenant, neighbor, operatorClient, operatorRealm, operator, sign)
	stopLedger()
	az("get", groups(neighbor.SubscriptionID), "", neighborToken, "ServiceUnavailable")
	az("get", "/ocean/tenants/"+neighbor.TenantID+"/dataExport?api-version=2026-11-01", "", neighborToken, "ServiceUnavailable")
	startup, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	if err := restored.bootstrap(startup); err == nil {
		t.Fatal("restored startup succeeded without an authoritative ledger")
	}
	t.Logf("Azure CLI suspended the tenant and replayed its decision from the independent ledger before restored API startup. Old ARM and OAuth access and key export were denied, a neighboring tenant remained usable, and ledger loss blocked access and restart. Verification took %d ms.", time.Since(started).Milliseconds())
}

func startHostedRestoreAPI(t *testing.T, ctx context.Context, region regionConfig, cli, operatorRealm, operatorClient, issuer string,
	issuerCert *x509.Certificate) (string, *http.Client, func(string, string, string, string, string) []byte, func(string) (string, []byte)) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pemFile := func(name, kind string, raw []byte) string {
		t.Helper()
		return write(name, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw}))
	}
	keyFile := func(name string, key any) string {
		t.Helper()
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		return pemFile(name, "PRIVATE KEY", raw)
	}
	ca, signer, _, _ := directoryJoinClientCertificates(t)
	server := directoryLabServerTLS(t, ca, signer, net.IPv4(10, 0, 2, 2)).Certificates[0]
	caFile := pemFile("api-ca.pem", "CERTIFICATE", ca.Raw)
	tlsSettings := &config.TLS{CertificateFile: pemFile("api.pem", "CERTIFICATE", server.Certificate[0]), KeyFile: keyFile("api.key", server.PrivateKey),
		ClientCAFile: caFile, OptionalClientCA: true}
	var workers []enrollment.Approval
	for index, id := range region.Storage.Workers {
		workers = append(workers, enrollment.Approval{HostID: id, MAC: fmt.Sprintf("02:00:00:00:00:%02x", index+1), Address: fmt.Sprintf("10.80.0.%d", index+1),
			Profile: "restore-lab", Cell: region.InitialCell, Pool: "primary", Roles: []string{"compute"}, MinimumCPU: 1, MinimumMemoryMiB: 512,
			TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(rand.Text()))), ExpiresAt: time.Now().UTC().Add(15 * time.Minute)})
	}
	inventory, err := json.Marshal(map[string][]enrollment.Approval{"hosts": workers})
	if err != nil {
		t.Fatal(err)
	}
	address := disposableEtcdAddress(t)
	origin := "https://" + address
	secret := write("onboarding.key", []byte(rand.Text()+rand.Text()))
	initial := false
	region.OperationController = &initial
	contents, err := json.Marshal(settings{Server: config.Server{ListenAddress: address, TLS: tlsSettings}, Region: &region,
		HostEnrollment: &enrollment.Config{CertificateFile: caFile, KeyFile: keyFile("api-ca.key", signer), InventoryFile: write("inventory.json", inventory)},
		Identity: &identity.Config{Provider: issuer, Authority: issuer, ProviderCAFile: pemFile("issuer.pem", "CERTIFICATE", issuerCert.Raw),
			Cloud: &identity.CloudEndpoints{ResourceManager: origin, MicrosoftGraph: "https://graph.ocean.test"},
			Onboarding: &identity.OnboardingConfig{OperatorTenant: operatorRealm, OperatorClient: operatorClient,
				AdminEndpoints: []string{"https://admin.ocean.test"}, AdminClient: "fixture", AdminSecretFile: secret, RegionalKeyFile: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	restoreCtx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(restoreCtx, filepath.Join("..", "..", "bin", "ocean-control-plane"), "-config", write("api.json", contents))
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		stop()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("restored control plane: %s", output.String())
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	pollVMWorker(t, ctx, 12*time.Second, "restored API readiness", func() bool {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/readyz", nil)
		if err != nil {
			return false
		}
		reply, err := client.Do(request)
		if err != nil {
			return false
		}
		_ = reply.Body.Close()
		return reply.StatusCode == http.StatusNoContent
	})
	hostIdentity := func(host string) (string, []byte) {
		t.Helper()
		state := t.TempDir()
		certificate := directoryFixtureHostCertificate(t, ca, signer, host, 20)
		raw, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		for name, data := range map[string][]byte{"identity.key": raw, "identity.crt": certificate.Certificate[0]} {
			if err := os.WriteFile(filepath.Join(state, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		agent, err := json.Marshal(map[string]any{"enrollment": map[string]string{"origin": origin, "hostId": host, "managementInterface": "lab",
			"caFile": caFile, "tokenFile": filepath.Join(state, "unused"), "stateDirectory": state}})
		if err != nil {
			t.Fatal(err)
		}
		return write("worker-"+host+".json", agent), certificate.Certificate[0]
	}
	return origin, client, regionalWorkerCLI(t, ctx, origin, caFile, cli), hostIdentity
}
