//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/nodeagent"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestRegionalDirectoryJoin(t *testing.T) {
	endpoint, samba, adcli := os.Getenv("OCEAN_E2E_DIRECTORY_ETCD"), os.Getenv("OCEAN_E2E_SAMBA_IMAGE"), os.Getenv("OCEAN_E2E_ADCLI_IMAGE")
	if endpoint == "" || samba == "" || adcli == "" {
		t.Skip("requires disposable etcd and the Samba and adcli fixture images")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	container, network, address, sid := holdDirectoryForJoin(t, root, dir, samba)
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r := &Region{client: client, name: "farm-1", cell: "cell-1", root: "/ocean/tests/directory-join/" + operationID(),
		directoryCapacity: enrollment.Capacity{CPUMillis: 400, MemoryMiB: 384}}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := client.Delete(cleanup, r.root+"/", clientv3.WithPrefix())
		if err != nil {
			t.Error(err)
		}
	}()
	file := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := file("workload.key", bytes.Repeat([]byte{6}, 32))
	r.workloads, err = openWorkloadControl(&workloadConfig{SecretsKeyFile: key,
		DefaultPlacement: PlacementPolicy{Pools: []string{"approved"}, Quota: r.directoryCapacity}})
	if err != nil {
		t.Fatal(err)
	}
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: "fixture"}
	member := operationID()
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	subscription := identity.Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		DisplayName: "Regional Directory Lab", Members: []string{tenant.Administrator, member}}
	if _, err := r.PublishSubscription(ctx, tenant, subscription); err != nil {
		t.Fatal(err)
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	vnet := arm.ResourceAddress{Group: "lab", Path: "Microsoft.Network/virtualNetworks/directory"}
	domain := identity.ManagedDirectory{ID: operationID(), TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		RequestedAt: time.Now().Add(-time.Minute), ProvisionedAt: time.Now(), DomainSID: sid,
		Spec: identity.DirectorySpec{DNSName: "ad.runtime.test", NetBIOSName: "OCEANRUN", SubnetID: strings.ToLower(vnet.ID(scope) + "/subnets/office")}}
	primary := Reservation{ID: operationID(), HostID: "join-writer", Generation: operationID(), PrivateIPv4: netip.MustParseAddr(address)}
	replica := Reservation{ID: operationID(), HostID: "join-replica", Generation: operationID(), PrivateIPv4: netip.MustParseAddr("10.254.247.12")}
	pair := directoryPlacement{DirectoryID: domain.ID, Controllers: [2]Reservation{primary, replica}}
	ca, caPrivate, writerCert, replicaCert := directoryJoinClientCertificates(t)
	caFile := file("enrollment-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	der, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := enrollment.Open(enrollment.Config{CertificateFile: caFile,
		KeyFile:       file("enrollment-ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		InventoryFile: file("inventory.json", []byte(`{"hosts":[]}`))}, r)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Grant(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Txn(ctx).Then(putJSON(r.managedDirectoryKey(tenant.TenantID), domain),
		putJSON(r.managedDirectoryPlacementKey(tenant.TenantID), pair)).Commit(); err != nil {
		t.Fatal(err)
	}
	assignments := make([]enrollment.Assignment, 2)
	for i, controller := range pair.Controllers {
		cert := []tls.Certificate{writerCert, replicaCert}[i]
		host := enrollment.Host{HostID: controller.HostID, Cell: r.cell, Pool: "approved", Roles: []string{"compute"}, Certificate: cert.Certificate[0]}
		live := enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles, DirectoryRuntime: true}
		assigned := enrollment.Assignment{ID: controller.ID, Generation: controller.Generation, TenantID: tenant.TenantID,
			SubscriptionID: tenant.SubscriptionID, PrivateIPv4: controller.PrivateIPv4, Directory: &enrollment.DirectoryAssignment{
				DirectoryID: domain.ID, DNSName: domain.Spec.DNSName, NetBIOSName: domain.Spec.NetBIOSName, ControllerIndex: i + 1,
				ControllerIPv4: [2]netip.Addr{primary.PrivateIPv4, replica.PrivateIPv4}}}
		data, _ := json.Marshal(live)
		if _, err := client.Txn(ctx).Then(putJSON(r.hostKey("registered", host.HostID), host),
			clientv3.OpPut(r.hostKey("live", host.HostID), string(data), clientv3.WithLease(lease.ID)),
			putJSON(r.hostReservationKey(scope, host.HostID, controller.ID), assigned)).Commit(); err != nil {
			t.Fatal(err)
		}
		assignments[i] = assigned
	}
	observe := func() {
		t.Helper()
		if err := r.ReportDirectoryHealth(ctx, primary.HostID, writerCert.Certificate[0], tenant.TenantID, primary.Generation,
			enrollment.DirectoryHealth{Ready: true, DomainSID: sid}); err != nil {
			t.Fatal(err)
		}
	}
	issuer, sign := directoryJoinIssuer(t, tenant.TenantID)
	ready := make(chan struct{})
	var handler http.Handler
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-ready
		handler.ServeHTTP(w, req)
	}))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	api.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	api.StartTLS()
	defer api.Close()
	compat, err := (identity.Config{Authority: "https://id.ocean.test", Provider: issuer.URL,
		ProviderCAFile: file("provider.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})),
		Cloud:          &identity.CloudEndpoints{ResourceManager: api.URL, MicrosoftGraph: "https://graph.ocean.test"}}).OpenCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	compat.EnableSubscriptions(r.name, r.lookupSubscription)
	if err := compat.EnableOnboarding(identity.OnboardingConfig{OperatorTenant: operationID(), OperatorClient: operationID(),
		AdminEndpoints: []string{"https://private.ocean.test"}, AdminClient: "lab", AdminSecretFile: key, RegionalKeyFile: key}, r); err != nil {
		t.Fatal(err)
	}
	if err := compat.EnableManagedDirectories(r); err != nil {
		t.Fatal(err)
	}
	handler = authority.Handler(compat.Handler())
	close(ready)

	authorization := operationID()
	path := "/ocean/tenants/" + tenant.TenantID + "/directory/joinAuthorizations/" + authorization
	query := "?api-version=2026-11-01"
	token, password := sign(api.URL, tenant.Administrator), "Join9-"+rand.Text()+rand.Text()
	expires := time.Now().Add(2 * time.Minute).Unix()
	body, _ := json.Marshal(map[string]any{"machineName": "REGIONJOIN", "expiresAt": expires, "password": password})
	input := file("authorization.json", body)
	caBundle := file("api.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}))
	runAz := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "az", args...)
		cmd.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+filepath.Join(dir, "az"), "REQUESTS_CA_BUNDLE="+caBundle,
			"AZURE_CORE_COLLECT_TELEMETRY=0", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Azure CLI %s returned %v: %s", args[0], err,
				strings.NewReplacer(token, "[fixture token]", password, "[join password]").Replace(string(out)))
		}
		return out
	}
	var version struct {
		CLI        string            `json:"azure-cli"`
		Extensions map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(runAz("version", "-o", "json"), &version); err != nil || version.CLI != "2.93.0" || len(version.Extensions) != 0 {
		t.Fatal("the directory join probe requires the pinned CLI")
	}
	rest := func(method, suffix, want string, extra ...string) {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", api.URL + path + suffix + query, "--headers", "Authorization=Bearer " + token, "--only-show-errors", "-o", "json"}
		out := runAz(append(args, extra...)...)
		var view identity.DirectoryJoinAuthorization
		if bytes.Contains(out, []byte(password)) || json.Unmarshal(out, &view) != nil || view.State != want || view.ID != authorization {
			t.Fatalf("az rest %s did not return authorization state %s (got %s)", method, want, view.State)
		}
		if want == identity.DirectoryJoinReady && !strings.HasSuffix(view.UPN, "@"+domain.Spec.DNSName) {
			t.Fatal("ready authorization has no eligible UPN")
		}
	}
	httpStatus := func(h *http.Client, method, url, bearer string, data []byte) int {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			request.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := h.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	mtls := func(cert tls.Certificate) *http.Client {
		transport := api.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	writer, peer := mtls(writerCert), mtls(replicaCert)
	taskURL := func(controller Reservation) string {
		return api.URL + "/ocean/hosts/" + controller.HostID + "/directories/" + tenant.TenantID + "/" + controller.Generation + "/join-task"
	}
	if httpStatus(api.Client(), "PUT", api.URL+path+query, sign(api.URL, member), body) != http.StatusForbidden ||
		httpStatus(api.Client(), "GET", api.URL+strings.Replace(path, tenant.TenantID, operationID(), 1)+query, token, nil) != http.StatusForbidden {
		t.Fatal("a non-administrator or foreign tenant could access a join authorization")
	}
	observe()
	rest("put", "", identity.DirectoryJoinPending, "--body", "@"+input)
	rest("put", "", identity.DirectoryJoinPending, "--body", "@"+input)
	otherAuthorization := strings.Replace(path, authorization, operationID(), 1)
	expiredBody, _ := json.Marshal(map[string]any{"machineName": "EXPIRED", "expiresAt": time.Now().Unix() - 1, "password": password})
	if httpStatus(api.Client(), "PUT", api.URL+otherAuthorization+query, token, expiredBody) != http.StatusBadRequest ||
		httpStatus(api.Client(), "PUT", api.URL+otherAuthorization+query, token, body) != http.StatusConflict {
		t.Fatal("an expired request or a competing join task entered the queue")
	}
	queued, err := client.Get(ctx, r.directoryJoinKey(domain, ""), clientv3.WithPrefix())
	if err != nil || queued.Count != 2 {
		t.Fatal("the region did not enqueue one durable receipt and one pending task")
	}
	for _, kv := range queued.Kvs {
		if bytes.Contains(kv.Value, []byte(password)) || (strings.HasSuffix(string(kv.Key), "/pending") && kv.Lease == 0) {
			t.Fatal("the region stored an unsealed or unbounded join credential")
		}
	}
	if httpStatus(api.Client(), "GET", taskURL(primary), "", nil) != http.StatusUnauthorized ||
		httpStatus(peer, "GET", taskURL(primary), "", nil) != http.StatusForbidden ||
		httpStatus(peer, "GET", taskURL(replica), "", nil) != http.StatusForbidden {
		t.Fatal("an uncertified or replica host could read the writer's credential")
	}
	stale, _ := json.Marshal(map[string]any{"attempt": operationID(), "succeeded": true})
	if httpStatus(writer, "POST", taskURL(primary), "", stale) != http.StatusConflict {
		t.Fatal("a stale join acknowledgement was accepted")
	}
	drain := func() {
		t.Helper()
		if err := nodeagent.RunDirectoryJoinFixture(ctx, api.URL, primary.HostID, writer, container, assignments[0]); err != nil {
			t.Fatal(err)
		}
	}
	drain()
	rest("get", "", identity.DirectoryJoinReady)
	rest("put", "", identity.DirectoryJoinReady, "--body", "@"+input)
	observe()
	rest("post", "/close", identity.DirectoryJoinClosing)
	drain()
	rest("get", "", identity.DirectoryJoinReady)
	machine := enrollment.DirectoryJoinInput{ID: authorization, Machine: "REGIONJOIN"}
	ad := func() ([]byte, error) {
		cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "lab/run_adcli_probe.sh"), adcli, network, address, machine.Machine, machine.Username())
		cmd.Stdin = strings.NewReader(password + "\n")
		return cmd.CombinedOutput()
	}
	if out, err := ad(); err != nil {
		t.Fatalf("the regional authorization failed at the real Debian client: %v: %s", err, strings.ReplaceAll(string(out), password, "[join password]"))
	}
	observe()
	rest("post", "/close", identity.DirectoryJoinClosing)
	drain()
	rest("get", "", identity.DirectoryJoinClosed)
	rest("post", "/close", identity.DirectoryJoinClosed)
	if out, err := ad(); err == nil || !bytes.Contains(out, []byte("credentials have been revoked")) {
		t.Fatal("the real Debian client reused a closed authorization")
	}
	if stored, err := client.Get(ctx, r.directoryJoinKey(domain, "pending")); err != nil || stored.Count != 0 {
		t.Fatal("closing the authorization retained a pending task")
	}
	t.Log("Azure CLI 2.93.0 issued and closed a real AD join through etcd and the authenticated node agent. Debian verified machine trust and rejected the revoked principal.")
}

func holdDirectoryForJoin(t *testing.T, root, temp, image string) (string, string, string, string) {
	t.Helper()
	path := filepath.Join(temp, "controller-ready")
	cmd := exec.Command("bash", filepath.Join(root, "lab/verify_samba_controller.sh"), image, "--hold-controller")
	cmd.Env = append(os.Environ(), "OCEAN_E2E_DIRECTORY_HANDOFF="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(temp, "controller.log")
	output, err := os.Create(log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cleaned := false
	t.Cleanup(func() {
		_ = stdin.Close()
		if cleaned {
			return
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("directory fixture cleanup: %v", err)
			}
		case <-time.After(35 * time.Second):
			_ = cmd.Process.Kill()
			t.Error("the directory fixture did not exit")
		}
	})
	for until := time.Now().Add(45 * time.Second); time.Now().Before(until); {
		select {
		case err := <-done:
			cleaned = true
			data, _ := os.ReadFile(log)
			t.Fatalf("the directory fixture stopped: %v: %s", err, data)
		case <-time.After(250 * time.Millisecond):
		}
		if info, err := os.ReadFile(path); err == nil {
			fields := strings.Fields(string(info))
			if len(fields) != 4 {
				t.Fatal("invalid directory fixture handoff")
			}
			return fields[0], fields[1], fields[2], fields[3]
		}
	}
	t.Fatal("the directory fixture did not report ready")
	return "", "", "", ""
}

func directoryJoinClientCertificates(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, tls.Certificate, tls.Certificate) {
	t.Helper()
	validAfter, validBefore := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	keypair := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	cert := func(template, issuer *x509.Certificate, public ed25519.PublicKey, signer ed25519.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		result, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ocean directory fixture CA"},
		NotBefore: validAfter, NotAfter: validBefore, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	public, private := keypair()
	ca = cert(ca, ca, public, private)
	leaf := func(serial int64) tls.Certificate {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Ocean directory fixture host"},
			NotBefore: validAfter, NotAfter: validBefore, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		public, key := keypair()
		certificate := cert(template, ca, public, private)
		return tls.Certificate{Certificate: [][]byte{certificate.Raw}, PrivateKey: key, Leaf: certificate}
	}
	return ca, private, leaf(2), leaf(3)
}

func directoryJoinIssuer(t *testing.T, tenant string) (*httptest.Server, func(string, string) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/realms/"+tenant+"/protocol/openid-connect/certs" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]map[string]string{
			"keys": {{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture", "n": encode(key.N.Bytes()), "e": "AQAB"}},
		})
	}))
	t.Cleanup(server.Close)
	return server, func(audience, subject string) string {
		t.Helper()
		claims, _ := json.Marshal(map[string]any{"iss": server.URL + "/realms/" + tenant, "sub": subject,
			"aud": audience, "typ": "Bearer", "exp": time.Now().Add(2 * time.Minute).Unix()})
		unsigned := encode([]byte(`{"alg":"RS256","kid":"fixture"}`)) + "." + encode(claims)
		digest := sha256.Sum256([]byte(unsigned))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return unsigned + "." + encode(signature)
	}
}
