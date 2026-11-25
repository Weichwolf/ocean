//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
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
	"github.com/Weichwolf/ocean/internal/network"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type windowsRecoveryArchive struct {
	Identity struct {
		DirectoryID string `json:"directoryId"`
		DNSName     string `json:"domain"`
		NetBIOSName string `json:"netbios"`
		SID         string `json:"domainSid"`
	} `json:"identity"`
	Digest string `json:"archiveSha256"`
	Policy string `json:"policySha256"`
}

func TestRegionalWindowsDirectoryRecovery(t *testing.T) {
	runRegionalWindowsDirectory(t, false)
}

func TestRegionalWindowsDirectoryGraph(t *testing.T) {
	runRegionalWindowsDirectory(t, true)
}

func runRegionalWindowsDirectory(t *testing.T, graphProbe bool) {
	t.Helper()
	state, archive := os.Getenv("OCEAN_E2E_WINDOWS_RECOVERY_STATE"), os.Getenv("OCEAN_E2E_WINDOWS_RECOVERY_ARCHIVE")
	endpoint, image := os.Getenv("OCEAN_E2E_DIRECTORY_ETCD"), os.Getenv("OCEAN_E2E_SAMBA_IMAGE")
	if state == "" || archive == "" || endpoint == "" || image == "" {
		t.Skip("requires the isolated Windows recovery lab, private backup, disposable etcd and Samba image ID")
	}
	if hexID, prefixed := strings.CutPrefix(image, "sha256:"); !prefixed || !directoryLabDigest(hexID) {
		t.Fatal("use a pinned local SHA-256 image ID")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Minute)
	defer cancel()
	vm, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := vm.Status()
	if err != nil || len(nodes) != 2 || !nodes[0].Running || !nodes[1].Running {
		t.Fatalf("start exactly two disposable Debian controllers before the probe: %v", err)
	}
	metadata := readWindowsRecoveryArchive(t, archive)
	backup := metadata.Identity
	if backup.DNSName != "ad.ocean.test" || backup.NetBIOSName != "OCEANLAB" {
		t.Fatal("backup is not from the Windows interoperability fixture")
	}
	private := t.TempDir()
	file := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	r := &Region{client: client, name: "farm-1", cell: "cell-1", root: "/ocean/tests/windows-directory/" + operationID(),
		directoryCapacity: enrollment.Capacity{CPUMillis: 600, MemoryMiB: 704}}
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
		defer stop()
		if _, err := client.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	}()
	key := file("regional.key", bytes.Repeat([]byte{6}, 32))
	r.workloads, err = openWorkloadControl(&workloadConfig{SecretsKeyFile: key,
		DefaultPlacement: PlacementPolicy{Pools: []string{"approved"}, Quota: addCapacity(r.directoryCapacity, r.directoryCapacity)}})
	if err != nil {
		t.Fatal(err)
	}
	var fencer ed25519.PrivateKey
	r.directoryFencer, fencer, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapDirectoryFencing(ctx); err != nil {
		t.Fatal(err)
	}
	tenant, old := seedWindowsRecoveryDirectory(t, ctx, r, metadata)

	issuer, sign, enableLogin := directoryJoinIssuer(t, tenant.TenantID)
	ca, caPrivate, _, _ := directoryJoinClientCertificates(t)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	caKey, err := x509.MarshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := enrollment.Open(enrollment.Config{
		CertificateFile: file("ca.pem", caPEM), KeyFile: file("ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKey})),
		InventoryFile: file("inventory.json", []byte(`{"hosts":[]}`)),
	}, r)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(nil)
	defer api.Close()
	graph := httptest.NewUnstartedServer(nil)
	defer graph.Close()
	origin := "https://" + api.Listener.Addr().String()
	graphOrigin := "https://" + graph.Listener.Addr().String()
	guestOrigin := directoryGuestOrigin(t, api)
	api.TLS = directoryLabServerTLS(t, ca, caPrivate)
	compat, err := (identity.Config{Authority: issuer.URL, Provider: issuer.URL,
		ProviderCAFile: file("issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})),
		Cloud:          &identity.CloudEndpoints{ResourceManager: origin, MicrosoftGraph: graphOrigin},
	}).OpenCompatibility()
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
	graph.Config.Handler = compat.Handler()
	api.Config.Handler = authority.Handler(graph.Config.Handler)
	graph.StartTLS()
	api.StartTLS()

	runID := operationID()
	stage := "ocean-recovery-" + runID
	fixture := directoryKVMHosts{root: root, state: state, directory: stage, t: t}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 12*time.Second)
		defer stop()
		fixture.shutdownAgents(cleanup)
	}()
	fixture.startAgents(ctx, r, nodes, guestOrigin, image, caPEM)
	go r.reconcileManagedDirectories(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pollDirectoryLab(t, ctx, "two enrolled KVM hosts to publish capacity", func() bool {
		fixture.refresh(ctx, nil)
		for _, host := range fixture.names {
			rows, err := client.Get(ctx, r.hostKey("live", host))
			var capacity enrollment.Availability
			if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &capacity) != nil ||
				!capacity.DirectoryRuntime || !fits(capacity.Capacity, enrollment.Capacity{}, r.directoryCapacity) {
				return false
			}
		}
		return true
	})
	t.Log("Both Debian KVM guests enrolled over HTTPS and advertised directory capacity over mTLS.")

	fence := identity.DirectoryRecoveryFence{Action: identity.RecoverDirectory, TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DirectoryID: backup.DirectoryID, RecoveryID: runID,
		BackupSHA256: metadata.Digest, Observation: "PoweredOff", ObservedAt: time.Now().UTC()}
	for _, reservation := range old.Controllers {
		fence.Controllers = append(fence.Controllers, identity.DirectoryRecoveryController{
			HostID: reservation.HostID, PlacementID: reservation.ID, Generation: reservation.Generation})
	}
	attestation, _ := json.Marshal(fence)
	body, _ := json.Marshal(identity.SignedDirectoryFence{Attestation: attestation, Signature: ed25519.Sign(fencer, attestation)})
	signed := file("fence.json", body)
	caBundle := file("api.pem", caPEM)
	token := sign(origin, tenant.Administrator)
	az := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "az", args...)
		cmd.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+filepath.Join(private, "az"), "REQUESTS_CA_BUNDLE="+caBundle,
			"AZURE_CORE_COLLECT_TELEMETRY=0", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("az %s: %v: %s", args[0], err, strings.ReplaceAll(string(out), token, "[fixture token]"))
		}
		return out
	}
	var version struct {
		CLI        string            `json:"azure-cli"`
		Extensions map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(az("version", "-o", "json"), &version); err != nil ||
		version.CLI != "2.93.0" || len(version.Extensions) != 0 {
		t.Fatal("the recovery probe requires the pinned Azure CLI and no extensions")
	}
	path := origin + "/ocean/tenants/" + tenant.TenantID + "/directory"
	query := "?api-version=2026-11-01"
	rest := func(method, suffix string, target any, extra ...string) {
		t.Helper()
		token = sign(origin, tenant.Administrator)
		args := []string{"rest", "--method", method, "--url", path + suffix + query,
			"--headers", "Authorization=Bearer " + token, "--only-show-errors", "-o", "json"}
		if err := json.Unmarshal(az(append(args, extra...)...), target); err != nil {
			t.Fatalf("invalid az %s response: %v", method, err)
		}
	}
	suffix := "/recoveries/" + runID
	var recovery identity.DirectoryRecovery
	rest("put", suffix, &recovery, "--body", "@"+signed)
	if recovery.ID != runID || recovery.BackupSHA != metadata.Digest || recovery.State != identity.DirectoryRecoveryFenced {
		t.Fatalf("unexpected signed recovery admission: %+v", recovery)
	}
	pollDirectoryLab(t, ctx, "the regional controller to reserve both replacements", func() bool {
		fixture.refresh(ctx, nil)
		rest("get", suffix, &recovery)
		return recovery.State == identity.DirectoryRecoveryStaged
	})
	if recovery.Writer != fixture.names[0] {
		t.Fatalf("the restored writer has an unexpected host: %s", recovery.Writer)
	}
	fixture.stageArchive(ctx, recovery.Writer, runID, archive)
	t.Log("Azure CLI submitted the signed recovery. The operator staged the archive on the assigned writer.")
	var stateView directoryLabView
	pollDirectoryLab(t, ctx, "both real agents to restore, bind and report the original domain", func() bool {
		fixture.refresh(ctx, []string{"10.232.1.11/24", "10.232.1.12/24"})
		rest("get", suffix, &recovery)
		return recovery.State == identity.DirectoryRecoveryReady
	})
	rest("get", "", &stateView)
	if stateView.ID != backup.DirectoryID || stateView.Availability != "Available" || len(stateView.Controllers) != 2 ||
		!stateView.Controllers[0].Writer || !stateView.Controllers[0].Ready || !stateView.Controllers[1].Ready {
		t.Fatalf("the API did not report both real replacements: %+v", stateView)
	}
	fixture.removeStagedArchive(ctx, recovery.Writer, runID)
	t.Log("The real node agents completed offline restore, startup authorization and standby join.")
	placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
	stored, err := client.Get(ctx, placementKey)
	var restored directoryPlacement
	if err != nil || len(stored.Kvs) != 1 || json.Unmarshal(stored.Kvs[0].Value, &restored) != nil {
		t.Fatal("the regional fixture lost the recovered placement")
	}
	// The disposable Windows fixtures use the recovered domain administrator
	// for their secure-channel and policy ACL probes.
	diagnostic, err := r.workloads.sealer.Open(nil, nil, restored.Bootstrap, restored.bootstrapLabel(placementKey))
	if err != nil {
		t.Fatal(err)
	}
	diagnosticPath := filepath.Join(state, "recovery-fixture-admin.secret")
	writeWindowsRecoverySecret(t, diagnosticPath, diagnostic)
	defer func() { _ = os.Remove(diagnosticPath) }()
	if graphProbe {
		app, secret := operationID(), rand.Text()
		enableLogin(api.URL, graph.URL, app, secret, tenant.Administrator)
		verifyRegionalWindowsGraph(t, regionalGraphFixture{ctx: ctx, private: private, api: api, graph: graph, apiCA: caPEM,
			issuer: issuer, tenant: tenant, app: app, secret: secret}, fixture, runID, metadata, stateView.Controllers[0])
		return
	}
	verifyRegionalWindowsClients(t, ctx, vm, fixture, runID, metadata, stateView, func() directoryLabView {
		var view directoryLabView
		rest("get", "", &view)
		return view
	})
}

type directoryLabView struct {
	ID           string                                  `json:"directoryId"`
	Availability string                                  `json:"availability"`
	Controllers  []identity.DirectoryControllerReadiness `json:"controllers"`
}

func directoryGuestOrigin(t *testing.T, api *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + net.JoinHostPort("10.0.2.2", port)
}

func readWindowsRecoveryArchive(t *testing.T, archive string) windowsRecoveryArchive {
	t.Helper()
	var metadata windowsRecoveryArchive
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(archive), "metadata.json"))
	if err != nil || json.Unmarshal(raw, &metadata) != nil || !enrollment.ValidDirectoryJoinID(metadata.Identity.DirectoryID) ||
		!(enrollment.DirectoryHealth{Ready: true, DomainSID: metadata.Identity.SID}).Valid() ||
		!directoryLabDigest(metadata.Policy) || !directoryLabDigest(metadata.Digest) {
		t.Fatalf("invalid backup manifest or missing policy digest: %v", err)
	}
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("the recovery archive must be a private regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || fmt.Sprintf("%x", hash.Sum(nil)) != metadata.Digest {
		t.Fatalf("the staged archive does not match its manifest: %v", err)
	}
	return metadata
}

func directoryLabDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func writeWindowsRecoverySecret(t *testing.T, path string, secret []byte) {
	t.Helper()
	defer clear(secret)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(secret)
	if err := file.Close(); err != nil || writeErr != nil {
		_ = os.Remove(path)
		t.Fatalf("write private Windows fixture credential: %v %v", writeErr, err)
	}
}

func directoryLabServerTLS(t *testing.T, ca *x509.Certificate, signer ed25519.PrivateKey) *tls.Config {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(4), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.2")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{raw}, PrivateKey: key}}}
}

func seedDirectoryTenantNetwork(t *testing.T, ctx context.Context, r *Region, label string) (identity.TenantReservation, string) {
	t.Helper()
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(),
		Administrator: operationID(), Fingerprint: operationID()}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID,
		SubscriptionID: tenant.SubscriptionID, DisplayName: label, Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: "lab", Location: r.name, Tags: map[string]string{}}, tenant.Administrator); err != nil {
		t.Fatal(err)
	}
	vnet := arm.ResourceAddress{Group: "lab", Path: "Microsoft.Network/virtualNetworks/directory"}
	subnet := vnet.ID(scope) + "/subnets/office"
	properties, _ := json.Marshal(network.VNetProperties{AddressSpace: network.AddressSpace{Prefixes: []string{"10.232.1.0/24"}},
		ProvisioningState: "Succeeded", Subnets: []network.Subnet{network.NewSubnet(vnet.ID(scope), "office",
			network.SubnetProperties{AddressPrefix: "10.232.1.0/24"})}})
	if err := r.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: vnet, APIVersion: network.VNetAPIVersion,
		Location: r.name, ProvisioningState: "Succeeded", Properties: properties}); err != nil {
		t.Fatal(err)
	}
	return tenant, subnet
}

func seedWindowsRecoveryDirectory(t *testing.T, ctx context.Context, r *Region, backup windowsRecoveryArchive) (identity.TenantReservation, directoryPlacement) {
	t.Helper()
	t.Helper()
	tenant, subnet := seedDirectoryTenantNetwork(t, ctx, r, "Windows recovery fixture")
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	domain, err := r.RequestManagedDirectory(ctx, tenant, identity.DirectorySpec{DNSName: backup.Identity.DNSName,
		NetBIOSName: backup.Identity.NetBIOSName, SubnetID: subnet})
	if err != nil {
		t.Fatal(err)
	}
	// This fixture imports the established identity from an independent
	// backup. The two former host records stand for the fenced source slots.
	domain.ID, domain.DomainSID, domain.ProvisionedAt = backup.Identity.DirectoryID, backup.Identity.SID, time.Now().UTC()
	parent, name, _ := arm.SubnetParent(scope, domain.Spec.SubnetID)
	writes := []clientv3.Op{putJSON(r.managedDirectoryKey(tenant.TenantID), domain),
		clientv3.OpPut(r.managedDirectorySubnetLock(scope, parent, name), domain.ID),
		clientv3.OpPut(r.root+"/cells/"+r.cell+"/metadata", "{}")}
	addresses := r.subnetNetworkPlacements(scope, parent, name)
	for host := 4; host < 11; host++ {
		writes = append(writes, clientv3.OpPut(addresses+fmt.Sprintf("10.232.1.%d", host), "fixture-reservation"))
	}
	lease, err := r.client.Grant(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fenced-source-01", "fenced-source-02"} {
		host := enrollment.Host{HostID: name, Cell: r.cell, Pool: "approved", Roles: []string{"compute"}, Certificate: []byte(name)}
		report := enrollment.Availability{HostID: host.HostID, Cell: host.Cell, Pool: host.Pool, Roles: host.Roles,
			Capacity: r.directoryCapacity, DirectoryRuntime: true, ContainerNetwork: true}
		raw, _ := json.Marshal(report)
		writes = append(writes, putJSON(r.hostKey("registered", name), host),
			clientv3.OpPut(r.hostKey("live", name), string(raw), clientv3.WithLease(lease.ID)))
	}
	if _, err := r.client.Txn(ctx).Then(writes...).Commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.placeManagedDirectory(ctx, tenant.TenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Revoke(ctx, lease.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := r.client.Get(ctx, r.managedDirectoryPlacementKey(tenant.TenantID))
	var placed directoryPlacement
	if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placed) != nil ||
		placed.Controllers[0].PrivateIPv4.String() != "10.232.1.11" || placed.Controllers[1].PrivateIPv4.String() != "10.232.1.12" {
		t.Fatalf("could not restore the original addressing in the former slots: %v", err)
	}
	return tenant, placed
}

func pollDirectoryLab(t *testing.T, ctx context.Context, action string, done func() bool) {
	t.Helper()
	for {
		if done() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", action, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
