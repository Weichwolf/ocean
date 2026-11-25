//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type directoryClientProof struct {
	Controller   string `json:"controller"`
	Address      string `json:"address"`
	PolicySHA256 string `json:"policySha256"`
}

func TestPackagedDirectoryProvisioning(t *testing.T) {
	state, endpoint, image := os.Getenv("OCEAN_E2E_PACKAGED_DIRECTORY_STATE"),
		os.Getenv("OCEAN_E2E_DIRECTORY_ETCD"), os.Getenv("OCEAN_E2E_SAMBA_IMAGE")
	if state == "" || endpoint == "" || image == "" {
		t.Skip("requires the disposable three-guest directory lab, etcd and a local Samba image")
	}
	if hexID, prefixed := strings.CutPrefix(image, "sha256:"); !prefixed || !directoryLabDigest(hexID) {
		t.Fatal("use a pinned local SHA-256 image ID")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	vm, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := vm.Status()
	if err != nil || len(nodes) != 3 || nodes[2].Guest.Name != packagedDirectoryClient {
		t.Fatalf("the packaged directory probe requires its disposable three-guest topology: %v", err)
	}
	for _, node := range nodes {
		if !node.Running {
			t.Fatalf("the disposable guest %s is not running", node.Guest.Name)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	private := t.TempDir()
	file := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(private, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	etcd, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer etcd.Close()
	runID := operationID()
	r := &Region{client: etcd, name: "farm-1", cell: "cell-1", root: "/ocean/tests/packaged-directory/" + runID,
		directoryCapacity: enrollment.Capacity{CPUMillis: 600, MemoryMiB: 704}}
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
		defer stop()
		if _, err := etcd.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	}()
	key := file("regional.key", bytes.Repeat([]byte{4}, 32))
	r.workloads, err = openWorkloadControl(&workloadConfig{SecretsKeyFile: key, DefaultPlacement: PlacementPolicy{
		Pools: []string{"approved"}, Quota: addCapacity(r.directoryCapacity, r.directoryCapacity)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapManagedDirectories(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := etcd.Put(ctx, r.root+"/cells/"+r.cell+"/metadata", "{}"); err != nil {
		t.Fatal(err)
	}
	tenant, subnet := seedDirectoryTenantNetwork(t, ctx, r, "Packaged directory fixture")
	foreign, _ := seedDirectoryTenantNetwork(t, ctx, r, "Foreign directory fixture")
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
	api, graph := httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	defer api.Close()
	defer graph.Close()
	origin, graphOrigin := "https://"+api.Listener.Addr().String(), "https://"+graph.Listener.Addr().String()
	guestOrigin := "https://" + net.JoinHostPort("10.0.2.2", fmt.Sprint(api.Listener.Addr().(*net.TCPAddr).Port))
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

	hosts := directoryKVMHosts{root: root, state: state, directory: "directory-lab-" + runID, t: t}
	online := map[string]bool{nodes[0].Guest.Name: true, nodes[1].Guest.Name: true}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 18*time.Second)
		defer stop()
		hosts.stopPackagedAgents(cleanup, online)
	}()
	hosts.startPackagedAgents(ctx, r, nodes[:2], guestOrigin, image, caPEM)
	go r.reconcileManagedDirectories(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pollDirectoryLab(t, ctx, "both packaged agents to enroll and advertise directory networking", func() bool {
		for _, host := range hosts.names {
			rows, err := etcd.Get(ctx, r.hostKey("live", host))
			var capacity enrollment.Availability
			if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &capacity) != nil ||
				!capacity.DirectoryRuntime || !capacity.ContainerNetwork || !fits(capacity.Capacity, enrollment.Capacity{}, r.directoryCapacity) {
				return false
			}
		}
		return true
	})
	t.Log("The two packaged agents enrolled and advertised the directory runtime and workload network.")

	app, secret := operationID(), rand.Text()
	enableLogin(api.URL, graph.URL, app, secret, tenant.Administrator)
	az := (regionalGraphFixture{ctx: ctx, private: private, api: api, graph: graph, apiCA: caPEM,
		issuer: issuer, tenant: tenant, app: app, secret: secret}).loginCLI(t)
	link := func(tenant string) string {
		return origin + "/ocean/tenants/" + tenant + "/directory?api-version=2026-11-01"
	}
	type status struct {
		directoryLabView
		Provisioning string `json:"provisioningState"`
	}
	rest := func(method string, extra ...string) status {
		t.Helper()
		args := []string{"rest", "--method", method, "--url", link(tenant.TenantID), "--only-show-errors", "-o", "json"}
		var view status
		if err := json.Unmarshal(az(false, append(args, extra...)...), &view); err != nil || !enrollment.ValidDirectoryJoinID(view.ID) {
			t.Fatalf("invalid directory state: %v", err)
		}
		return view
	}
	assertDenied := func(id, code string, args ...string) {
		t.Helper()
		request := []string{"rest", "--method", "get", "--url", link(id), "--only-show-errors", "-o", "json"}
		if !bytes.Contains(az(true, append(request, args...)...), []byte(code)) {
			t.Fatalf("expected Azure CLI error %s", code)
		}
	}
	// Use the normal CLI login for the original and foreign tenant requests.
	// Sign a separate test token to exercise the tenant administrator check.
	assertDenied(tenant.TenantID, "ResourceNotFound")
	assertDenied(foreign.TenantID, "AuthorizationFailed")
	assertDenied(tenant.TenantID, "AuthorizationFailed", "--headers", "Authorization=Bearer "+sign(origin, operationID()))

	const domain = "ad.packaged.test"
	request, _ := json.Marshal(identity.DirectorySpec{DNSName: domain, NetBIOSName: "OCEANPKG", SubnetID: subnet})
	body := []string{"--body", "@" + file("request.json", request)}
	requested := time.Now()
	first := rest("put", body...)
	if first.Provisioning != "Creating" || rest("put", body...).ID != first.ID {
		t.Fatal("fresh directory request or replay returned an unexpected state")
	}
	var ready status
	pollDirectoryLab(t, ctx, "fresh packaged Samba controllers to become available", func() bool {
		ready = rest("get")
		return ready.Provisioning == "Succeeded" && ready.Availability == "Available"
	})
	availableAfter := time.Since(requested).Milliseconds()
	if ready.ID != first.ID || len(ready.Controllers) != 2 || !ready.Controllers[0].Ready || !ready.Controllers[0].Writer ||
		!ready.Controllers[1].Ready || ready.Controllers[1].Writer {
		t.Fatalf("unexpected API readiness: %+v", ready)
	}
	if replay := rest("put", body...); replay.ID != ready.ID || replay.Availability != "Available" {
		t.Fatal("the original directory identity or availability changed on replay")
	}
	t.Logf("Stock Azure CLI created one directory and reported both fresh packaged controllers available after %d ms.", availableAfter)

	placementKey := r.managedDirectoryPlacementKey(tenant.TenantID)
	rows, err := etcd.Get(ctx, placementKey)
	var placement directoryPlacement
	if err != nil || len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &placement) != nil ||
		placement.DirectoryID != ready.ID || placement.Controllers[0].HostID == placement.Controllers[1].HostID {
		t.Fatalf("the two available controllers did not have distinct current placements: %v", err)
	}
	password, err := r.workloads.sealer.Open(nil, nil, placement.Bootstrap, placement.bootstrapLabel(placementKey))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	var proof [2]directoryClientProof
	var versions [2]string
	for i, controller := range ready.Controllers {
		host := placement.Controllers[i].HostID
		if !online[host] {
			t.Fatalf("the region used a host outside the packaged fixture: %s", host)
		}
		versions[i] = hosts.packagedAttachment(ctx, host, controller.PrivateIPv4.String())
		proof[i] = hosts.probePackagedDirectory(ctx, controller.DNSName, controller.PrivateIPv4.String(), domain, password)
		t.Logf("Debian reached %s over the routed network from ocean-agent %s on %s.", controller.DNSName, versions[i], host)
	}
	if proof[0].PolicySHA256 != proof[1].PolicySHA256 {
		t.Fatal("fresh controllers returned different SYSVOL data")
	}
	failures := verifyPackagedDirectoryFailures(t, ctx, vm, hosts, online, placement, ready.Controllers, func() directoryLabView {
		return rest("get").directoryLabView
	}, domain, password, proof[0].PolicySHA256)
	writeDirectoryLabResult(t, filepath.Join(state, "evidence", "packaged-directory.json"), map[string]any{
		"runId": runID, "directoryId": ready.ID, "controllerHosts": [2]string{placement.Controllers[0].HostID, placement.Controllers[1].HostID},
		"packageVersions": versions, "availableAfterMs": availableAfter, "initialProbes": proof, "outageProbes": failures,
	})
}

type directoryOutageProof struct {
	PoweredOff      string               `json:"poweredOff"`
	DegradedAfterMS int64                `json:"degradedAfterMs"`
	Client          directoryClientProof `json:"client"`
}

func verifyPackagedDirectoryFailures(t *testing.T, ctx context.Context, vm *lab.Lab,
	hosts directoryKVMHosts, online map[string]bool, placement directoryPlacement, controllers []identity.DirectoryControllerReadiness,
	read func() directoryLabView, domain string, password []byte, policy string) []directoryOutageProof {
	t.Helper()
	var failures []directoryOutageProof
	for _, down := range []int{1, 0} {
		host := placement.Controllers[down].HostID
		if err := vm.Stop(host); err != nil {
			t.Fatal(err)
		}
		online[host] = false
		started := time.Now()
		pollDirectoryLab(t, ctx, "the region to observe the stopped controller", func() bool {
			view := read()
			return view.Availability == "Degraded" && len(view.Controllers) == 2 &&
				!view.Controllers[down].Ready && view.Controllers[1-down].Ready
		})
		degraded := time.Since(started).Milliseconds()
		survivor := controllers[1-down]
		proof := hosts.probePackagedDirectory(ctx, survivor.DNSName, survivor.PrivateIPv4.String(), domain, password)
		if proof.PolicySHA256 != policy {
			t.Fatal("the surviving controller lost the original SYSVOL data")
		}
		failures = append(failures, directoryOutageProof{PoweredOff: host, DegradedAfterMS: degraded, Client: proof})
		t.Logf("With %s off, %s still served DNS, fresh Kerberos and the original SYSVOL file.", host, survivor.DNSName)

		cmd := exec.CommandContext(ctx, filepath.Join(hosts.root, "bin/ocean-lab"), "up", "-state", hosts.state,
			"-profile", filepath.Join(hosts.root, "lab/profiles/domain-join.yaml"), "-only", host)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("resume packaged controller %s: %v: %s", host, err, out)
		}
		online[host] = true
		pollDirectoryLab(t, ctx, "both packaged controllers to resume with the original placement", func() bool {
			view := read()
			return view.Availability == "Available" && len(view.Controllers) == 2 &&
				view.Controllers[0] == controllers[0] && view.Controllers[1] == controllers[1]
		})
	}
	return failures
}
