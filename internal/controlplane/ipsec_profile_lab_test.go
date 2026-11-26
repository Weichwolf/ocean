//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	ipsecProfileHost = "farm-1-node-01"
	ipsecProfileBase = "/var/tmp/ocean-ipsec-profile"
	ipsecProfileExec = "sudo /bin/sh " + ipsecProfileBase + "/fixture.sh "
	ipsecProfileSlot = "ipsec-profile"
)

func TestPackagedIPsecProfile(t *testing.T) {
	state := os.Getenv("OCEAN_E2E_IPSEC_LAB_STATE")
	if state == "" || os.Getenv("OCEAN_E2E_IPSEC_PROFILE") != "1" {
		t.Skip("requires a prepared IPsec KVM guest, mTLS etcd and pinned Azure CLI")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	machines, err := lab.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	guests, err := machines.Status()
	if err != nil || len(guests) != 1 || !guests[0].Running || guests[0].Guest.Name != ipsecProfileHost {
		t.Fatalf("start only the dedicated IPsec KVM guest %s: %v", ipsecProfileHost, err)
	}
	ctx, stop := context.WithTimeout(t.Context(), 7*time.Minute)
	defer stop()
	private := t.TempDir()
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(),
		Administrator: operationID(), Fingerprint: operationID()}
	r := packagedIPsecRegion(t, ctx, private, tenant)
	installation := directoryKVMHosts{root: root, state: state, directory: "ipsec-profile-" + tenant.TenantID, t: t}
	nonce := rand.Text()
	ipsecProfilePrepareGuest(t, ctx, r, installation, guests[0].Guest, nonce)
	secret := rand.Text()
	az := ipsecProfileAPI(t, ctx, private, r, tenant, installation, secret)
	vpn := ipsecProfileCommands(t, root, az, r.name, secret)
	if got, err := installation.ssh(ctx, ipsecProfileHost, "dpkg-query -W ocean-agent strongswan-charon strongswan-swanctl", nil); err != nil {
		t.Fatalf("could not inspect installed gateway packages: %v: %s", err, got)
	} else {
		t.Logf("Gateway and customer peer packages:\n%s", strings.TrimSpace(string(got)))
	}

	runCLI := func(fail bool, networkCommand, verb string, args ...string) []byte {
		t.Helper()
		return az(fail, append([]string{"network", networkCommand, verb, "-g", "ipsec-profile", "--only-show-errors"}, args...)...)
	}
	_ = az(false, "group", "create", "--name", "ipsec-profile", "--location", r.name, "--only-show-errors")
	runCLI(false, "vnet", "create", "-n", "tenant", "-l", r.name, "--address-prefixes", "10.91.0.0/16",
		"--subnet-name", "apps", "--subnet-prefixes", "10.91.1.0/24")
	az(false, "network", "vnet", "subnet", "create", "-g", "ipsec-profile", "--vnet-name", "tenant", "-n", "GatewaySubnet",
		"--address-prefixes", "10.91.0.0/24", "--only-show-errors")
	runCLI(false, "public-ip", "create", "-n", "external", "-l", r.name, "--sku", "Standard", "--tier", "Regional",
		"--version", "IPv4", "--allocation-method", "Static")
	vpn(false, "virtual-gateway-create")
	vpn(false, "local-gateway-create")
	pollIPsecProfile(t, ctx, 15*time.Second, "the assigned public address on the gateway namespace", func() bool {
		out, err := installation.ssh(ctx, ipsecProfileHost, ipsecProfileExec+"address", nil)
		return err == nil && bytes.Contains(out, []byte("198.18.24.1/32"))
	})
	loadPeer := func(key string) {
		t.Helper()
		installation.run(ctx, ipsecProfileHost, ipsecProfileExec+"peer-key", strings.NewReader(key))
	}
	peerCommand := func(probe string) ([]byte, error) {
		t.Helper()
		return installation.ssh(ctx, ipsecProfileHost, ipsecProfileExec+probe, nil)
	}
	assertBlocked := func(probe string, allowedDiagnostics ...string) {
		t.Helper()
		result, err := peerCommand(probe)
		for _, diagnostic := range allowedDiagnostics {
			if err != nil && bytes.Contains(result, []byte(diagnostic)) {
				return
			}
		}
		t.Fatalf("fixture probe %s was not blocked as expected: %v: %s", probe, err, result)
	}
	show := func() string {
		t.Helper()
		data := vpn(false, "connection-show")
		var view struct {
			Status     string `json:"connectionStatus"`
			Properties struct {
				Status string `json:"connectionStatus"`
			}
		}
		if err := json.Unmarshal(data, &view); err != nil || bytes.Contains(data, []byte(secret)) {
			t.Fatal("the VPN connection response was invalid or exposed its shared key")
		}
		if view.Status != "" {
			return view.Status
		}
		return view.Properties.Status
	}

	loadPeer(rand.Text())
	deployed := vpn(false, "connection-create")
	if !json.Valid(deployed) || bytes.Contains(deployed, []byte(secret)) || show() != "NotConnected" {
		t.Fatal("a peer with the wrong key appeared connected or the deployment leaked a credential")
	}
	assertBlocked("workload", "curl: (7)", "curl: (28)")
	loadPeer(secret)
	started := time.Now()
	if output, err := peerCommand("peer-initiate"); err != nil {
		t.Fatalf("the native strongSwan peer could not initiate IKEv2: %v: %s", err, output)
	}
	pollIPsecProfile(t, ctx, 20*time.Second, "the native IKEv2 SA in Azure CLI and the private HTTP workload", func() bool {
		body, err := peerCommand("workload")
		return err == nil && strings.TrimSpace(string(body)) == nonce && show() == "Connected"
	})
	connectMS := time.Since(started).Milliseconds()
	if out, err := peerCommand("reverse"); err != nil {
		t.Fatalf("authorized forwarding from the workload to the customer failed: %v: %s", err, out)
	}
	assertBlocked("outside", "100% packet loss", "Destination Host Unreachable")
	assertBlocked("protected", "100% packet loss", "Destination Host Unreachable")
	_ = vpn(false, "connection-create")

	installation.run(ctx, ipsecProfileHost, "sudo systemctl kill --signal=STOP --kill-whom=main ocean-ipsec-agent.service", nil)
	stopped := time.Now()
	pollIPsecProfile(t, ctx, 9*time.Second, "fresh Azure CLI status to expire during a gateway stall", func() bool {
		return show() == "NotConnected"
	})
	statusMS := time.Since(stopped).Milliseconds()
	pollIPsecProfile(t, ctx, 13*time.Second, "kernel forwarding lease to expire during a gateway stall", func() bool {
		output, err := peerCommand("workload")
		return err != nil && (bytes.Contains(output, []byte("curl: (7)")) || bytes.Contains(output, []byte("curl: (28)")))
	})
	leaseMS := time.Since(stopped).Milliseconds()
	if statusMS > 9000 || leaseMS > 13000 {
		t.Fatalf("status or packet expiry exceeded its lab budget: status %d ms, packets %d ms", statusMS, leaseMS)
	}
	installation.run(ctx, ipsecProfileHost, "sudo systemctl kill --signal=CONT --kill-whom=main ocean-ipsec-agent.service", nil)
	pollIPsecProfile(t, ctx, 20*time.Second, "Azure CLI status and private HTTP after resuming the gateway", func() bool {
		body, err := peerCommand("workload")
		return err == nil && strings.TrimSpace(string(body)) == nonce && show() == "Connected"
	})
	if used := vpn(true, "local-gateway-delete"); !bytes.Contains(used, []byte("ResourceInUse")) {
		t.Fatal("the local gateway could be withdrawn while still bound")
	}
	vpn(false, "connection-delete")
	vpn(false, "connection-delete")
	if missing := vpn(true, "connection-show"); !bytes.Contains(missing, []byte("ResourceNotFound")) {
		t.Fatal("a withdrawn VPN connection remained discoverable")
	}
	assertBlocked("workload", "curl: (7)", "curl: (28)")
	if routes, err := peerCommand("routes"); err != nil || len(bytes.TrimSpace(routes)) != 0 {
		t.Fatalf("the connection left a managed route: %v: %s", err, routes)
	}
	assertBlocked("tunnel", "does not exist", "Cannot find device")
	vpn(false, "local-gateway-delete")
	vpn(false, "virtual-gateway-delete")
	if address, err := peerCommand("address"); err != nil || len(bytes.TrimSpace(address)) != 0 {
		t.Fatalf("the gateway left its public endpoint installed: %v: %s", err, address)
	}
	runCLI(false, "public-ip", "delete", "-n", "external")
	writeIPsecMeasurements(t, connectMS, statusMS, leaseMS)
	t.Logf("Azure CLI 2.93.0 reached Connected with native strongSwan and a private HTTP response in %d ms. During a stopped worker, Azure CLI showed NotConnected in %d ms and packet forwarding closed in %d ms.", connectMS, statusMS, leaseMS)
	t.Log("Both traffic directions, wrong-key rejection, blocked networks, same-key deployment replay, lease recovery, and repeated CLI teardown passed.")
}

func writeIPsecMeasurements(t *testing.T, connect, status, lease int64) {
	t.Helper()
	base := os.Getenv("OCEAN_E2E_IPSEC_MEASUREMENTS")
	if base == "" {
		return
	}
	tsv := fmt.Sprintf("measurement\tvalue_ms\nikev2_and_http_ready\t%d\narm_status_after_worker_stall\t%d\nforwarding_closed_after_worker_stall\t%d\n",
		connect, status, lease)
	markdown := fmt.Sprintf(`# IPsec profile measurements

| Measurement | Milliseconds |
| --- | ---: |
| Native IKEv2, ARM Connected and reachable workload | %d |
| ARM NotConnected after worker pause | %d |
| Forwarding blocked after worker pause | %d |

The test used Azure CLI 2.93.0 and two independently configured strongSwan
processes in a disposable Debian KVM guest.
`, connect, status, lease)
	for name, body := range map[string]string{base + ".tsv": tsv, base + ".md": markdown} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func ipsecProfileCommands(t *testing.T, root string, az func(bool, ...string) []byte, location, key string) func(bool, string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "tests/e2e/testdata/arm-contract.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.Comma = '\t'
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	commands := make(map[string]string)
	for _, row := range rows {
		if row[0] == "PROFILE-01" {
			if row[2] != "2.93.0" || row[3] != "none" || commands[row[1]] != "" {
				t.Fatal("invalid or duplicate Azure CLI IPsec contract row")
			}
			commands[row[1]] = row[5]
		}
	}
	bindings := strings.NewReplacer("{group}", "ipsec-profile", "{virtual_gateway}", "cloud", "{local_gateway}", "branch",
		"{vnet}", "tenant", "{public_ip}", "external", "{location}", location, "{peer_ip}", "198.18.24.2",
		"{peer_prefix}", "10.92.1.0/24", "{connection}", "tunnel", "{shared_key}", key)
	return func(reject bool, name string) []byte {
		t.Helper()
		command, present := commands[name]
		if !present {
			t.Fatalf("the IPsec command %s is missing from the CLI contract", name)
		}
		args := strings.Fields(command)
		for index, arg := range args {
			args[index] = bindings.Replace(arg)
		}
		return az(reject, append(args, "--only-show-errors")...)
	}
}

func packagedIPsecRegion(t *testing.T, ctx context.Context, private string, tenant identity.TenantReservation) *Region {
	t.Helper()
	r := openLabRegion(t)
	r.root = "/ocean/v1/regions/ipsec-profile-" + operationID()
	r.keys, r.values = initialRecords(r.root, r.name, r.cell)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if _, err := r.client.Delete(ctx, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	})
	seal := make([]byte, 32)
	rand.Read(seal)
	defer clear(seal)
	sealPath := ipsecPrivateFile(t, private, "vpn-sealing.key", seal)
	r.publicIPv4 = []netip.Addr{netip.MustParseAddr("198.18.24.1")}
	control, err := openIPsec(&ipsecConfig{SharedKeyEnvelopeFile: sealPath,
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.231.1.0/24")},
		Slots: []ipsecSlot{{Name: ipsecProfileSlot, Host: ipsecProfileHost, TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
			PublicIPv4: r.publicIPv4[0], InsideIPv4: netip.MustParsePrefix("10.91.1.1/24")}},
	}, r.publicIPv4)
	if err != nil {
		t.Fatal(err)
	}
	r.ipsec = control
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, identity.Subscription{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID,
		DisplayName: "IPsec profile fixture", Members: []string{tenant.Administrator}}); err != nil {
		t.Fatal(err)
	}
	return r
}

func ipsecProfilePrepareGuest(t *testing.T, ctx context.Context, r *Region, guest directoryKVMHosts, status lab.Guest, nonce string) {
	t.Helper()
	const config = "/etc/ocean-agent"
	guest.run(ctx, status.Name, "sudo test -x /usr/bin/ocean-network-agent && sudo test ! -e "+config+"/ipsec.json && sudo mkdir -m 0700 "+ipsecProfileBase, nil)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 35*time.Second)
		defer stop()
		if t.Failed() {
			data, _ := guest.ssh(cleanup, status.Name, "sudo journalctl -u ocean-ipsec-agent.service -n 18 --no-pager", nil)
			t.Logf("Gateway worker journal:\n%s", data)
		}
		command := "sudo systemctl kill --signal=CONT --kill-whom=main ocean-ipsec-agent.service 2>/dev/null || true; " +
			"sudo systemctl stop ocean-ipsec-agent.service; " + packagedDirectoryWorker +
			"worker systemctl --user stop ocean-agent.service 2>/dev/null || true\n" +
			"sudo /bin/sh -eu -c 'if test -f " + ipsecProfileBase + "/fixture.sh; then /bin/sh " + ipsecProfileBase + "/fixture.sh cleanup; fi; " +
			"if test -f " + ipsecProfileBase + "/agent-config.original; then cp -p " + ipsecProfileBase + "/agent-config.original " + config + "/config.json; fi; " +
			"rm -f " + config + "/ipsec.json " + config + "/ipsec-profile-ca.pem; rm -rf " + ipsecProfileBase + " /var/lib/ocean-agent/" + guest.directory + "'"
		if data, err := guest.ssh(cleanup, status.Name, command, nil); err != nil {
			t.Errorf("clean up the dedicated IPsec guest: %v: %s", err, data)
		}
	})
	fixture, err := os.ReadFile(filepath.Join(guest.root, "lab/ipsec_profile_fixture.sh"))
	if err != nil {
		t.Fatal(err)
	}
	guest.run(ctx, status.Name, "sudo cp -p "+config+"/config.json "+ipsecProfileBase+"/agent-config.original && "+
		"sudo install -m 0700 /dev/stdin "+ipsecProfileBase+"/fixture.sh", bytes.NewReader(fixture))
	guest.run(ctx, status.Name, ipsecProfileExec+"setup "+nonce, nil)
}

func ipsecProfileAPI(t *testing.T, ctx context.Context, private string, r *Region, tenant identity.TenantReservation,
	guest directoryKVMHosts, sensitive ...string) func(bool, ...string) []byte {
	t.Helper()
	ca, signer, _, _ := directoryJoinClientCertificates(t)
	if ca == nil {
		t.Fatal("missing the disposable gateway CA")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	key, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := enrollment.Open(enrollment.Config{
		CertificateFile: ipsecPrivateFile(t, private, "gateway-ca.pem", caPEM),
		KeyFile:         ipsecPrivateFile(t, private, "gateway-ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		InventoryFile:   ipsecPrivateFile(t, private, "hosts.json", []byte(`{"hosts":[]}`)),
	}, r)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _, enableLogin := directoryJoinIssuer(t, tenant.TenantID)
	api, graph := httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	t.Cleanup(graph.Close)
	apiOrigin, graphOrigin := "https://"+api.Listener.Addr().String(), "https://"+graph.Listener.Addr().String()
	api.TLS = directoryLabServerTLS(t, ca, signer)
	compat, err := (identity.Config{Authority: issuer.URL, Provider: issuer.URL,
		ProviderCAFile: ipsecPrivateFile(t, private, "issuer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})),
		Cloud:          &identity.CloudEndpoints{ResourceManager: apiOrigin, MicrosoftGraph: graphOrigin}}).OpenCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	compat.EnableSubscriptions(r.name, r.lookupSubscription)
	management := arm.Server{Origin: apiOrigin, Location: r.name, Authenticate: compat.AuthenticateARM, Inventory: r,
		Groups: r, Roles: r, Operations: r, Networks: r, Deployments: r, VPN: r}
	graph.Config.Handler = compat.Handler()
	api.Config.Handler = authority.Handler(management.Handler(graph.Config.Handler))
	graph.StartTLS()
	api.StartTLS()
	app, secret := operationID(), rand.Text()
	enableLogin(api.URL, graph.URL, app, secret, tenant.Administrator)
	ipsecProfileEnroll(t, ctx, r, guest, directoryGuestOrigin(t, api), caPEM)
	return (regionalGraphFixture{ctx: ctx, private: private, api: api, graph: graph, issuer: issuer,
		tenant: tenant, app: app, secret: secret, apiCA: caPEM}).loginCLI(t, sensitive...)
}

func ipsecProfileEnroll(t *testing.T, ctx context.Context, r *Region, guest directoryKVMHosts, origin string, ca []byte) {
	t.Helper()
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	clear(entropy[:])
	port, err := guest.ssh(ctx, ipsecProfileHost, "cat /sys/class/net/mgmt0/address", nil)
	if err != nil {
		t.Fatal(err)
	}
	approval := enrollment.Approval{HostID: ipsecProfileHost, MAC: strings.TrimSpace(string(port)),
		Address: "10.231.1.11", Profile: "debian-13", Cell: r.cell, Pool: "lab", Roles: []string{"gateway"}, MinimumCPU: 1,
		MinimumMemoryMiB: 832, TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), ExpiresAt: time.Now().Add(time.Hour).UTC()}
	if err := r.seedHostInventory(ctx, []enrollment.Approval{approval}); err != nil {
		t.Fatal(err)
	}
	const config = "/etc/ocean-agent/"
	directory := "/var/lib/ocean-agent/" + guest.directory
	settings := ipsecFixtureJSON(t, map[string]any{"listenAddress": "127.0.0.1:8081", "enrollment": map[string]string{
		"origin": origin, "hostId": ipsecProfileHost, "managementInterface": "mgmt0", "caFile": config + "ipsec-profile-ca.pem",
		"tokenFile": directory + "/join-token", "stateDirectory": directory,
	}})
	registry := ipsecFixtureJSON(t, map[string]any{"slots": map[string]any{ipsecProfileSlot: map[string]string{
		"namespace": "ovpn-cloud", "tunnel": "xfrm42", "underlay": "wan0", "inside": "lan0",
		"publicIPv4": r.publicIPv4[0].String(), "socket": "/dev/shm/ocean-ipsec-lab-profile-cloud/vici.sock",
	}}})
	guest.run(ctx, ipsecProfileHost, "sudo install -d -o ocean-agent -g ocean-agent -m 0700 "+directory, nil)
	for name, content := range map[string][]byte{"config.json": settings, "ipsec-profile-ca.pem": ca, "ipsec.json": registry} {
		guest.run(ctx, ipsecProfileHost, "sudo install -m 0644 /dev/stdin "+config+name, bytes.NewReader(content))
	}
	guest.run(ctx, ipsecProfileHost, "sudo -u ocean-agent sh -c 'umask 077; cat > "+directory+"/join-token'", strings.NewReader(token))
	guest.run(ctx, ipsecProfileHost, "set -eu\n"+packagedDirectoryWorker+`
sudo loginctl enable-linger ocean-agent
sudo systemctl start "user@$uid.service"
worker systemctl --user daemon-reload
worker systemctl --user restart ocean-agent.service
sudo systemctl daemon-reload
`, nil)
	pollIPsecProfile(t, ctx, 40*time.Second, "the installed gateway agent to enroll and advertise availability", func() bool {
		entry, err := r.client.Get(ctx, r.hostKey("live", ipsecProfileHost))
		var live enrollment.Availability
		return err == nil && len(entry.Kvs) == 1 && entry.Kvs[0].Lease != 0 && json.Unmarshal(entry.Kvs[0].Value, &live) == nil &&
			live.HostID == ipsecProfileHost
	})
	guest.run(ctx, ipsecProfileHost, "sudo systemctl start ocean-ipsec-agent.service", nil)
}

func ipsecPrivateFile(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func pollIPsecProfile(t *testing.T, ctx context.Context, timeout time.Duration, action string, done func() bool) {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pollDirectoryLab(t, wait, action, done)
}
