//go:build e2e

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/rack"
)

const rackLabZone = "rack-a.ocean.test"

func TestRackInventoryAndDNS(t *testing.T) {
	if os.Getenv("OCEAN_E2E_RACK_BIND_BINARY") == "" {
		t.Skip("requires a local BIND 9 server binary")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
	defer cancel()
	regionName := "rack-" + strings.ToLower(rand.Text())
	primary, peer := openNamedLabRegion(t, regionName), openNamedLabRegion(t, regionName)
	if err := primary.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	dnsServer, tsigKey := startRackLabDNS(t, ctx, directory)
	assets, bmc, ironic := rackLabHardware(t)
	cfg := rackProvisioningConfig{
		InventoryFile: filepath.Join(directory, "inventory.json"), SignatureFile: filepath.Join(directory, "inventory.sig"),
		PublicKeyFile: filepath.Join(directory, "inventory-public.pem"),
		BMCCAFile:     rackLabCA(t, directory, "bmc-ca.pem", bmc), IronicOrigin: ironic.URL,
		IronicCAFile: rackLabCA(t, directory, "ironic-ca.pem", ironic),
		IronicToken:  writeRackLabFile(t, directory, "ironic-token", []byte("lab-site-service")),
		DNS:          rack.DNSConfig{Server: dnsServer, KeyFile: tsigKey},
		Racks: map[string]rackPolicy{"rack-a": {
			Network: netip.MustParsePrefix("10.74.16.0/24"), First: netip.MustParseAddr("10.74.16.10"), Last: netip.MustParseAddr("10.74.16.13"),
			Gateway: netip.MustParseAddr("10.74.16.1"), DNSZone: rackLabZone,
			BMCCredential: writeRackLabFile(t, directory, "bmc-credential.json", []byte(`{"username":"site-reader","password":"lab-password"}`)),
			Profile:       "debian-rack", Cell: "cell-1", Pool: "owned", Roles: []string{"compute"}, MinimumCPU: 2, MinimumMemoryMiB: 1024, RequireKVM: true,
		}},
	}
	for _, region := range []*Region{primary, peer} {
		provisioning, err := openRackProvisioning(&cfg)
		if err != nil {
			t.Fatal(err)
		}
		region.rack = provisioning
	}
	now := time.Now().UTC()
	signed := rack.Inventory{Revision: 1, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Assets: assets[:4]}
	sign := rackLabSigner(t, cfg)
	sign(signed)
	static := enrollment.Approval{HostID: "static-host", MAC: "02:00:00:ef:00:01", Address: "10.74.16.10", Profile: "debian-rack", Cell: "cell-1",
		Pool: "owned", Roles: []string{"compute"}, MinimumCPU: 1, MinimumMemoryMiB: 512,
		TokenSHA256: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour)}
	if err := peer.seedHostInventory(ctx, []enrollment.Approval{static}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var workers sync.WaitGroup
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	workers.Go(func() { primary.reconcileRackFeed(ctx, logger) })
	workers.Go(func() { peer.reconcileRackFeed(ctx, logger) })
	workers.Wait()
	elapsed := time.Since(start)

	policy := cfg.Racks["rack-a"]
	conflict := assets[3]
	owners := map[string]string{static.Address: static.HostID}
	revisions := map[string]int64{}
	for _, asset := range []rack.Asset{assets[0], assets[1], conflict} {
		job, revision, err := primary.loadRackAssignment(ctx, asset, policy)
		if err != nil || revision == 0 || job.DNSPublished == (asset == conflict) {
			t.Fatalf("host %s has an unexpected reservation or DNS status: %+v, rev %d, err %v", asset.HostID, job, revision, err)
		}
		ip := job.Address.Addr().String()
		if current := owners[ip]; current != "" {
			t.Fatalf("address %s assigned to %s and %s", ip, current, asset.HostID)
		}
		owners[ip] = asset.HostID
		revisions[asset.HostID] = revision
		want := ip
		if asset == conflict {
			want = "192.0.2.90"
		}
		if answer, err := digRackLabDNS(ctx, dnsServer, job.DNSName); err != nil || answer != want {
			t.Fatalf("authoritative DNS for %s is %q, want %s, err %v", job.DNSName, answer, want, err)
		}
		if job.DNSPublished {
			if err := primary.rack.dns.Publish(ctx, policy.DNSZone, asset.HostID, job.Address.Addr()); err != nil {
				t.Fatalf("retry after an existing DNS update: %v", err)
			}
		}
		if allowed, _, _, err := primary.Enrollment(ctx, asset.HostID); err != nil || allowed != nil {
			t.Fatalf("reservation exposed an enrollment credential for %s: %v", asset.HostID, err)
		}
	}
	for _, rejected := range []rack.Asset{assets[2], assets[4]} {
		_, revision, err := peer.loadRackAssignment(ctx, rejected, policy)
		if err != nil || revision != 0 {
			t.Fatalf("unverified host %s has an assignment: %d, %v", rejected.HostID, revision, err)
		}
		answer, err := digRackLabDNS(ctx, dnsServer, rejected.HostID+"."+policy.DNSZone)
		if err != nil || answer != "" {
			t.Fatalf("unverified host %s is in DNS: %q, %v", rejected.HostID, answer, err)
		}
	}
	static.HostID, static.Address, static.MAC = assets[0].HostID, "10.74.16.40", "02:00:00:ef:00:02"
	if err := peer.seedHostInventory(ctx, []enrollment.Approval{static}); err == nil {
		t.Fatal("static enrollment bypassed an existing rack reservation")
	}
	promoted := signed
	promoted.Revision, promoted.Assets = 2, assets[:2]
	sign(promoted)
	restarted := openNamedLabRegion(t, regionName)
	var err error
	restarted.rack, err = openRackProvisioning(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.reconcileRackFeed(ctx, logger)
	for _, asset := range promoted.Assets {
		after, rev, err := restarted.loadRackAssignment(ctx, asset, policy)
		if err != nil || !after.DNSPublished || rev != revisions[asset.HostID] || owners[after.Address.Addr().String()] != asset.HostID {
			t.Fatalf("restart changed the address or DNS confirmation for %s: %+v, %d, %v", asset.HostID, after, rev, err)
		}
	}
	sign(signed)
	stale, err := rack.LoadInventory(cfg.InventoryFile, cfg.SignatureFile, cfg.PublicKeyFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.acceptRackFeed(ctx, stale); err == nil {
		t.Fatal("region accepted a valid signature for an older inventory revision")
	}
	if path := os.Getenv("OCEAN_E2E_RACK_EVIDENCE"); path != "" {
		writeRackLabEvidence(t, path, elapsed, owners, revisions)
	}
}

func startRackLabDNS(t *testing.T, ctx context.Context, directory string) (netip.AddrPort, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	tsig := writeRackLabFile(t, directory, "rack.key", fmt.Appendf(nil, "key ocean-rack { algorithm hmac-sha256; secret %q; };\n", base64.StdEncoding.EncodeToString(key)))
	writeRackLabFile(t, directory, "rack.zone", []byte(`$TTL 60
@ IN SOA ns hostmaster 1 60 60 60 60
@ IN NS ns
ns IN A 127.0.0.1
occupied IN A 192.0.2.90
`))
	config := fmt.Appendf(nil, `options {
    directory %q;
    listen-on port %d { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    pid-file "named.pid";
};
controls {};
include %q;
zone %q { type primary; file "rack.zone"; update-policy { grant ocean-rack zonesub A; }; };
`, directory, address.Port(), tsig, rackLabZone)
	conf := writeRackLabFile(t, directory, "named.conf", config)
	named := exec.CommandContext(ctx, os.Getenv("OCEAN_E2E_RACK_BIND_BINARY"), "-f", "-c", conf, "-n", "1")
	dnsLog := filepath.Join(directory, "named.log")
	log, err := os.OpenFile(dnsLog, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	named.Stdout, named.Stderr = log, log
	err = named.Start()
	_ = log.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = named.Process.Kill()
		_ = named.Wait()
		if t.Failed() {
			content, err := os.ReadFile(dnsLog)
			if err == nil {
				t.Logf("local BIND log:\n%s", content)
			}
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if answer, err := digRackLabDNS(ctx, address, "occupied."+rackLabZone); err == nil && answer == "192.0.2.90" {
			return address, tsig
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("local BIND did not load the authoritative zone")
	return netip.AddrPort{}, ""
}

func digRackLabDNS(ctx context.Context, address netip.AddrPort, name string) (string, error) {
	output, err := exec.CommandContext(ctx, "dig", "@"+address.Addr().String(), "-p", fmt.Sprint(address.Port()),
		"+time=1", "+tries=1", "+short", "+norecurse", name+".", "A").Output()
	return strings.TrimSpace(string(output)), err
}

func rackLabBMC(t *testing.T) ([]rack.Asset, *httptest.Server) {
	t.Helper()
	var assets []rack.Asset
	for index, id := range []string{"host-blue", "host-green", "mismatched", "occupied", "not-in-feed"} {
		assets = append(assets, rack.Asset{HostID: id, Rack: "rack-a",
			NodeID: fmt.Sprintf("00000000-0000-4000-8000-%012x", index+1), UUID: fmt.Sprintf("00000000-0000-4000-8001-%012x", index+1),
			System: "/redfish/v1/Systems/" + id, Serial: "LAB-" + id, BootMAC: fmt.Sprintf("02:00:00:de:00:%02x", index+1)})
	}
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "site-reader" || password != "lab-password" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		for _, asset := range assets {
			collection := asset.System + "/EthernetInterfaces"
			link := func(path string) map[string]string { return map[string]string{"@odata.id": path} }
			switch r.URL.Path {
			case asset.System:
				serial := asset.Serial
				if asset.HostID == "mismatched" {
					serial += "-different"
				}
				rackLabJSON(t, w, map[string]any{"SerialNumber": serial, "UUID": asset.UUID, "EthernetInterfaces": link(collection)})
				return
			case collection:
				rackLabJSON(t, w, map[string]any{"Members": []any{link(collection + "/1")}})
				return
			case collection + "/1":
				rackLabJSON(t, w, map[string]string{"MACAddress": asset.BootMAC})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(bmc.Close)
	for index := range assets {
		assets[index].BMC = bmc.URL
	}
	return assets, bmc
}

func rackLabJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("write site fixture response: %v", err)
	}
}

func rackLabHardware(t *testing.T) ([]rack.Asset, *httptest.Server, *httptest.Server) {
	t.Helper()
	assets, bmc := rackLabBMC(t)
	ironic := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "lab-site-service" || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		for _, asset := range assets {
			node := "/v1/nodes/" + asset.NodeID
			switch r.URL.Path {
			case node:
				rackLabJSON(t, w, map[string]any{"uuid": asset.NodeID, "driver": "redfish", "boot_interface": "ipxe", "deploy_interface": "direct",
					"driver_info": map[string]any{"redfish_address": asset.BMC, "redfish_system_id": asset.System, "redfish_verify_ca": true}})
				return
			case node + "/ports/detail":
				rackLabJSON(t, w, map[string]any{"ports": []any{map[string]any{"node_uuid": asset.NodeID, "address": asset.BootMAC, "pxe_enabled": true}}})
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(ironic.Close)
	return assets, bmc, ironic
}

func rackLabSigner(t *testing.T, cfg rackProvisioningConfig) func(rack.Inventory) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeRackLabFile(t, filepath.Dir(cfg.PublicKeyFile), filepath.Base(cfg.PublicKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key}))
	return func(inventory rack.Inventory) {
		t.Helper()
		raw, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		for path, content := range map[string][]byte{cfg.InventoryFile: raw,
			cfg.SignatureFile: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)))} {
			writeRackLabFile(t, filepath.Dir(path), filepath.Base(path), content)
		}
	}
}

func rackLabCA(t *testing.T, directory, filename string, server *httptest.Server) string {
	t.Helper()
	return writeRackLabFile(t, directory, filename, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
}

func writeRackLabFile(t *testing.T, directory, filename string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, filename)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRackLabEvidence(t *testing.T, path string, elapsed time.Duration, addresses map[string]string, revisions map[string]int64) {
	t.Helper()
	data, err := json.MarshalIndent(map[string]any{
		"reconcileMilliseconds": elapsed.Milliseconds(), "contendingControllers": 2,
		"addressOwners": addresses, "etcdAssignmentRevisions": revisions,
		"authoritativeARecordsChecked": 3, "mismatchedAndUnsignedAbsent": true,
		"existingDNSRecordPreserved": true, "signedRollbackRejected": true,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeRackLabFile(t, filepath.Dir(path), filepath.Base(path), append(data, '\n'))
}
