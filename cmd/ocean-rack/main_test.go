package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/rack"
)

func TestVerifyRackAsset(t *testing.T) {
	const system = "/redfish/v1/Systems/1"
	const collection = system + "/EthernetInterfaces"
	const nic = collection + "/NIC1"
	const approvedSerial = "OCEAN-ASSET-0001"
	const approvedUUID = "0a9b8c7d-6e5f-4a3b-9210-123456789abc"
	const approvedMAC = "02:00:00:10:00:01"
	const approvedNode = "5d5814ba-a5b7-4e19-82b0-947312ae49f7"
	testCases := []struct {
		name   string
		change string
		err    string
	}{
		{name: "approved hardware"},
		{name: "expired inventory", change: "expiry", err: "validity interval"},
		{name: "edited inventory", change: "tamper", err: "signature verification failed"},
		{name: "unknown host", change: "missing", err: "absent from the approved"},
		{name: "duplicate MAC", change: "duplicate", err: "duplicate hardware or host identity"},
		{name: "different hardware with matching MAC", change: "serial", err: "serial or UUID"},
		{name: "different UUID with matching MAC", change: "uuid", err: "serial or UUID"},
		{name: "different boot interface", change: "mac", err: "do not include the approved boot MAC"},
		{name: "spoofed MAC", change: "permanent", err: "permanent MAC differs"},
		{name: "credentials readable by others", change: "permissions", err: "owner-only"},
		{name: "redirect", change: "redirect", err: "HTTP 307"},
		{name: "foreign pagination", change: "pagination", err: "invalid Ethernet interface page link"},
		{name: "untrusted TLS", change: "tls", err: "BMC request failed"},
		{name: "different Ironic node binding", change: "ironic-system", err: "does not bind the approved Redfish system"},
		{name: "Ironic BMC TLS disabled", change: "ironic-insecure", err: "outside the verified Redfish"},
		{name: "different Ironic boot port", change: "ironic-port", err: "outside the approved boot identity"},
		{name: "Ironic boot disabled", change: "ironic-disabled", err: "exactly one approved PXE-enabled port"},
		{name: "Ironic redirect", change: "ironic-redirect", err: "Ironic returned HTTP 307"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var contacted, commissioning, redirected atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(target.Close)
			bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contacted.Add(1)
				user, password, ok := r.BasicAuth()
				if !ok || user != "inventory-reader" || password != "test-only" || r.Method != http.MethodGet {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				var data any
				switch r.URL.Path {
				case system:
					if tc.change == "redirect" {
						http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
						return
					}
					serial, uuid := approvedSerial, strings.ToUpper(approvedUUID)
					switch tc.change {
					case "serial":
						serial += "-other"
					case "uuid":
						uuid = approvedNode
					}
					data = map[string]any{"SerialNumber": serial, "UUID": uuid, "EthernetInterfaces": link(collection)}
				case collection:
					switch {
					case tc.change == "pagination":
						data = map[string]any{"Members": []any{}, "Members@odata.nextLink": target.URL + collection + "?page=2"}
					case r.URL.RawQuery == "":
						data = map[string]any{"Members": []any{}, "Members@odata.nextLink": collection + "?page=2"}
					default:
						data = map[string]any{"Members": []any{link(nic)}}
					}
				case nic:
					mac, permanent := strings.ToUpper(approvedMAC), approvedMAC
					switch tc.change {
					case "mac":
						mac = "02:00:00:10:00:02"
					case "permanent":
						permanent = "02:00:00:10:00:02"
					}
					data = map[string]string{"MACAddress": mac, "PermanentMACAddress": permanent}
				default:
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(data); err != nil {
					t.Errorf("write Redfish response: %v", err)
				}
			}))
			t.Cleanup(bmc.Close)
			ironic := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				commissioning.Add(1)
				if r.Header.Get("X-Auth-Token") != "test-keystone-token" || r.Header.Get("X-OpenStack-Ironic-API-Version") != "1.56" ||
					r.Header.Get("Authorization") != "" || r.Method != http.MethodGet {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				var data any
				switch r.URL.Path {
				case "/v1/nodes/" + approvedNode:
					if tc.change == "ironic-redirect" {
						http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
						return
					}
					driverInfo := map[string]any{"redfish_address": bmc.URL, "redfish_system_id": system, "redfish_verify_ca": true}
					switch tc.change {
					case "ironic-system":
						driverInfo["redfish_system_id"] = system + "-other"
					case "ironic-insecure":
						driverInfo["redfish_verify_ca"] = false
					}
					data = map[string]any{"uuid": approvedNode, "driver": "redfish", "driver_info": driverInfo,
						"boot_interface": "ipxe", "deploy_interface": "direct"}
				case "/v1/nodes/" + approvedNode + "/ports/detail":
					mac := approvedMAC
					if tc.change == "ironic-port" {
						mac = "02:00:00:10:00:03"
					}
					data = map[string]any{"ports": []map[string]any{{"address": mac, "node_uuid": approvedNode,
						"pxe_enabled": tc.change != "ironic-disabled"}}}
				default:
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(data); err != nil {
					t.Errorf("write Ironic response: %v", err)
				}
			}))
			t.Cleanup(ironic.Close)
			dir := t.TempDir()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publicDER, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			asset := rack.Asset{HostID: "host-01", Rack: "rack-02", NodeID: approvedNode, BMC: bmc.URL,
				System: system, Serial: approvedSerial, UUID: approvedUUID, BootMAC: approvedMAC}
			inventory := rack.Inventory{Revision: 7, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Assets: []rack.Asset{asset}}
			switch tc.change {
			case "expiry":
				inventory.ExpiresAt = now.Add(-time.Minute)
			case "missing":
				inventory.Assets = nil
			case "duplicate":
				asset.HostID, asset.NodeID, asset.UUID, asset.System = "host-02", approvedUUID, approvedNode, system+"-other"
				inventory.Assets = append(inventory.Assets, asset)
			}
			inventoryBytes, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, inventoryBytes))
			if tc.change == "tamper" {
				inventoryBytes = bytes.Replace(inventoryBytes, []byte(approvedSerial), []byte("other"), 1)
			}
			ca := bmc.Certificate().Raw
			if tc.change == "tls" {
				// httptest's default certificate is shared by all its TLS servers.
				ca = makeUntrustedCA(t, public, private)
			}
			mode := os.FileMode(0o600)
			if tc.change == "permissions" {
				mode = 0o644
			}
			var output, diagnostics bytes.Buffer
			err = run([]string{
				"-inventory", writeFixture(t, dir, "inventory.json", inventoryBytes, 0o600),
				"-signature", writeFixture(t, dir, "inventory.sig", []byte(signature), 0o600),
				"-public-key", writeFixture(t, dir, "public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600),
				"-bmc-ca", writeFixture(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0o600),
				"-bmc-credential", writeFixture(t, dir, "bmc.json", []byte(`{"username":"inventory-reader","password":"test-only"}`), mode),
				"-ironic-origin", ironic.URL,
				"-ironic-ca", writeFixture(t, dir, "ironic-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ironic.Certificate().Raw}), 0o600),
				"-ironic-token", writeFixture(t, dir, "ironic.token", []byte("test-keystone-token\n"), 0o600),
				"-host", "host-01",
			}, &output, &diagnostics)
			if redirected.Load() != 0 {
				t.Fatal("verification contacted an unapproved endpoint")
			}
			switch tc.change {
			case "expiry", "tamper", "missing", "duplicate", "permissions":
				if contacted.Load() != 0 {
					t.Fatal("verification contacted the BMC before validating its inputs")
				}
			}
			if tc.err != "" {
				if !strings.HasPrefix(tc.change, "ironic-") && commissioning.Load() != 0 {
					t.Fatal("verification contacted Ironic before the approved hardware was confirmed")
				}
				if err == nil || !strings.Contains(err.Error(), tc.err) || output.Len() != 0 {
					t.Fatalf("got output %q and error %v, want only %q", output.String(), err, tc.err)
				}
				return
			}
			want := `{"hostId":"host-01","rack":"rack-02","ironicNodeId":"` + approvedNode + `","inventoryRevision":7}`
			if err != nil || strings.TrimSpace(output.String()) != want || contacted.Load() != 4 || commissioning.Load() != 2 {
				t.Fatalf("got output %q, error %v, %d BMC requests and %d Ironic requests",
					output.String(), err, contacted.Load(), commissioning.Load())
			}
		})
	}
}

func link(path string) map[string]string { return map[string]string{"@odata.id": path} }

func makeUntrustedCA(t *testing.T, public ed25519.PublicKey, private ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writeFixture(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
