//go:build e2e

package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/rack"
)

func TestRackInstallAndJoin(t *testing.T) {
	image, agent := os.Getenv("OCEAN_E2E_RACK_IMAGE"), os.Getenv("OCEAN_E2E_RACK_PACKAGE")
	if image == "" || agent == "" || os.Getenv("OCEAN_E2E_RACK_BIND_BINARY") == "" {
		t.Skip("requires a Debian qcow2 image, ocean-agent package and BIND 9")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	directory := t.TempDir()
	name := "rack-" + strings.ToLower(rand.Text())
	primary, peer := openNamedLabRegion(t, name), openNamedLabRegion(t, name)
	if err := primary.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	server, ca, enrollmentAttempts := rackLabEnrollment(t, primary, directory, agent)
	dnsServer, dnsKey := startRackLabDNS(t, ctx, directory)
	assets, bmc := rackLabBMC(t)
	asset := assets[0]
	site := &rackLabInstaller{t: t, asset: asset, state: "enroll", imageSHA: rackLabFileHash(t, image)}
	ironic := httptest.NewTLSServer(http.HandlerFunc(site.serve))
	t.Cleanup(ironic.Close)
	var rootSecret [32]byte
	rand.Read(rootSecret[:])
	origin := "https://10.0.2.2:" + rackLabListenerPort(t, server.Listener)
	address := netip.MustParseAddr("10.0.2.44")
	cfg := rackProvisioningConfig{
		InventoryFile: filepath.Join(directory, "inventory.json"), SignatureFile: filepath.Join(directory, "inventory.sig"),
		PublicKeyFile: filepath.Join(directory, "inventory.pem"),
		BMCCAFile:     rackLabCA(t, directory, "bmc-ca.pem", bmc), IronicOrigin: ironic.URL, IronicCAFile: rackLabCA(t, directory, "ironic-ca.pem", ironic),
		IronicToken: writeRackLabFile(t, directory, "ironic-token", []byte("lab-site-service")),
		DNS:         rack.DNSConfig{Server: dnsServer, KeyFile: dnsKey},
		Racks: map[string]rackPolicy{asset.Rack: {
			Network: netip.MustParsePrefix("10.0.2.0/24"), First: address, Last: address, Gateway: netip.MustParseAddr("10.0.2.2"),
			Resolvers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}, DNSZone: rackLabZone,
			BMCCredential: writeRackLabFile(t, directory, "bmc.json", []byte(`{"username":"site-reader","password":"lab-password"}`)),
			Profile:       "debian-rack", Cell: "cell-1", Pool: "owned", Roles: []string{"compute"}, MinimumCPU: 2, MinimumMemoryMiB: 768,
		}},
		Installation: &rack.InstallationConfig{EnrollmentOrigin: origin, EnrollmentCAFile: ca, PackageCAFile: ca,
			CredentialKeyFile: writeRackLabFile(t, directory, "join-derivation.key", []byte(base64.RawURLEncoding.EncodeToString(rootSecret[:]))),
			DebianImageURL:    origin + "/debian.qcow2", DebianImageSHA256: site.imageSHA,
			AgentPackageURL: origin + "/agent.deb", AgentSHA256: rackLabFileHash(t, agent),
			ResourceClass: "ocean-debian", MinimumDiskGiB: 8, CPUArchitecture: "x86_64"},
	}
	now := time.Now().UTC()
	rackLabSigner(t, cfg)(rack.Inventory{Revision: 1, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(8 * time.Minute), Assets: []rack.Asset{asset}})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	addressing := cfg
	addressing.Installation = nil
	policy := cfg.Racks[asset.Rack]
	originalPolicy := policy
	originalPolicy.Resolvers = nil
	addressing.Racks = map[string]rackPolicy{asset.Rack: originalPolicy}
	configureRackLabController(t, primary, addressing)
	primary.reconcileRackFeed(ctx, logger)
	reservation, addressRevision, err := primary.loadRackAssignment(ctx, asset, originalPolicy)
	if err != nil || addressRevision == 0 || !reservation.DNSPublished {
		t.Fatalf("could not allocate the host before enabling installation: %v", err)
	}
	for _, controller := range []*Region{primary, peer} {
		configureRackLabController(t, controller, cfg)
	}
	for attempt := 0; attempt < 16 && site.configDrive() == nil; attempt++ {
		var group sync.WaitGroup
		group.Go(func() { primary.reconcileRackFeed(ctx, logger) })
		group.Go(func() { peer.reconcileRackFeed(ctx, logger) })
		group.Wait()
	}
	seed := site.configDrive()
	if seed == nil {
		t.Fatal("Ironic did not accept a config drive")
	}
	deployment, _, err := primary.loadRackDeployment(ctx, primary.rackKey("deployments", asset.HostID))
	if err != nil || deployment.ID == "" || deployment.EnrollmentReleased || deployment.ActivationAccepted {
		t.Fatalf("regional state did not preserve a deployment after a lost Ironic response: %v", err)
	}
	if _, nextRevision, err := primary.loadRackAssignment(ctx, asset, policy); err != nil || nextRevision != addressRevision {
		t.Fatalf("enabling installation changed the management reservation: %v", err)
	}
	assertNoRackJoin(t, ctx, primary, asset.HostID)
	newGuest := time.Now()
	ssh := bootRackLabGuest(t, ctx, directory, image, asset.BootMAC, address, seed)
	select {
	case code := <-enrollmentAttempts:
		if code != http.StatusUnauthorized {
			t.Fatalf("guest enrollment before Ironic activation returned %d", code)
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("Debian guest never attempted enrollment while Ironic was deploying")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	restarted := openNamedLabRegion(t, name)
	configureRackLabController(t, restarted, cfg)
	restarted.reconcileRackFeed(ctx, logger)
	assertNoRackJoin(t, ctx, restarted, asset.HostID)
	site.complete()
	restarted.reconcileRackFeed(ctx, logger)
	ready := func() (string, error) {
		approved, host, _, err := primary.Enrollment(ctx, asset.HostID)
		if err != nil {
			return "", err
		}
		if approved == nil || host == nil {
			return "", fmt.Errorf("enrollment is pending")
		}
		if host.Cell != "cell-1" || host.Pool != "owned" || approved.Address != address.String() || approved.MAC != asset.BootMAC ||
			!host.Report.RootlessPodman || host.Report.OSVersion != "13" || approved.TokenSHA256 != deployment.CredentialDigest {
			t.Fatal("qualified host does not match its rack approval")
		}
		return ssh("cloud-init status --wait >/dev/null && ip -4 -o addr show dev mgmt0 | grep -q '10.0.2.44/24' && " +
			`test "$(curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/readyz)" = 204 && ` +
			"cat /proc/sys/kernel/random/boot_id && sudo sha256sum /var/lib/ocean-agent/host-enrollment/identity.crt && " +
			`dpkg-query -W -f='${Version}\n' ocean-agent`)
	}
	first := awaitRackLabGuest(t, ctx, ready)
	readyElapsed := time.Since(newGuest)
	reboot := time.Now()
	if _, err := ssh("sudo systemctl reboot --no-block"); err != nil {
		t.Fatal(err)
	}
	second := awaitRackLabGuest(t, ctx, func() (string, error) {
		current, err := ready()
		if current == first {
			return "", fmt.Errorf("waiting for Debian to reboot")
		}
		return current, err
	})
	previous, current := strings.Split(first, "\n"), strings.Split(second, "\n")
	if len(previous) != 3 || len(current) != 3 || previous[0] == current[0] || previous[1] != current[1] || previous[2] != current[2] {
		t.Fatal("guest did not preserve its installed agent and certificate across reboot")
	}
	rebootElapsed := time.Since(reboot)
	restarted.reconcileRackFeed(ctx, logger)
	site.mu.Lock()
	events := slices.Clone(site.events)
	site.mu.Unlock()
	if want := []string{"manage", "inspect", "provide", "allocate", "pin-image", "active"}; !slices.Equal(events, want) {
		t.Fatalf("unexpected Ironic transitions: %v", events)
	}
	if path := os.Getenv("OCEAN_E2E_RACK_EVIDENCE"); path != "" {
		data, err := json.MarshalIndent(map[string]any{"commissioningCalls": events, "address": address.String(),
			"allocationId": deployment.ID, "debianImageSHA256": site.imageSHA, "agentPackageSHA256": cfg.Installation.AgentSHA256,
			"enrollmentBeforeActivationHTTP": 401, "readyHTTP": 204, "firstBootToReadyMilliseconds": readyElapsed.Milliseconds(),
			"diskRebootToReadyMilliseconds": rebootElapsed.Milliseconds(), "certificateSHA256": strings.Fields(current[1])[0],
			"agentPackageVersion": current[2]}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeRackLabFile(t, filepath.Dir(path), filepath.Base(path), append(data, '\n'))
	}
}

func configureRackLabController(t *testing.T, controller *Region, cfg rackProvisioningConfig) {
	t.Helper()
	provisioning, err := openRackProvisioning(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	controller.rack = provisioning
}

func assertNoRackJoin(t *testing.T, ctx context.Context, region *Region, id string) {
	t.Helper()
	if approved, host, _, err := region.Enrollment(ctx, id); err != nil || approved != nil || host != nil {
		t.Fatalf("capacity was admitted before Ironic activated the installation: %v", err)
	}
}

type rackLabInstaller struct {
	mu         sync.Mutex
	t          *testing.T
	asset      rack.Asset
	state      string
	inspection time.Time
	allocation string
	image      rack.IronicImage
	imageSHA   string
	seed       *rack.ConfigDrive
	events     []string
}

func (s *rackLabInstaller) serve(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("X-Auth-Token") != "lab-site-service" || req.Header.Get("X-OpenStack-Ironic-API-Version") != "1.56" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node := "/v1/nodes/" + s.asset.NodeID
	switch {
	case req.Method == http.MethodGet && req.URL.Path == node:
		var info any = map[string]string{}
		if s.image.Source != "" {
			info = s.image
		}
		rackLabJSON(s.t, w, map[string]any{"uuid": s.asset.NodeID, "driver": "redfish", "boot_interface": "ipxe", "deploy_interface": "direct",
			"management_interface": "redfish", "inspect_interface": "redfish", "provision_state": s.state, "inspection_finished_at": s.inspection,
			"power_interface": "redfish", "storage_interface": "noop",
			"resource_class": "ocean-debian", "instance_uuid": s.allocation, "instance_info": info,
			"properties":  map[string]any{"cpus": 2, "memory_mb": 1024, "local_gb": 12, "cpu_arch": "x86_64"},
			"driver_info": map[string]any{"redfish_address": s.asset.BMC, "redfish_system_id": s.asset.System, "redfish_verify_ca": true}})
	case req.Method == http.MethodGet && req.URL.Path == node+"/ports/detail":
		rackLabJSON(s.t, w, map[string]any{"ports": []any{map[string]any{"node_uuid": s.asset.NodeID, "address": s.asset.BootMAC, "pxe_enabled": true}}})
	case req.Method == http.MethodGet && s.allocation != "" && req.URL.Path == "/v1/allocations/"+s.allocation:
		rackLabJSON(s.t, w, rack.IronicAllocation{ID: s.allocation, Node: s.asset.NodeID, State: "active"})
	case req.Method == http.MethodPost && req.URL.Path == "/v1/allocations" && s.state == "available" && s.allocation == "":
		var request struct {
			ID            string   `json:"uuid"`
			Candidates    []string `json:"candidate_nodes"`
			ResourceClass string   `json:"resource_class"`
		}
		if json.NewDecoder(req.Body).Decode(&request) != nil || len(request.ID) != 36 ||
			!slices.Equal(request.Candidates, []string{s.asset.NodeID}) || request.ResourceClass != "ocean-debian" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.allocation = request.ID
		s.events = append(s.events, "allocate")
		w.WriteHeader(http.StatusCreated)
	case req.Method == http.MethodPatch && req.URL.Path == node && s.state == "available" && s.allocation != "":
		var patch []struct {
			Op    string           `json:"op"`
			Path  string           `json:"path"`
			Value rack.IronicImage `json:"value"`
		}
		if json.NewDecoder(req.Body).Decode(&patch) != nil || len(patch) != 1 || patch[0].Op != "replace" || patch[0].Path != "/instance_info" ||
			patch[0].Value.SHA256 != s.imageSHA || patch[0].Value.Algo != "sha256" || patch[0].Value.DownloadSource != "http" ||
			!strings.HasSuffix(patch[0].Value.Source, "/debian.qcow2") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.image = patch[0].Value
		s.events = append(s.events, "pin-image")
		w.WriteHeader(http.StatusOK)
	case req.Method == http.MethodPut && req.URL.Path == node+"/states/provision":
		s.transition(w, req)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *rackLabInstaller) transition(w http.ResponseWriter, req *http.Request) {
	var request struct {
		Target string            `json:"target"`
		Seed   *rack.ConfigDrive `json:"configdrive"`
	}
	if json.NewDecoder(req.Body).Decode(&request) != nil || (request.Target == "active") != (request.Seed != nil) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	status := http.StatusAccepted
	switch {
	case request.Target == "manage" && s.state == "enroll":
		s.state = "manageable"
	case request.Target == "inspect" && s.state == "manageable" && s.inspection.IsZero():
		s.inspection = time.Now().UTC()
	case request.Target == "provide" && s.state == "manageable" && !s.inspection.IsZero():
		s.state = "available"
	case request.Target == "active" && s.state == "available" && s.image.Source != "" && request.Seed.Metadata["uuid"] == s.allocation:
		s.seed, s.state = request.Seed, "deploying"
		status = http.StatusServiceUnavailable // The transition took effect before its response was lost.
	default:
		w.WriteHeader(http.StatusConflict)
		return
	}
	s.events = append(s.events, request.Target)
	w.WriteHeader(status)
}

func (s *rackLabInstaller) configDrive() *rack.ConfigDrive {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seed
}

func (s *rackLabInstaller) complete() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = "active"
}

func rackLabEnrollment(t *testing.T, region *Region, directory, agent string) (*httptest.Server, string, <-chan int) {
	t.Helper()
	ca, key, _, _ := directoryJoinClientCertificates(t)
	pemPath := writeRackLabFile(t, directory, "enrollment-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeRackLabFile(t, directory, "enrollment-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	authority, _, err := enrollment.Open(enrollment.Config{CertificateFile: pemPath, KeyFile: keyPath}, region)
	if err != nil {
		t.Fatal(err)
	}
	attempts := make(chan int, 16)
	enrollmentHandler := authority.Handler(nil)
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/agent.deb" {
			http.ServeFile(w, req, agent)
			return
		}
		wrapped := &rackLabResponse{ResponseWriter: w}
		enrollmentHandler.ServeHTTP(wrapped, req)
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/enrollment") {
			select {
			case attempts <- wrapped.status:
			default:
			}
		}
	}))
	service.TLS = directoryLabServerTLS(t, ca, key)
	service.StartTLS()
	t.Cleanup(service.Close)
	return service, pemPath, attempts
}

type rackLabResponse struct {
	http.ResponseWriter
	status int
}

func (r *rackLabResponse) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func rackLabFileHash(t *testing.T, path string) string {
	t.Helper()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	digest := sha256.New()
	if _, err := io.Copy(digest, input); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func bootRackLabGuest(t *testing.T, ctx context.Context, directory, image, mac string, address netip.Addr,
	seed *rack.ConfigDrive) func(string) (string, error) {
	t.Helper()
	key := filepath.Join(directory, "operator-key")
	runRackLabCommand(t, ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	public, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	seed.Metadata["public_keys"] = map[string]string{"operator": strings.TrimSpace(string(public))}
	content := filepath.Join(directory, "seed", "openstack", "latest")
	if err := os.MkdirAll(content, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]any{"meta_data.json": seed.Metadata, "network_data.json": seed.Network} {
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		writeRackLabFile(t, content, name, raw)
	}
	writeRackLabFile(t, content, "user_data", []byte(seed.UserData))
	iso := filepath.Join(directory, "config-drive.iso")
	runRackLabCommand(t, ctx, "genisoimage", "-quiet", "-output", iso, "-volid", "config-2", "-joliet", "-rock", filepath.Join(directory, "seed"))
	if err := os.Chmod(iso, 0o600); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(directory, "installed.qcow2")
	runRackLabCommand(t, ctx, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, disk, "12G")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := rackLabListenerPort(t, listener)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	console := filepath.Join(directory, "console.log")
	qemu := exec.CommandContext(ctx, "nice", "-n", "10", "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host",
		"-m", "1024", "-smp", "2", "-display", "none", "-serial", "file:"+console, "-boot", "order=c,strict=on",
		"-drive", "file="+disk+",if=virtio,format=qcow2", "-drive", "file="+iso+",media=cdrom,readonly=on,format=raw",
		"-netdev", "user,id=nic,hostfwd=tcp:127.0.0.1:"+port+"-"+address.String()+":22",
		"-device", "virtio-net-pci,netdev=nic,mac="+mac)
	qemu.Stderr = os.Stderr
	if err := qemu.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = qemu.Process.Kill()
		_ = qemu.Wait()
		if t.Failed() {
			output, err := os.ReadFile(console)
			if err == nil {
				t.Logf("Debian guest console tail:\n%s", output[max(0, len(output)-16000):])
			}
		}
	})
	return func(remote string) (string, error) {
		request, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		output, err := exec.CommandContext(request, "ssh", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
			"-o", "ConnectTimeout=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile="+filepath.Join(directory, "known_hosts"),
			"-i", key, "-p", port, "debian@127.0.0.1", remote).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("guest command failed: %w: %s", err, output)
		}
		return strings.TrimSpace(string(output)), nil
	}
}

func rackLabListenerPort(t *testing.T, listener net.Listener) string {
	t.Helper()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func runRackLabCommand(t *testing.T, ctx context.Context, binary string, args ...string) {
	t.Helper()
	if output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v: %s", binary, err, output)
	}
}

func awaitRackLabGuest(t *testing.T, ctx context.Context, check func() (string, error)) string {
	t.Helper()
	var lastErr error
	for ctx.Err() == nil {
		value, err := check()
		if err == nil {
			return value
		}
		lastErr = err
		time.Sleep(750 * time.Millisecond)
	}
	t.Fatalf("Debian guest did not reach readiness: %v", lastErr)
	return ""
}
