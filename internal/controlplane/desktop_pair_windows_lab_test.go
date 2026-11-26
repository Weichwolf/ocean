//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	pairWindowsIP = "10.232.1.28"
	pairCRLPort   = "18711"
)

type desktopPairWindowsClient struct {
	state  string
	root   *x509.Certificate
	key    *rsa.PrivateKey
	crl    string
	leaves map[string][]byte
}

func newDesktopPairWindowsClient(t *testing.T, ctx context.Context, worker directoryKVMHosts, state string) *desktopPairWindowsClient {
	t.Helper()
	root, err := os.ReadFile(filepath.Join(state, "rdp-root.cer"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(root)
	if err != nil || !certificate.IsCA || time.Now().Before(certificate.NotBefore) || time.Until(certificate.NotAfter) < time.Hour {
		t.Fatalf("provide a valid disposable Windows RDP test root: %v", err)
	}
	keyFile := filepath.Join(state, "rdp-root.key")
	info, err := os.Stat(keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("provide the private lab signing key with mode 0600")
	}
	private, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, _ := pem.Decode(private)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("expected a PKCS #8 PEM lab signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		t.Fatal("the Windows RDP test root and RSA key do not match")
	}
	now := time.Now()
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(now.UnixNano()),
		ThisUpdate: now.Add(-2 * time.Minute), NextUpdate: now.Add(time.Hour)}, certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	unit := worker.directory + "-desktop-crl"
	directory := "/run/" + unit
	worker.run(ctx, desktopRDPObserver, "sudo install -d -m 0755 "+directory+" && sudo tee "+directory+"/desktop-root.crl >/dev/null",
		bytes.NewReader(crl))
	worker.run(ctx, desktopRDPObserver, "sudo systemd-run --quiet --collect --unit="+unit+
		" --property=DynamicUser=yes --property=ProtectSystem=strict /usr/bin/python3 -m http.server --bind "+pairObserverIP+
		" --directory "+directory+" "+pairCRLPort, nil)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		worker.run(cleanup, desktopRDPObserver, "sudo systemctl stop "+unit+" && sudo rm -rf -- "+directory, nil)
	})
	url := "http://" + net.JoinHostPort(pairObserverIP, pairCRLPort) + "/desktop-root.crl"
	pollVMWorker(t, ctx, 10*time.Second, "the isolated desktop CRL endpoint", func() bool {
		out, err := worker.ssh(ctx, desktopRDPObserver, "curl -fsS "+url, nil)
		return err == nil && bytes.Equal(out, crl)
	})
	return &desktopPairWindowsClient{state: state, root: certificate, key: key, crl: url, leaves: make(map[string][]byte)}
}

func (c *desktopPairWindowsClient) serverCertificate(t *testing.T, machine desktopPairMachine) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	name := machine.name + "." + pairDomain
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		IPAddresses: []net.IP{net.ParseIP(machine.ip)}, CRLDistributionPoints: []string{c.crl},
		NotBefore: time.Now().Add(-2 * time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, c.root, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	c.leaves[machine.name] = cert
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}

func (c *desktopPairWindowsClient) connect(ctx context.Context, machine desktopPairMachine, account desktopPairAccount) ([]byte, error) {
	input, err := json.Marshal(map[string]string{"target": machine.name + "." + pairDomain, "address": machine.ip, "source": pairWindowsIP,
		"user": account.user.UPN, "password": account.password, "root": hex.EncodeToString(c.root.Raw),
		"leaf": hex.EncodeToString(c.leaves[machine.name])})
	if err != nil {
		return nil, err
	}
	defer clear(input)
	command := desktopPairWindowsCommand(ctx, c.state)
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

func desktopPairWindowsCommand(ctx context.Context, state string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "python3", append([]string{"-B", filepath.Join("..", "..", "lab", "windows_desktop_rdp.py"), "--state", state}, args...)...)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	return command
}

func readDesktopPairWindowsReport(t *testing.T, data []byte, allowed bool) (string, string) {
	t.Helper()
	var started, finished struct {
		Event         string `json:"event"`
		Source        string `json:"source"`
		ClientVersion string `json:"clientVersion"`
		Edition       string `json:"windowsEdition"`
		Build         string `json:"build"`
		Connected     int    `json:"connected"`
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 || json.Unmarshal(lines[0], &started) != nil || json.Unmarshal(lines[1], &finished) != nil ||
		started.Event != "starting" || finished.Event != "finished" || started.Source != pairWindowsIP ||
		started.ClientVersion == "" || strings.ContainsAny(started.ClientVersion, "\t\r\n") ||
		started.Build == "" || (started.Edition != "Professional" && started.Edition != "EnterpriseEval") ||
		(allowed && finished.Connected != 1) {
		t.Fatalf("the native Windows 11 RDP client did not complete its attempt: %s", data)
	}
	return started.ClientVersion, fmt.Sprintf("Windows 11 %s %s", started.Edition, started.Build)
}
