//go:build e2e

package network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPrivateHTTPSIngress(t *testing.T) {
	if os.Getenv("OCEAN_E2E_HTTPS_INGRESS") != "1" {
		t.Skip("requires an isolated Debian guest with root, HAProxy, curl, and Python")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	run := func(command string, args ...string) string {
		t.Helper()
		result, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %q: %v: %s", command, args, err, result)
		}
		return strings.TrimSpace(string(result))
	}
	stamp := strconv.Itoa(os.Getpid())
	gateway, client, backend := "oghttps"+stamp, "ochttps"+stamp, "obhttps"+stamp
	for _, namespace := range []string{gateway, client, backend} {
		run("ip", "netns", "add", namespace)
		t.Cleanup(func() {
			cleanup, clear := context.WithTimeout(context.Background(), 5*time.Second)
			defer clear()
			if out, err := exec.CommandContext(cleanup, "ip", "netns", "delete", namespace).CombinedOutput(); err != nil {
				t.Errorf("delete namespace %s: %v: %s", namespace, err, out)
			}
		})
		run("ip", "-n", namespace, "link", "set", "lo", "up")
	}
	attach := func(other, name, gatewayAddress, targetAddress string) {
		t.Helper()
		run("ip", "-n", gateway, "link", "add", name, "type", "veth", "peer", "name", "eth0", "netns", other)
		run("ip", "-n", gateway, "addr", "add", gatewayAddress, "dev", name)
		run("ip", "-n", other, "addr", "add", targetAddress, "dev", "eth0")
		run("ip", "-n", gateway, "link", "set", name, "up")
		run("ip", "-n", other, "link", "set", "eth0", "up")
	}
	attach(client, "public0", "198.51.100.20/24", "198.51.100.2/24")
	attach(backend, "work0", "10.89.1.1/24", "10.89.1.4/24")
	run("ip", "netns", "exec", gateway, "sysctl", "-q", "-w", "net.ipv4.ip_forward=0")
	run("ip", "-n", client, "route", "add", "10.89.1.0/24", "via", "198.51.100.20")

	const hostname = "ingress.ocean.test"
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	bundle := filepath.Join(dir, "ingress.pem")
	writeIngressTestCert(t, hostname, ca, bundle)
	pfx := filepath.Join(dir, "ingress.pfx")
	run("/usr/bin/openssl", "pkcs12", "-export", "-inkey", bundle, "-in", ca, "-out", pfx, "-passout", "pass:disposable")
	encoded, err := os.ReadFile(pfx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHTTPSCertificate(ctx, encoded, "unrecognized"); err == nil {
		t.Fatal("a certificate with the wrong password was accepted")
	}
	certificate, err := DecodeHTTPSCertificate(ctx, encoded, "disposable")
	if err != nil || certificate.Hostname != hostname || len(certificate.PublicCertificate) == 0 {
		t.Fatalf("decode the PFX for the gateway: %v", err)
	}
	if err := os.WriteFile(bundle, certificate.Bundle, 0600); err != nil {
		t.Fatal(err)
	}
	configuration := HTTPSIngress{PublicIPv4: netip.MustParseAddr("198.51.100.20"), Hostname: hostname, CertificateFile: bundle,
		Backend: netip.MustParseAddrPort("10.89.1.4:8080"), BackendSubnet: netip.MustParsePrefix("10.89.1.0/24")}
	rendered, err := configuration.HAProxy()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(configPath, []byte(rendered), 0600); err != nil {
		t.Fatal(err)
	}
	run("ip", "netns", "exec", gateway, "/usr/sbin/haproxy", "-c", "-f", configPath)

	start := func(namespace, command string, args ...string) {
		t.Helper()
		process := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", namespace, command}, args...)...)
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = process.Process.Kill()
			_ = process.Wait()
		})
	}
	start(backend, "python3", "-c", `
from http.server import BaseHTTPRequestHandler, HTTPServer
class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        values = ["ocean-https", self.headers.get("X-Forwarded-For"), self.headers.get("X-Forwarded-Proto"),
                  self.headers.get("X-Forwarded-Host"), self.headers.get("Forwarded", "unset")]
        self.wfile.write(":".join(values).encode())
HTTPServer(("10.89.1.4", 8080), Fixture).serve_forever()
`)
	start(gateway, "/usr/sbin/haproxy", "-db", "-f", configPath)

	probe := func(args ...string) ([]byte, error) {
		base := []string{"netns", "exec", client, "curl", "--noproxy", "*", "-sS", "--max-time", "1"}
		return exec.CommandContext(ctx, "ip", append(base, args...)...).CombinedOutput()
	}
	resolve := hostname + ":443:198.51.100.20"
	var got []byte
	for deadline := time.Now().Add(8 * time.Second); ; {
		got, err = probe("--fail", "--cacert", ca, "--resolve", resolve,
			"-H", "X-Forwarded-For: 10.231.1.3", "-H", "Forwarded: for=10.231.1.3", "https://"+hostname+"/")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || string(got) != "ocean-https:198.51.100.2:https:"+hostname+":unset" {
		t.Fatalf("unexpected HTTPS backend response: %v: %s", err, got)
	}
	got, err = probe("--cacert", ca, "--resolve", resolve, "-H", "Host: wrong.ocean.test", "-o", "/dev/null",
		"-w", "%{http_code}", "https://"+hostname+"/")
	if err != nil || string(got) != "421" {
		t.Fatalf("unexpected response to an unrecognized HTTP hostname: %v: %s", err, got)
	}
	if got, err = probe("-k", "--resolve", "wrong.ocean.test:443:198.51.100.20", "https://wrong.ocean.test/"); err == nil {
		t.Fatalf("an unrecognized TLS hostname was accepted: %s", got)
	}
	if got, err = probe("http://10.89.1.4:8080/"); err == nil {
		t.Fatalf("the outside client reached the private workload directly: %s", got)
	}
	t.Log("HAProxy delivered trusted HTTPS, replaced spoofed forwarding headers, and blocked unknown names and direct access")
}

func writeIngressTestCert(t *testing.T, hostname, ca, bundle string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname},
		BasicConstraintsValid: true, IsCA: true, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{hostname}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(ca, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	pair := append(certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
	if err := os.WriteFile(bundle, pair, 0600); err != nil {
		t.Fatal(err)
	}
}
