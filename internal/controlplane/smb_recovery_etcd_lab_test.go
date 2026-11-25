//go:build e2e

package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func prepareSMBRecoveryEtcd(t *testing.T, ctx context.Context, archive, directory string) (etcdConfig, string, string, string, string) {
	t.Helper()
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, err = io.Copy(digest, file)
	if closeErr := file.Close(); err != nil || closeErr != nil ||
		fmt.Sprintf("%x", digest.Sum(nil)) != "5c6365e03d0c81f605458f3f9a115f6daaebca08d1fb42d3ab0f1a38fd30909c" {
		t.Fatalf("the etcd 3.6.17 lab archive does not match its pin: %v %v", err, closeErr)
	}
	const release = "etcd-v3.6.17-linux-amd64/"
	etcdLabCommand(t, ctx, nil, "tar", "-xzf", archive, "-C", directory, "--strip-components=1", release+"etcd", release+"etcdctl", release+"etcdutl")

	ca, signer, client, _ := directoryJoinClientCertificates(t)
	server := directoryLabServerTLS(t, ca, signer).Certificates[0]
	write := func(name, kind string, data []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pair := func(name string, certificate tls.Certificate) (string, string) {
		t.Helper()
		key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		return write(name+".pem", "CERTIFICATE", certificate.Certificate[0]), write(name+".key", "PRIVATE KEY", key)
	}
	clientCert, clientKey := pair("etcd-client", client)
	serverCert, serverKey := pair("etcd-server", server)
	return etcdConfig{CAFile: write("etcd-ca.pem", "CERTIFICATE", ca.Raw), CertificateFile: clientCert, KeyFile: clientKey},
		serverCert, serverKey, filepath.Join(directory, "etcd"), filepath.Join(directory, "etcdctl")
}

func startSMBRecoveryEtcd(t *testing.T, ctx context.Context, cfg etcdConfig, serverCert, serverKey, etcd, data string, restore func(string, string, string)) (etcdConfig, uint64, func()) {
	t.Helper()
	loopback := func() string {
		t.Helper()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		return address
	}
	endpoint, peer, token := "https://"+loopback(), "http://"+loopback(), operationID()
	cluster := "smb-recovery=" + peer
	if restore != nil {
		restore(peer, cluster, token)
	}
	logFile, err := os.OpenFile(data+".log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, etcd, "--name", "smb-recovery", "--data-dir", data,
		"--listen-client-urls", endpoint, "--advertise-client-urls", endpoint, "--listen-peer-urls", peer, "--initial-advertise-peer-urls", peer,
		"--initial-cluster", cluster, "--initial-cluster-token", token, "--client-cert-auth",
		"--trusted-ca-file", cfg.CAFile, "--cert-file", serverCert, "--key-file", serverKey)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	stop := func() {
		t.Helper()
		if cmd.ProcessState != nil {
			return
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if err := logFile.Close(); err != nil {
			t.Error(err)
		}
		if t.Failed() {
			log, err := os.ReadFile(logFile.Name())
			if err == nil && len(log) > 6144 {
				log = log[len(log)-6144:]
			}
			t.Logf("disposable etcd journal %s: %v\n%s", filepath.Base(data), err, log)
		}
	}
	t.Cleanup(stop)
	cfg.Endpoints = []string{endpoint}
	connection, err := cfg.clientConfig()
	if err != nil {
		t.Fatal(err)
	}
	probe, err := clientv3.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	var clusterID uint64
	pollVMWorker(t, ctx, 20*time.Second, "the isolated etcd with mutual TLS", func() bool {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		status, err := probe.Status(attempt, endpoint)
		if err != nil {
			return false
		}
		clusterID = status.Header.ClusterId
		return clusterID != 0
	})
	return cfg, clusterID, stop
}

func etcdLabCommand(t *testing.T, ctx context.Context, env []string, command string, args ...string) []byte {
	t.Helper()
	probe := exec.CommandContext(ctx, command, args...)
	probe.Env = env
	output, err := probe.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", filepath.Base(command), err, output)
	}
	return output
}
