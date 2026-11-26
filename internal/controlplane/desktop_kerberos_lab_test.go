//go:build e2e

package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// TestDesktopKerberosLabService exposes the real regional guest endpoint to
// the disposable browser and Debian session probe.
func TestDesktopKerberosLabService(t *testing.T) {
	path := os.Getenv("OCEAN_E2E_DESKTOP_KERBEROS_SERVICE")
	if path == "" {
		t.Skip("requires a disposable desktop Kerberos service fixture")
	}
	settings, err := config.Load(path, struct {
		Origin    string              `json:"origin"`
		Listen    string              `json:"listen"`
		TLS       config.TLS          `json:"tls"`
		Etcd      string              `json:"etcd"`
		Launch    desktopLaunchConfig `json:"launch"`
		SMB       smbBinding          `json:"smb"`
		DoneFile  string              `json:"doneFile"`
		Namespace string              `json:"namespace"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	if !identifier.MatchString(settings.Namespace) {
		t.Fatal("provide a unique disposable broker namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	etcd, err := clientv3.New(clientv3.Config{Endpoints: []string{settings.Etcd}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = etcd.Close() }()
	r := &Region{client: etcd, root: "/ocean/tests/desktop-broker/" + settings.Namespace}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := etcd.Delete(cleanup, r.root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
	}()
	smb := &smbControl{bindings: map[arm.SubscriptionScope]smbBinding{settings.SMB.scope(): settings.SMB}}
	r.desktopLaunch, err = openDesktopLaunch(&settings.Launch, true, smb)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapDesktopLaunch(ctx); err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	ca, err := os.ReadFile(settings.TLS.ClientCAFile)
	if err != nil || !trust.AppendCertsFromPEM(ca) {
		t.Fatal("load the desktop guest fixture CA")
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: (arm.Server{Origin: settings.Origin, DesktopCIFS: r}).
		Handler(http.NotFoundHandler()), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: trust}}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", settings.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = server.Close() }()
	service := make(chan error, 1)
	go func() { service <- server.ServeTLS(listener, settings.TLS.CertificateFile, settings.TLS.KeyFile) }()
	t.Log("desktop Kerberos lab endpoint ready")
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-service:
			t.Fatalf("desktop Kerberos endpoint stopped: %v", err)
		case <-ctx.Done():
			t.Fatal("desktop Kerberos lab probe did not finish")
		case <-ticker.C:
			if _, err := os.Stat(settings.DoneFile); err == nil {
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
				if err := <-service; !errors.Is(err, http.ErrServerClosed) {
					t.Fatal(err)
				}
				return
			}
		}
	}
}
