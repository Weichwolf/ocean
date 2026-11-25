//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

type regionalUserFixture struct {
	ctx                           context.Context
	root, private                 string
	api, graph, issuer            *httptest.Server
	tenant                        identity.TenantReservation
	app, secret, member           string
	clientImage, network, address string
	work                          func(context.Context) error
	observe                       func()
	sign                          func(string, string) string
}

func (f regionalUserFixture) verify(t *testing.T) {
	t.Helper()
	workerCtx, stop := context.WithCancel(f.ctx)
	workerExit := make(chan error, 1)
	go func() {
		tick := time.NewTicker(180 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-workerCtx.Done():
				workerExit <- nil
				return
			case <-tick.C:
				if err := f.work(workerCtx); err != nil && workerCtx.Err() == nil {
					workerExit <- err
					return
				}
			}
		}
	}()
	defer func() {
		stop()
		if err := <-workerExit; err != nil {
			t.Errorf("directory user worker: %v", err)
		}
	}()
	rootPEM := filepath.Join(f.private, "graph-ca.pem")
	var trust []byte
	for _, server := range []*httptest.Server{f.api, f.graph, f.issuer} {
		trust = append(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})...)
	}
	if err := os.WriteFile(rootPEM, trust, 0o600); err != nil {
		t.Fatal(err)
	}
	password := "Oc9-" + rand.Text() + rand.Text()
	replacementPassword := "Oc9-" + rand.Text() + rand.Text()
	run := func(reject bool, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(f.ctx, "az", args...)
		cmd.Env = append(os.Environ(), "AZURE_CONFIG_DIR="+filepath.Join(f.private, "graph-az"), "REQUESTS_CA_BUNDLE="+rootPEM,
			"AZURE_CORE_INSTANCE_DISCOVERY=false", "AZURE_CORE_COLLECT_TELEMETRY=0", "AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no")
		out, err := cmd.CombinedOutput()
		if (err != nil) != reject {
			label := args[:2]
			if len(args) > 2 && args[0] == "ad" {
				label = args[:3]
			}
			t.Fatalf("Azure CLI %s returned %v: %s", strings.Join(label, " "), err,
				strings.NewReplacer(f.secret, "[fixture secret]", password, "[directory password]",
					replacementPassword, "[directory password]").Replace(string(out)))
		}
		return out
	}
	var version struct {
		CLI        string            `json:"azure-cli"`
		Extensions map[string]string `json:"extensions"`
	}
	if err := json.Unmarshal(run(false, "version", "-o", "json"), &version); err != nil || version.CLI != "2.93.0" || len(version.Extensions) != 0 {
		t.Fatal("the Graph user case requires the pinned CLI")
	}
	run(false, "cloud", "register", "--name", "directory-fixture", "--endpoint-resource-manager", f.api.URL,
		"--endpoint-active-directory", f.issuer.URL+"/", "--endpoint-active-directory-resource-id", f.api.URL+"/",
		"--endpoint-microsoft-graph-resource-id", f.graph.URL+"/")
	run(false, "cloud", "set", "--name", "directory-fixture")
	run(false, "login", "--service-principal", "--username", f.app, "--password", f.secret, "--tenant", f.tenant.TenantID, "-o", "none")

	ad := func(reject bool, args ...string) []byte {
		t.Helper()
		f.observe()
		return run(reject, append([]string{"ad", "user"}, args...)...)
	}
	const upn = "marine@ad.runtime.test"
	const alias = "marine.ops"
	var created enrollment.DirectoryUserView
	out := ad(false, "create", "--user-principal-name", upn, "--display-name", "Marine Agent",
		"--mail-nickname", alias, "--password", password, "-o", "json")
	if bytes.Contains(out, []byte(password)) || json.Unmarshal(out, &created) != nil ||
		created.UPN != upn || !enrollment.ValidDirectoryJoinID(created.ID) || !created.Enabled ||
		created.Alias != alias || created.Mail != alias+"@ad.runtime.test" {
		t.Fatal("Graph creation did not return the Samba workforce user")
	}
	for _, filter := range [][]string{{"--upn", upn}, {"--display-name", "Marine"}} {
		var listed []enrollment.DirectoryUserView
		args := append([]string{"list", "-o", "json"}, filter...)
		if err := json.Unmarshal(ad(false, args...), &listed); err != nil || len(listed) != 1 || listed[0].ID != created.ID {
			t.Fatal("the pinned CLI user filter did not resolve the AD object")
		}
	}
	var shown enrollment.DirectoryUserView
	if err := json.Unmarshal(ad(false, "show", "--id", upn, "-o", "json"), &shown); err != nil || shown.ID != created.ID {
		t.Fatal("the UPN did not resolve to its original AD object GUID")
	}
	probe := func(credential string, reject bool) {
		t.Helper()
		cmd := exec.CommandContext(f.ctx, "bash", filepath.Join(f.root, "lab/run_adcli_probe.sh"), f.clientImage, f.network, f.address, "authenticate", "marine")
		cmd.Stdin = strings.NewReader(credential + "\n")
		out, err := cmd.CombinedOutput()
		if (err != nil) != reject || reject && !bytes.Contains(out, []byte("credentials have been revoked")) {
			t.Fatalf("fresh Kerberos validation failed: %v: %s", err, strings.ReplaceAll(string(out), credential, "[directory password]"))
		}
	}
	probe(password, false)
	ad(false, "update", "--id", created.ID, "--password", replacementPassword, "-o", "none")
	probe(replacementPassword, false)
	ad(false, "update", "--id", created.ID, "--display-name", "Marine Operations", "--account-enabled", "false", "-o", "none")
	if err := json.Unmarshal(ad(false, "show", "--id", created.ID, "-o", "json"), &shown); err != nil ||
		shown.ID != created.ID || shown.Enabled || shown.DisplayName != "Marine Operations" || shown.Alias != alias {
		t.Fatal("Graph did not preserve identity and alias while disabling the user")
	}
	probe(replacementPassword, true)
	if out := ad(true, "show", "--id", "Administrator@ad.runtime.test", "-o", "json"); !bytes.Contains(out, []byte("managed user was not found")) {
		t.Fatal("the managed route did not protect the Samba administrator")
	}
	for _, check := range []struct {
		audience, subject string
		status            int
	}{
		{f.api.URL, f.tenant.Administrator, http.StatusUnauthorized},
		{f.graph.URL, f.member, http.StatusForbidden},
	} {
		request, err := http.NewRequestWithContext(f.ctx, http.MethodGet, f.graph.URL+"/v1.0/users", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.sign(check.audience, check.subject))
		response, err := f.graph.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != check.status {
			t.Fatalf("Graph returned an unexpected authorization status %d", response.StatusCode)
		}
	}
	t.Log("Azure CLI 2.93.0 created, listed, read, rotated the password and disabled a Samba workforce user through mTLS and etcd. Debian obtained a fresh Kerberos ticket with the new password and was denied after disable.")
}
