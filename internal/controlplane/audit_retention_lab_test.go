//go:build e2e

package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestHostedAuditRetention(t *testing.T) {
	endpoint, cliPath := os.Getenv("OCEAN_E2E_HOSTED_ETCD"), os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if endpoint == "" || cliPath == "" {
		t.Skip("requires isolated lab etcd and stock Azure CLI")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("use a disposable loopback etcd endpoint")
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	root := "/test/hosted-audit/" + operationID()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if _, err := client.Delete(cleanup, root+"/", clientv3.WithPrefix()); err != nil {
			t.Error(err)
		}
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	keys, values := initialRecords(root, "hosted-lab", "cell-1")
	r := &Region{client: client, name: "hosted-lab", root: root, cell: "cell-1", keys: keys, values: values, auditRetention: time.Minute}
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, duration := range []time.Duration{0, 10 * time.Minute, time.Minute} {
		replica := &Region{client: client, name: r.name, root: root, cell: r.cell, keys: keys, values: values, auditRetention: duration}
		if err := replica.bootstrap(ctx); (err == nil) != (duration == r.auditRetention) {
			t.Fatalf("unexpected bootstrap result for replica with audit retention %s: %v", duration, err)
		}
	}

	owner := arm.SubscriptionScope{TenantID: "tenant-a", SubscriptionID: operationID()}
	foreign := arm.SubscriptionScope{TenantID: "tenant-b", SubscriptionID: operationID()}
	now := time.Now().UTC()
	auditKeys := make(map[string]bool)
	for _, scope := range []arm.SubscriptionScope{owner, foreign} {
		prefix := r.armPrefix(scope)
		for namespace, recordedAt := range map[string]time.Time{"expired": now.Add(-2 * time.Minute), "current": now.Add(-5 * time.Second)} {
			event := arm.AuditEvent{Time: recordedAt, Actor: "lab-principal", Action: "Ocean.Test/" + namespace,
				Target: "/subscriptions/" + scope.SubscriptionID + "/resourceGroups/privacy-sample", Outcome: "Succeeded"}
			if err := r.RecordAudit(ctx, scope, event); err != nil {
				t.Fatal(err)
			}
		}
		records, err := client.Get(ctx, prefix+"audit/", clientv3.WithPrefix())
		if err != nil || len(records.Kvs) != 2 {
			t.Fatalf("read both initial persisted audit events: %v", err)
		}
		for _, record := range records.Kvs {
			var event arm.AuditEvent
			if err := json.Unmarshal(record.Value, &event); err != nil {
				t.Fatal(err)
			}
			auditKeys[string(record.Key)] = event.Action == "Ocean.Test/current"
		}
	}
	// Force the sweep to cross a page of non-audit metadata between tenants.
	noise := make([]clientv3.Op, 0, 70)
	for i := range cap(noise) {
		key := r.armPrefix(owner) + fmt.Sprintf("inventory/lab-%03d", i)
		noise = append(noise, clientv3.OpPut(key, `{"time":"2000-01-01T00:00:00Z","action":"DoNotRemove"}`))
	}
	if _, err := client.Txn(ctx).Then(noise...).Commit(); err != nil {
		t.Fatal(err)
	}

	ca, caKey, _, _ := directoryJoinClientCertificates(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(nil)
	defer api.Close()
	api.TLS = directoryLabServerTLS(t, ca, caKey)
	api.Config.Handler = arm.Server{Origin: "https://" + api.Listener.Addr().String(), Location: r.name, Roles: r, Monitor: r,
		Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			scope := owner
			switch request.Header.Get("Authorization") {
			case "Bearer audit-owner-lab":
			case "Bearer audit-foreign-lab":
				scope = foreign
			default:
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: "operator", Subscription: identity.Subscription{
				TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, DisplayName: "Lab Subscription", Members: []string{"operator"},
			}}, nil
		},
	}.Handler(http.NotFoundHandler())
	api.StartTLS()
	az := regionalWorkerCLI(t, ctx, api.URL, caPath, cliPath)
	query := url.Values{"api-version": {"2015-04-01"}, "$filter": {fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'",
		now.Add(-10*time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339))}}
	path := "/subscriptions/" + owner.SubscriptionID + "/providers/Microsoft.Insights/eventtypes/management/values?" + query.Encode()
	visible := func() {
		t.Helper()
		raw := az("get", path, "", "audit-owner-lab", "")
		var rows struct {
			Value []struct {
				OperationName struct{ Value string } `json:"operationName"`
			} `json:"value"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil || len(rows.Value) != 1 || rows.Value[0].OperationName.Value != "Ocean.Test/current" {
			t.Fatalf("Azure CLI must return only the current audit event: %v: %s", err, raw)
		}
	}
	visible()
	az("get", path, "", "audit-foreign-lab", "SubscriptionNotFound")
	started := time.Now()
	stopSweep := make(chan struct{})
	sweepCtx, cancelSweep := context.WithCancel(ctx)
	doSweep := func() {
		defer close(stopSweep)
		r.reconcileAuditRetention(sweepCtx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	go doSweep()
	defer func() {
		cancelSweep()
		<-stopSweep
	}()
	pollVMWorker(t, ctx, 8*time.Second, "all expired activity keys to be pruned across both tenants", func() bool {
		for key, expected := range auditKeys {
			entry, err := client.Get(ctx, key, clientv3.WithCountOnly())
			if err != nil || (entry.Count == 1) != expected {
				return false
			}
		}
		return true
	})
	elapsed := time.Since(started)
	remaining, err := client.Get(ctx, r.armPrefix(owner)+"inventory/", clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil || remaining.Count != int64(len(noise)) {
		t.Fatalf("audit expiry changed unrelated tenant metadata: %v", err)
	}
	visible()
	t.Logf("Azure CLI 2.93.0 hid expired audit events before the sweep and rejected the other subscription. Both stale current-store records were deleted within %d ms. Recent and unrelated entries survived.", elapsed.Milliseconds())
}
