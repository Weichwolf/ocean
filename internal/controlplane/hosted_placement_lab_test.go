//go:build e2e

package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/storage"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestHostedPlacement(t *testing.T) {
	client, cliPath := hostedLabEtcd(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	root := hostedLabRoot(t, client, "hosted-placement")
	policy := &hostedRegionPolicy{Country: "DE", OperatorPools: map[string]string{"primary": "DE", "partner": "NL"}}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []*hostedRegionPolicy{
		{Country: "CH", OperatorPools: policy.OperatorPools},
		{Country: "DE", OperatorPools: map[string]string{"primary": "CH"}},
	} {
		if _, err := openRegion(regionConfig{Name: "hosted", InitialCell: "cell-1", HostedWorkplace: invalid}); err == nil {
			t.Fatal("accepted a non-EU regional or operator pool country")
		}
	}
	key, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cipher.NewGCMWithRandomNonce(key)
	if err != nil {
		t.Fatal(err)
	}
	public, fencer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	quota := enrollment.Capacity{CPUMillis: 800, MemoryMiB: 512}
	defaultPlacement := PlacementPolicy{Pools: []string{"primary", "partner"}, Quota: quota}
	keys, values := initialRecords(root, "hosted", "cell-1", policy)
	r := &Region{client: client, root: root, name: "hosted", cell: "cell-1", keys: keys, values: values, hosted: policy,
		workloads: &workloadControl{defaultPlacement: defaultPlacement},
		storage:   &storageControl{sealer: sealer, fencer: public, workers: []string{"a-partner", "b-primary"}}}
	if err := r.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	for _, proposed := range []*hostedRegionPolicy{nil, {Country: "FR", OperatorPools: policy.OperatorPools}, policy} {
		_, records := initialRecords(root, r.name, r.cell, proposed)
		replica := &Region{client: client, keys: keys, values: records}
		if err := replica.ready(ctx); (err == nil) != (proposed == policy) {
			t.Fatalf("unexpected regional policy comparison: %v", err)
		}
	}
	if err := r.seedHostInventory(ctx, []enrollment.Approval{{HostID: "offsite", Pool: "offsite"}}); err == nil {
		t.Fatal("accepted an inventory entry outside the approved pools")
	}
	if err := r.seedHostInventory(ctx, []enrollment.Approval{{HostID: "b-primary", Pool: "primary", Roles: []string{"compute"}}}); err == nil {
		t.Fatal("accepted a storage worker absent from the approved inventory")
	}
	approved := seedHostedPlacementWorker(t, ctx, r, "b-primary", "primary")
	other := seedHostedPlacementWorker(t, ctx, r, "a-partner", "partner")
	seedHostedPlacementWorker(t, ctx, r, "a-offsite", "offsite")
	tenant := identity.TenantReservation{TenantID: operationID(), SubscriptionID: operationID(), Administrator: operationID(), Fingerprint: operationID()}
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	subscription := identity.Subscription{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		DisplayName: "Hosted lab", Members: []string{tenant.Administrator}}
	if _, err := r.ReserveTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PublishSubscription(ctx, tenant, subscription); err != nil {
		t.Fatal(err)
	}
	if err := r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"offsite"}, Quota: quota}); !errors.Is(err, ErrPlacementPolicy) {
		t.Fatalf("unexpected external pool result: %v", err)
	}
	if err := r.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"primary"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	request := PlacementRequest{ID: "guest-test", Cell: r.cell, Role: "compute", Resources: quota, NeedsVMRuntime: true, NeedsStorage: true}
	placement, err := r.ReservePlacement(ctx, scope, request)
	if err != nil || placement.HostID != approved.HostID {
		t.Fatalf("guest placed outside its tenant pool: %v", err)
	}
	request.ID, request.NeedsVMRuntime, request.NeedsStorage, request.NeedsDirectoryRuntime = "directory-target", false, false, true
	if _, err := r.chooseHosts(ctx, scope, request, defaultPlacement.Pools, 2, approved.HostID); !errors.Is(err, ErrNoEligibleHost) {
		t.Fatalf("admitted an offsite directory replacement: %v", err)
	}
	az := hostedPlacementCLI(t, ctx, r, cliPath, tenant.Administrator, subscription)
	if _, _, err := r.PutGroup(ctx, scope, arm.Group{Name: "lab", Location: r.name, Tags: map[string]string{}}, tenant.Administrator); err != nil {
		t.Fatal(err)
	}
	account := arm.ResourceAddress{Group: "lab", Path: storage.AccountType + "/hostedfixture"}
	accountURL := account.ID(scope) + "?api-version=" + storage.AccountAPIVersion
	accountBody := `{"location":%q,"kind":"StorageV2","sku":{"name":"Standard_LRS"},"properties":{"publicNetworkAccess":"Disabled"}}`
	az("put", accountURL, fmt.Sprintf(accountBody, "offsite"), "hosted-lab", "InvalidRequestContent")
	az("put", accountURL, fmt.Sprintf(accountBody, r.name), "hosted-lab", "")
	share := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/fixture"}
	shareURL := share.ID(scope) + "?api-version=" + storage.ShareAPIVersion
	started := time.Now()
	_, op, created, err := r.PutFileShare(ctx, scope, tenant.Administrator, account, share, storage.ShareProperties{QuotaGiB: 1})
	if err != nil || !created || op == nil {
		t.Fatalf("approved share could not provision: %v", err)
	}
	jobs, err := r.HostShareJobs(ctx, other.HostID, other.Certificate)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("worker outside the tenant pool observed a job: %v", err)
	}
	jobs, err = r.HostShareJobs(ctx, approved.HostID, approved.Certificate)
	if err != nil || len(jobs) != 1 || jobs[0].ID != op.ID || len(jobs[0].VolumeKey) != storage.KeySize {
		t.Fatalf("approved worker was not issued the encrypted share assignment: %v", err)
	}
	clear(jobs[0].VolumeKey)
	if err := r.CompleteShareJob(ctx, approved.HostID, approved.Certificate, op.ID); err != nil {
		t.Fatal(err)
	}
	az("get", shareURL, "", "hosted-lab", "")
	if _, err := client.Delete(ctx, r.hostKey("live", approved.HostID)); err != nil {
		t.Fatal(err)
	}
	remaining := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/blocked"}
	az("put", remaining.ID(scope)+"?api-version="+storage.ShareAPIVersion, `{"properties":{"shareQuota":1}}`, "hosted-lab", "InsufficientCapacity")
	count, err := client.Get(ctx, r.shareKey(scope, remaining), clientv3.WithCountOnly())
	if err != nil || count.Count != 0 {
		t.Fatalf("denied share modified regional state: %v", err)
	}
	verifyHostedSMBFence(t, ctx, r, scope, approved.HostID, other.HostID, fencer, defaultPlacement)
	t.Logf("Stock Azure CLI accepted the hosted location and denied the offsite location. The live partner outside the tenant policy received no key or SMB writer transfer. The CLI and regional storage decisions took %d ms.", time.Since(started).Milliseconds())
}

func seedHostedPlacementWorker(t *testing.T, ctx context.Context, r *Region, name, pool string) enrollment.Host {
	t.Helper()
	lease, err := r.client.Grant(ctx, 70)
	if err != nil {
		t.Fatal(err)
	}
	host := enrollment.Host{HostID: name, Cell: r.cell, Pool: pool, Roles: []string{"compute"}, Certificate: []byte(name)}
	live := enrollment.Availability{HostID: name, Cell: r.cell, Pool: pool, Roles: host.Roles,
		Capacity: enrollment.Capacity{CPUMillis: 800, MemoryMiB: 512}, VMRuntime: true, DirectoryRuntime: true}
	body, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Txn(ctx).Then(putJSON(r.hostKey("registered", name), host),
		clientv3.OpPut(r.hostKey("live", name), string(body), clientv3.WithLease(lease.ID))).Commit(); err != nil {
		t.Fatal(err)
	}
	return host
}

func hostedPlacementCLI(t *testing.T, ctx context.Context, r *Region, cliPath, principal string, subscription identity.Subscription) func(string, string, string, string, string) []byte {
	t.Helper()
	ca, caKey, _, _ := directoryJoinClientCertificates(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(nil)
	t.Cleanup(api.Close)
	api.TLS = directoryLabServerTLS(t, ca, caKey)
	api.Config.Handler = arm.Server{Origin: "https://" + api.Listener.Addr().String(), Location: r.name,
		Roles: r, Groups: r, Inventory: r, Operations: r, Storage: r,
		Authenticate: func(_ context.Context, request *http.Request) (identity.ARMPrincipal, error) {
			if request.Header.Get("Authorization") != "Bearer hosted-lab" {
				return identity.ARMPrincipal{}, identity.ErrInvalidARMToken
			}
			return identity.ARMPrincipal{Subject: principal, Subscription: subscription}, nil
		},
	}.Handler(http.NotFoundHandler())
	api.StartTLS()
	return regionalWorkerCLI(t, ctx, api.URL, caPath, cliPath)
}

func verifyHostedSMBFence(t *testing.T, ctx context.Context, r *Region, scope arm.SubscriptionScope, primary, standby string,
	fencer ed25519.PrivateKey, widened PlacementPolicy) {
	t.Helper()
	binding := smbBinding{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, HostID: primary, StandbyHostID: standby}
	r.smb = &smbControl{bindings: map[arm.SubscriptionScope]smbBinding{scope: binding}}
	owner := smbOwner{HostID: primary, Generation: operationID()}
	ownerKey := r.smbOwnerKey(binding)
	if _, err := r.client.Txn(ctx).Then(putJSON(ownerKey, owner)).Commit(); err != nil {
		t.Fatal(err)
	}
	proof, err := json.Marshal(smb.FenceAttestation{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID,
		HostID: primary, Generation: owner.Generation, Observation: storage.PoweredOff, ObservedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	signed := storage.SignedFence{Attestation: proof, Signature: ed25519.Sign(fencer, proof)}
	if err := r.ApplySMBFence(ctx, signed); !errors.Is(err, arm.ErrStorageAccess) {
		t.Fatalf("accepted an out-of-policy SMB recovery writer: %v", err)
	}
	checkOwner := func(wanted string) {
		t.Helper()
		rows, err := r.client.Get(ctx, ownerKey)
		if err != nil {
			t.Fatal(err)
		}
		actual, _, err := readSMBOwner(binding, rows.Kvs)
		if err != nil || actual.HostID != wanted {
			t.Fatalf("unexpected SMB writer after fence: %v", err)
		}
	}
	checkOwner(primary)
	if err := r.SetPlacementPolicy(ctx, scope, widened); err != nil {
		t.Fatal(err)
	}
	if err := r.ApplySMBFence(ctx, signed); err != nil {
		t.Fatal(err)
	}
	checkOwner(standby)
}
