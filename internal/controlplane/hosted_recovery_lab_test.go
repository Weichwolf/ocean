//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

func TestHostedRecoveryTarget(t *testing.T) {
	archive := os.Getenv("OCEAN_E2E_HOSTED_ETCD_ARCHIVE")
	cli := os.Getenv("OCEAN_E2E_HOSTED_AZ")
	if archive == "" || cli == "" {
		t.Skip("requires the pinned etcd archive and stock Azure CLI for isolated backup and recovery")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Second)
	defer cancel()
	started := time.Now()
	dir, keys, otherKeys := t.TempDir(), t.TempDir(), t.TempDir()
	base, cert, certKey, etcd, _ := prepareSMBRecoveryEtcd(t, ctx, archive, dir)
	source, sourceID, stopSource := startSMBRecoveryEtcd(t, ctx, base, cert, certKey, etcd, filepath.Join(dir, "source"), nil)
	ledger, ledgerID, stopLedger := startSMBRecoveryEtcd(t, ctx, base, cert, certKey, etcd, filepath.Join(dir, "ledger"), nil)
	approvedOrigin := "https://" + disposableEtcdAddress(t)
	wrapping := filepath.Join(dir, "regional.key")
	wrappingKey := make([]byte, storage.KeySize)
	rand.Read(wrappingKey)
	if err := os.WriteFile(wrapping, wrappingKey, 0600); err != nil {
		t.Fatal(err)
	}
	clear(wrappingKey)
	quota := enrollment.Capacity{CPUMillis: 800, MemoryMiB: 512}
	cfg := regionConfig{Name: "hosted-recovery", InitialCell: "cell-1", Etcd: source,
		AuditRetention:     3600,
		DeletionLedgerEtcd: &ledger,
		HostedWorkplace: &hostedRegionPolicy{Country: "DE", OperatorPools: map[string]string{"primary": "DE", "partner": "NL"},
			DeletionLedger: &hostedLedgerPolicy{OperatorPool: "primary", ClusterID: fmt.Sprintf("%x", ledgerID), Endpoints: ledger.Endpoints},
			RecoveryTargets: map[string]hostedRecoveryTarget{
				"recovery-a": {OperatorPool: "primary", KeyDirectory: keys, MetadataOrigins: []string{approvedOrigin}},
				"recovery-b": {OperatorPool: "partner", KeyDirectory: otherKeys, MetadataOrigins: []string{approvedOrigin}},
			}},
		Workloads: &workloadConfig{SecretsKeyFile: wrapping, DefaultPlacement: PlacementPolicy{Pools: []string{"primary", "partner"}, Quota: quota}},
		Storage:   &storageConfig{KeyFile: wrapping, Workers: []string{"worker-a", "worker-b"}},
	}
	backupIdentity := configureHostedBackupLab(t, cfg.HostedWorkplace)
	region, err := openRegion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = region.close() }()
	if err := region.bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	tenant := seedHostedRestoreTenant(t, ctx, region)
	neighbor := seedHostedRestoreTenant(t, ctx, region)
	scope := arm.SubscriptionScope{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID}
	if err := region.SetPlacementPolicy(ctx, scope, PlacementPolicy{Pools: []string{"primary"}, Quota: quota}); err != nil {
		t.Fatal(err)
	}
	seedHostedRestoreAssignments(t, ctx, region, tenant, neighbor, quota)
	seedHostedExportFixture(t, ctx, region, tenant, neighbor)
	account := arm.ResourceAddress{Group: "retained-fixture", Path: storage.AccountType + "/fixture"}
	share := arm.ResourceAddress{Group: account.Group, Path: account.Path + "/fileServices/default/shares/fixture"}
	volume := storage.Volume{ID: "vol-" + operationID(), SizeMiB: 1024}
	key := make([]byte, storage.KeySize)
	rand.Read(key)
	defer clear(key)
	shareKey := region.shareKey(scope, share)
	envelope := region.storage.sealer.Seal(nil, nil, key, []byte(shareKey+"/"+volume.ID))
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: createFileShare, Group: share.Group, Actor: tenant.Administrator, Status: arm.OperationSucceeded,
		StartedAt: now, FinishedAt: &now}
	record := storageShareRecord{Address: share, Account: account, Scope: scope, Volume: volume, Envelope: envelope, Host: hostedSuspensionHost, Operation: op.ID}
	if err := region.PutInventoryResource(ctx, scope, arm.InventoryResource{Address: share, APIVersion: storage.ShareAPIVersion, Location: region.name}); err != nil {
		t.Fatal(err)
	}
	writer := seedHostedContainer(t, ctx, region, scope, tenant.Administrator, workload.ContainerGroupType, 0)
	writer.Volume = &volumeBinding{ID: volume.ID, Share: share}
	if _, err := region.client.Txn(ctx).Then(putJSON(shareKey, record), putJSON(region.operationKey(scope, op.ID), op),
		putJSON(region.containerKey(scope, writer.Address), writer), putJSON(region.writerKey(scope, volume.ID), writerFor(writer))).Commit(); err != nil {
		t.Fatal(err)
	}
	snapshot := verifyHostedBackup(t, ctx, cfg, region, scope, quota, backupIdentity, dir)
	restoredPath := filepath.Join(dir, "recovery")
	restored, restoredID, _ := startSMBRecoveryEtcd(t, ctx, base, cert, certKey, etcd, restoredPath,
		func(peer, cluster, token string) {
			etcdLabCommand(t, ctx, nil, filepath.Join(dir, "etcdutl"), "snapshot", "restore", snapshot, "--name=smb-recovery",
				"--initial-cluster="+cluster, "--initial-advertise-peer-urls="+peer, "--initial-cluster-token="+token, "--data-dir="+restoredPath)
		}, approvedOrigin)
	if restoredID == sourceID || restoredID == ledgerID || sourceID == ledgerID {
		t.Fatal("the key recovery test requires an independent restored cluster")
	}
	cfg.Etcd = restored
	configuration := filepath.Join(dir, "restore.json")
	binary := filepath.Join("..", "..", "bin", "ocean-recover")
	run := func(cfg regionConfig, target, path, want string) {
		t.Helper()
		input, err := json.Marshal(settings{Region: &cfg})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configuration, input, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, binary, "-config", configuration, "-tenant", scope.TenantID, "-subscription", scope.SubscriptionID,
			"-share", share.ID(scope), "-target", target, "-output", path)
		output, err := cmd.CombinedOutput()
		if want == "" {
			if err != nil {
				t.Fatalf("approved recovery failed: %v %s", err, output)
			}
			return
		}
		if err == nil || !strings.Contains(string(output), want) {
			t.Fatalf("expected recovery refusal %q: %v %s", want, err, output)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("denied recovery left output: %v", err)
		}
	}
	keyPath := filepath.Join(keys, "recovered.key")
	run(cfg, "outside", keyPath, "do not match an approved recovery target")
	run(cfg, "recovery-a", filepath.Join(dir, "outside.key"), "outside the approved target directory")
	run(cfg, "recovery-b", filepath.Join(otherKeys, "denied.key"), "tenant policy does not authorize")
	mismatched := cfg
	mismatched.Etcd.Endpoints = source.Endpoints
	run(mismatched, "recovery-a", keyPath, "do not match an approved recovery target")
	downgraded := cfg
	downgraded.HostedWorkplace, downgraded.DeletionLedgerEtcd = nil, nil
	run(downgraded, "", keyPath, "requires its original policy")
	if err := os.Chmod(keys, 0750); err != nil {
		t.Fatal(err)
	}
	run(cfg, "recovery-a", keyPath, "recovery directory must be private")
	if err := os.Chmod(keys, 0700); err != nil {
		t.Fatal(err)
	}
	run(cfg, "recovery-a", keyPath, "")
	actual, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(actual, key) {
		t.Fatal("the approved recovery did not export the original sealed key")
	}
	clear(actual)
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("the recovery key file is not owner-only")
	}
	t.Logf("Pinned etcd restored an independent cluster. ocean-recover rejected four target or policy mismatches, an outside path, and a shared directory before recovering the sealed key. Verification took %d ms.", time.Since(started).Milliseconds())
	verifyHostedSuspension(t, ctx, cfg, region, tenant, neighbor, cli, stopLedger, record, writer, func() {
		run(cfg, "recovery-a", filepath.Join(keys, "after-suspension.key"), "hosted tenant subscription is unavailable")
	})
	stopSource()
}
