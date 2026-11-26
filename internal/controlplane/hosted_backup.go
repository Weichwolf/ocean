package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type hostedBackupTarget struct {
	OperatorPool     string `json:"operatorPool"`
	ArchiveDirectory string `json:"archiveDirectory"`
	Recipient        string `json:"recipient"`
	RetentionSeconds int64  `json:"retentionSeconds"`
}

type HostedBackupResult struct {
	Archive     string    `json:"archive"`
	ExpiresAt   time.Time `json:"expiresAt"`
	SourceBytes int64     `json:"sourceBytes"`
}

type HostedBackupRequest struct {
	Target         string
	Kind           string
	TenantID       string
	SubscriptionID string
	SHA256         string
	Input          io.Reader
}

func (p *hostedRegionPolicy) validateBackupTargets() error {
	if len(p.BackupTargets) == 0 && p.BackupStagingDirectory == "" {
		return nil
	}
	if len(p.BackupTargets) == 0 || !validHostedDirectory(p.BackupStagingDirectory) {
		return errors.New("hosted backup requires targets and a private source staging directory")
	}
	directories := map[string]bool{p.BackupStagingDirectory: true}
	for name, target := range p.BackupTargets {
		if !identifier.MatchString(name) || !p.allowsPool(target.OperatorPool) || !validHostedDirectory(target.ArchiveDirectory) ||
			directories[target.ArchiveDirectory] {
			return errors.New("backup targets require an approved operator pool and distinct private directories")
		}
		if retention, err := configuredAuditRetention(target.RetentionSeconds); err != nil || retention == 0 {
			return errors.New("a hosted backup target requires positive retention")
		}
		if _, err := age.ParseX25519Recipient(target.Recipient); err != nil {
			return errors.New("a hosted backup target requires an age X25519 public recipient")
		}
		directories[target.ArchiveDirectory] = true
	}
	return nil
}

func loadHostedBackup(path, targetName string) (regionConfig, hostedBackupTarget, error) {
	settings, err := config.Load(path, settings{})
	if err != nil {
		return regionConfig{}, hostedBackupTarget{}, err
	}
	if settings.Region == nil || settings.Region.HostedWorkplace == nil || settings.Region.HostedWorkplace.DeletionLedger == nil || !identifier.MatchString(settings.Region.Name) ||
		!identifier.MatchString(settings.Region.InitialCell) {
		return regionConfig{}, hostedBackupTarget{}, errors.New("backup requires a configured hosted region")
	}
	cfg := *settings.Region
	if err := cfg.HostedWorkplace.validate(); err != nil {
		return regionConfig{}, hostedBackupTarget{}, err
	}
	target, ok := cfg.HostedWorkplace.BackupTargets[targetName]
	if !ok {
		return regionConfig{}, hostedBackupTarget{}, errors.New("the backup target is outside the approved regional policy")
	}
	return cfg, target, nil
}

func (r *Region) backupPolicyKey() string { return r.root + "/backup/policy-epoch" }

// advanceBackupPolicy shares the transaction that changes eligible destinations.
func (r *Region) advanceBackupPolicy() clientv3.Op {
	return clientv3.OpPut(r.backupPolicyKey(), "active")
}

func openBackupSource(ctx context.Context, cfg regionConfig, snapshot bool) (*Region, error) {
	connection, err := cfg.Etcd.clientConfig()
	if err != nil {
		return nil, err
	}
	if snapshot {
		// The etcd snapshot stream carries no MVCC revision. Use the same
		// leader endpoint for the linearizable policy barrier and snapshot.
		discovery, err := clientv3.New(connection)
		if err != nil {
			return nil, err
		}
		var leader string
		for _, endpoint := range connection.Endpoints {
			attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
			status, err := discovery.Status(attempt, endpoint)
			cancel()
			if err == nil && status.Leader != 0 && status.Header.MemberId == status.Leader {
				leader = endpoint
				break
			}
		}
		if err := discovery.Close(); err != nil {
			return nil, err
		}
		if leader == "" {
			return nil, errors.New("no configured etcd endpoint reports itself as regional leader")
		}
		connection.Endpoints = []string{leader}
	}
	client, err := clientv3.New(connection)
	if err != nil {
		return nil, err
	}
	root := "/ocean/v1/regions/" + cfg.Name
	keys, values := initialRecords(root, cfg.Name, cfg.InitialCell, cfg.HostedWorkplace)
	ledger, err := cfg.openDeletionLedger(root)
	if err != nil {
		return nil, errors.Join(err, client.Close())
	}
	return &Region{client: client, root: root, name: cfg.Name, keys: keys, values: values, hosted: cfg.HostedWorkplace, deletionLedger: ledger}, nil
}

type hostedBackupEpoch struct {
	placement   int64
	offboarding int64
}

func (r *Region) backupPolicyBarrier(ctx context.Context, dedicated bool) (int64, hostedBackupEpoch, error) {
	var epoch hostedBackupEpoch
	reads := []clientv3.Op{clientv3.OpGet(r.keys[0]), clientv3.OpGet(r.keys[1]), clientv3.OpGet(r.backupPolicyKey())}
	if dedicated {
		prefix := r.root + "/"
		reads = append(reads, clientv3.OpGet("\x00", clientv3.WithRange(prefix), clientv3.WithCountOnly()),
			clientv3.OpGet(clientv3.GetPrefixRangeEnd(prefix), clientv3.WithFromKey(), clientv3.WithCountOnly()))
	}
	result, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return 0, epoch, err
	}
	for i, expected := range r.values {
		rows := result.Responses[i].GetResponseRange().Kvs
		if len(rows) != 1 || string(rows[0].Value) != expected {
			return 0, epoch, errors.New("backup configuration differs from the persisted hosted region")
		}
	}
	if dedicated && (result.Responses[3].GetResponseRange().Count != 0 || result.Responses[4].GetResponseRange().Count != 0) {
		return 0, epoch, errors.New("regional snapshots require a dedicated etcd cluster")
	}
	if row := result.Responses[2].GetResponseRange().Kvs; len(row) != 0 {
		epoch.placement = row[0].ModRevision
	}
	epoch.offboarding, err = r.deletionLedger.revision(ctx, result.Header.ClusterId)
	return result.Header.Revision, epoch, err
}

func (r *Region) backupTenantAllowed(ctx context.Context, scope arm.SubscriptionScope, pool string, revision int64) error {
	_, key := r.tenantKeys(scope.TenantID)
	rows, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return err
	}
	var subscription identity.Subscription
	if len(rows.Kvs) != 1 || json.Unmarshal(rows.Kvs[0].Value, &subscription) != nil || !subscription.Valid(scope.TenantID) ||
		subscription.SubscriptionID != scope.SubscriptionID {
		return errors.New("backup requires the active tenant subscription")
	}
	if _, err := r.hostedPoolGuard(ctx, scope, pool, revision); err != nil {
		return errors.Join(errors.New("the tenant policy does not authorize this backup target"), err)
	}
	return nil
}

func (r *Region) authorizeBackup(ctx context.Context, scope arm.SubscriptionScope, pool string, revision int64, snapshot bool) error {
	stored, err := r.client.Get(ctx, r.root+"/workloads/config", clientv3.WithRev(revision))
	if err != nil {
		return err
	}
	var manifest struct{ DefaultPlacement PlacementPolicy }
	if len(stored.Kvs) != 1 || json.Unmarshal(stored.Kvs[0].Value, &manifest) != nil ||
		!r.hosted.allowsPlacement(manifest.DefaultPlacement.Pools) || !validCapacity(manifest.DefaultPlacement.Quota) {
		return errors.New("the hosted workload placement manifest is unavailable")
	}
	r.workloads = &workloadControl{defaultPlacement: manifest.DefaultPlacement}
	if !snapshot {
		return r.backupTenantAllowed(ctx, scope, pool, revision)
	}
	if !slices.Contains(manifest.DefaultPlacement.Pools, pool) {
		return errors.New("the default tenant policy does not authorize this regional snapshot target")
	}
	prefix := r.root + "/tenants/"
	for cursor := prefix; ; {
		page, err := r.client.Get(ctx, cursor, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)), clientv3.WithKeysOnly(),
			clientv3.WithLimit(128), clientv3.WithRev(revision))
		if err != nil {
			return err
		}
		for _, row := range page.Kvs {
			tenant, leaf, _ := strings.Cut(strings.TrimPrefix(string(row.Key), prefix), "/")
			if leaf != "subscription" {
				continue
			}
			entry, err := r.client.Get(ctx, string(row.Key), clientv3.WithRev(revision))
			if err != nil {
				return err
			}
			var sub identity.Subscription
			if len(entry.Kvs) != 1 || json.Unmarshal(entry.Kvs[0].Value, &sub) != nil || !sub.Valid(tenant) {
				return errors.New("invalid subscription in regional backup scope")
			}
			if _, err := r.hostedPlacementAt(ctx, arm.SubscriptionScope{TenantID: tenant, SubscriptionID: sub.SubscriptionID}, pool, revision); err != nil {
				return errors.Join(errors.New("a tenant policy does not authorize this regional snapshot target"), err)
			}
		}
		if !page.More {
			return nil
		}
		cursor = string(page.Kvs[len(page.Kvs)-1].Key) + "\x00"
	}
}

// SaveHostedBackup writes a native regional snapshot or a scoped tenant archive.
// Source staging holds only ciphertext. Publication begins after the policy
// barrier confirms the approved pool is still valid for the captured data.
func SaveHostedBackup(ctx context.Context, configuration string, request HostedBackupRequest) (HostedBackupResult, error) {
	scope := arm.SubscriptionScope{TenantID: request.TenantID, SubscriptionID: request.SubscriptionID}
	snapshot := request.Kind == "etcd"
	wantDigest, err := hex.DecodeString(request.SHA256)
	if snapshot && (scope != (arm.SubscriptionScope{}) || request.SHA256 != "") || !snapshot &&
		(!slices.Contains([]string{"directory", "volume", "export"}, request.Kind) || !validScope(scope) || request.Input == nil ||
			err != nil || len(wantDigest) != sha256.Size) {
		return HostedBackupResult{}, errors.New("use an etcd snapshot or a tenant-scoped directory, volume or export archive with its SHA-256 checksum")
	}
	cfg, target, err := loadHostedBackup(configuration, request.Target)
	if err != nil {
		return HostedBackupResult{}, err
	}
	r, err := openBackupSource(ctx, cfg, snapshot)
	if err != nil {
		return HostedBackupResult{}, err
	}
	defer func() { _ = r.close() }()
	revision, epoch, err := r.backupPolicyBarrier(ctx, snapshot)
	if err != nil {
		return HostedBackupResult{}, err
	}
	if err := r.authorizeBackup(ctx, scope, target.OperatorPool, revision, snapshot); err != nil {
		return HostedBackupResult{}, err
	}
	return writeHostedBackup(ctx, r, cfg, target, request, epoch, wantDigest)
}

func writeHostedBackup(ctx context.Context, r *Region, cfg regionConfig, target hostedBackupTarget, request HostedBackupRequest, epoch hostedBackupEpoch, wantDigest []byte) (HostedBackupResult, error) {
	snapshot := request.Kind == "etcd"
	staging, err := openPrivateHostedDirectory(cfg.HostedWorkplace.BackupStagingDirectory, "backup staging")
	if err != nil {
		return HostedBackupResult{}, err
	}
	defer func() { _ = staging.Close() }()
	recipient, err := age.ParseX25519Recipient(target.Recipient)
	if err != nil {
		return HostedBackupResult{}, err
	}
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Duration(target.RetentionSeconds) * time.Second)
	scopeName := request.TenantID
	if snapshot {
		scopeName = "regional"
	}
	archive := fmt.Sprintf("%s.%s.%s.%s.%d.%s.age", cfg.Name, request.Target, request.Kind, scopeName, expiry.Unix(), operationID())
	partial := archive + ".partial"
	file, err := staging.OpenFile(partial, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return HostedBackupResult{}, err
	}
	defer func() { _ = staging.Remove(partial) }()
	defer func() { _ = file.Close() }()
	input := request.Input
	if snapshot {
		body, err := r.client.Snapshot(ctx)
		if err != nil {
			return HostedBackupResult{}, err
		}
		defer func() { _ = body.Close() }()
		input = body
	}
	encryption, err := age.Encrypt(file, recipient)
	if err != nil {
		return HostedBackupResult{}, err
	}
	n, copyErr := copyVerifiedArchive(encryption, input, snapshot, wantDigest)
	if err := errors.Join(copyErr, encryption.Close()); err != nil {
		return HostedBackupResult{}, err
	}
	recheck := func() error {
		_, after, err := r.backupPolicyBarrier(ctx, snapshot)
		if err == nil && after != epoch {
			return errors.New("the hosted placement policy changed during backup; retry the capture")
		}
		return err
	}
	if err := recheck(); err != nil {
		return HostedBackupResult{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return HostedBackupResult{}, err
	}
	root, err := openPrivateHostedDirectory(target.ArchiveDirectory, "backup target")
	if err != nil {
		return HostedBackupResult{}, err
	}
	defer func() { _ = root.Close() }()
	if err := publishHostedArchive(ctx, root, archive, file, expiry, recheck); err != nil {
		return HostedBackupResult{}, err
	}
	return HostedBackupResult{Archive: archive, ExpiresAt: expiry, SourceBytes: n}, nil
}

func copyVerifiedArchive(dst io.Writer, src io.Reader, snapshot bool, want []byte) (int64, error) {
	digest := sha256.New()
	var verify io.Writer = digest
	var trailing snapshotChecksum
	if snapshot {
		trailing.digest = digest
		verify = &trailing
	}
	n, err := io.Copy(io.MultiWriter(dst, verify), src)
	if err != nil {
		return n, err
	}
	if snapshot {
		if n < 512 || n%512 != sha256.Size {
			return n, errors.New("the etcd snapshot is incomplete")
		}
		want = trailing.tail
	}
	if n == 0 || !bytes.Equal(digest.Sum(nil), want) {
		return n, errors.New("the backup input failed its SHA-256 checksum")
	}
	return n, nil
}

// etcd appends a SHA-256 checksum to the database image. Hold the last
// checksum-sized block out of the hash while streaming the database.
type snapshotChecksum struct {
	digest hash.Hash
	tail   []byte
}

func (c *snapshotChecksum) Write(input []byte) (int, error) {
	n := len(input)
	spill := len(c.tail) + n - sha256.Size
	if spill > 0 {
		old := min(spill, len(c.tail))
		_, _ = c.digest.Write(c.tail[:old])
		c.tail = c.tail[old:]
		spill -= old
		_, _ = c.digest.Write(input[:spill])
		input = input[spill:]
	}
	c.tail = append(c.tail, input...)
	return n, nil
}

func publishHostedArchive(ctx context.Context, root *os.Root, name string, source io.Reader, expiry time.Time, recheck func() error) error {
	partial := name + ".partial"
	file, err := root.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(partial) }()
	_, copyErr := io.Copy(file, source)
	if err := errors.Join(copyErr, file.Sync(), file.Close(), ctx.Err()); err != nil {
		return err
	}
	if err := recheck(); err != nil {
		return err
	}
	if !time.Now().Before(expiry) {
		return errors.New("the backup expired before publication")
	}
	if err := root.Link(partial, name); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

var archiveID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// PruneHostedBackups expires artifacts in the configured directories even
// while the source cluster is offline. The operator supplies the pinned policy.
func PruneHostedBackups(configuration, targetName string) (int, error) {
	cfg, target, err := loadHostedBackup(configuration, targetName)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	prefix := cfg.Name + "." + targetName + "."
	archives, archiveErr := pruneHostedDirectory(target.ArchiveDirectory, prefix, now)
	staged, stageErr := pruneHostedDirectory(cfg.HostedWorkplace.BackupStagingDirectory, prefix, now)
	return archives + staged, errors.Join(archiveErr, stageErr)
}

func pruneHostedDirectory(path, prefix string, now int64) (int, error) {
	root, err := openPrivateHostedDirectory(path, "backup")
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	directory, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	defer func() { _ = directory.Close() }()
	count := 0
	for {
		rows, err := directory.ReadDir(128)
		if err == io.EOF {
			return count, directory.Sync()
		}
		if err != nil {
			return count, err
		}
		for _, row := range rows {
			if !row.Type().IsRegular() || !expiredHostedArchive(prefix, row.Name(), now) {
				continue
			}
			if err := root.Remove(row.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return count, err
			} else if err == nil {
				count++
			}
		}
	}
}

func expiredHostedArchive(prefix, name string, now int64) bool {
	suffix, ok := strings.CutPrefix(strings.TrimSuffix(name, ".partial"), prefix)
	if !ok {
		return false
	}
	parts := strings.Split(suffix, ".")
	if len(parts) != 5 || parts[4] != "age" || !archiveID.MatchString(parts[3]) {
		return false
	}
	if parts[0] == "etcd" && parts[1] != "regional" || parts[0] != "etcd" &&
		(!slices.Contains([]string{"directory", "volume", "export"}, parts[0]) || !archiveID.MatchString(parts[1])) {
		return false
	}
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	return err == nil && expiry > 0 && expiry <= now
}
