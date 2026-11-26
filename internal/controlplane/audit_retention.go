package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func configuredAuditRetention(seconds int64) (time.Duration, error) {
	if seconds < 0 || seconds > math.MaxInt64/int64(time.Second) {
		return 0, errors.New("invalid regional audit retention duration")
	}
	return time.Duration(seconds) * time.Second, nil
}

func (r *Region) bootstrapAuditRetention(ctx context.Context) error {
	key := r.root + "/activity/retention"
	expected := strconv.FormatInt(int64(r.auditRetention/time.Second), 10)
	if r.auditRetention != 0 {
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
			Then(clientv3.OpPut(key, expected)).Else(clientv3.OpGet(key)).Commit()
		if err != nil || result.Succeeded {
			return err
		}
		rows := result.Responses[0].GetResponseRange().Kvs
		if len(rows) == 1 && string(rows[0].Value) == expected {
			return nil
		}
	} else {
		result, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err != nil || result.Count == 0 {
			return err
		}
	}
	return errors.New("audit retention differs from the regional policy")
}

func (r *Region) reconcileAuditRetention(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var cursor string
	for ctx.Err() == nil {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		next, err := r.pruneAuditPage(call, cursor, time.Now().Add(-r.auditRetention))
		cancel()
		if err == nil {
			cursor = next
		} else if ctx.Err() == nil {
			logger.Warn("Audit retention sweep will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

// pruneAuditPage scans keys without loading other tenant data into the sweep.
// Compare record revisions before deleting so a retry or concurrent sweep
// cannot delete a replacement record.
func (r *Region) pruneAuditPage(ctx context.Context, cursor string, expiration time.Time) (string, error) {
	prefix := r.root + "/tenants/"
	if cursor == "" {
		cursor = prefix
	}
	page, err := r.client.Get(ctx, cursor, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)),
		clientv3.WithKeysOnly(), clientv3.WithLimit(64))
	if err != nil {
		return cursor, err
	}
	var next string
	if page.More {
		next = string(page.Kvs[len(page.Kvs)-1].Key) + "\x00"
	}
	var reads []clientv3.Op
	for _, item := range page.Kvs {
		key := string(item.Key)
		parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
		if len(parts) == 5 && parts[1] == "arm" && parts[3] == "audit" && parts[4] != "" &&
			validScope(arm.SubscriptionScope{TenantID: parts[0], SubscriptionID: parts[2]}) {
			reads = append(reads, clientv3.OpGet(key, clientv3.WithRev(page.Header.Revision)))
		}
	}
	if len(reads) == 0 {
		return next, nil
	}
	snapshot, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return cursor, err
	}
	var compare []clientv3.Cmp
	var deletes []clientv3.Op
	for _, response := range snapshot.Responses {
		for _, item := range response.GetResponseRange().Kvs {
			var event arm.AuditEvent
			if json.Unmarshal(item.Value, &event) == nil && !event.Time.IsZero() && !event.Time.After(expiration) {
				key := string(item.Key)
				compare = append(compare, clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision))
				deletes = append(deletes, clientv3.OpDelete(key))
			}
		}
	}
	if len(deletes) != 0 {
		result, err := r.client.Txn(ctx).If(compare...).Then(deletes...).Commit()
		if err != nil || !result.Succeeded {
			return cursor, err
		}
	}
	return next, nil
}
