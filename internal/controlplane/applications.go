package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) appPrefix(tenant string) string {
	return r.root + "/tenants/" + tenant + "/directory/"
}

func (r *Region) FindApplication(ctx context.Context, tenant, field, value string) (*identity.Application, int64, error) {
	prefix := r.appPrefix(tenant)
	id := value
	switch field {
	case "appId", "principalId":
		index, err := r.client.Get(ctx, prefix+field+"/"+value)
		if err != nil || len(index.Kvs) == 0 {
			return nil, 0, err
		}
		id = string(index.Kvs[0].Value)
	case "id":
	default:
		return nil, 0, errors.New("invalid directory lookup index")
	}
	result, err := r.client.Get(ctx, prefix+"apps/"+id)
	if err != nil || len(result.Kvs) == 0 {
		return nil, 0, err
	}
	var app identity.Application
	entry := result.Kvs[0]
	if err := json.Unmarshal(entry.Value, &app); err != nil {
		return nil, 0, err
	}
	if !app.Valid(tenant) || app.ID != id ||
		(field == "appId" && app.ClientID != value) || (field == "principalId" && app.PrincipalID != value) {
		return nil, 0, errors.New("invalid directory application")
	}
	return &app, entry.ModRevision, nil
}

func (r *Region) ListApplications(ctx context.Context, tenant, after string, limit int) ([]identity.Application, error) {
	prefix := r.appPrefix(tenant) + "apps/"
	start := prefix
	if after != "" {
		start += after + "\x00"
	}
	result, err := r.client.Get(ctx, start, clientv3.WithRange(clientv3.GetPrefixRangeEnd(prefix)),
		clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend), clientv3.WithLimit(int64(limit)))
	if err != nil {
		return nil, err
	}
	apps := make([]identity.Application, 0, len(result.Kvs))
	for _, entry := range result.Kvs {
		var app identity.Application
		if err := json.Unmarshal(entry.Value, &app); err != nil {
			return nil, err
		}
		if !app.Valid(tenant) || app.ID != strings.TrimPrefix(string(entry.Key), prefix) {
			return nil, errors.New("invalid directory application")
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func (r *Region) SaveApplication(ctx context.Context, app identity.Application, revision int64) (bool, error) {
	prefix := r.appPrefix(app.TenantID)
	key := prefix + "apps/" + app.ID
	data, err := json.Marshal(app)
	if err != nil {
		return false, err
	}
	conditions := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(key), "=", revision)}
	writes := []clientv3.Op{clientv3.OpPut(key, string(data))}
	if revision == 0 {
		index := prefix + "appId/" + app.ClientID
		conditions = append(conditions, clientv3.Compare(clientv3.Version(index), "=", 0))
		writes = append(writes, clientv3.OpPut(index, app.ID))
	}
	if app.PrincipalID != "" {
		index := prefix + "principalId/" + app.PrincipalID
		// Rewriting an established index is safe only for the same app.
		result, err := r.client.Get(ctx, index)
		if err != nil {
			return false, err
		}
		if len(result.Kvs) == 0 {
			conditions = append(conditions, clientv3.Compare(clientv3.Version(index), "=", 0))
			writes = append(writes, clientv3.OpPut(index, app.ID))
		} else {
			conditions = append(conditions, clientv3.Compare(clientv3.Value(index), "=", app.ID))
		}
	}
	result, err := r.client.Txn(ctx).If(conditions...).Then(writes...).Commit()
	return err == nil && result.Succeeded, err
}
