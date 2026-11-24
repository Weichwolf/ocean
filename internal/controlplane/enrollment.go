package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) hostKey(kind, id string) string { return r.root + "/hosts/" + kind + "/" + id }

func (r *Region) seedHostInventory(ctx context.Context, inventory []enrollment.Approval) error {
	for _, approved := range inventory {
		key := r.hostKey("inventory", approved.HostID)
		mac := r.hostKey("mac", approved.MAC)
		address := r.hostKey("address", approved.Address)
		credential := r.hostKey("credential", strings.ToLower(approved.TokenSHA256))
		cell := r.root + "/cells/" + approved.Cell + "/metadata"
		data, _ := json.Marshal(approved)
		txn := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0), clientv3.Compare(clientv3.Version(mac), "=", 0),
			clientv3.Compare(clientv3.Version(address), "=", 0), clientv3.Compare(clientv3.Version(credential), "=", 0),
			clientv3.Compare(clientv3.Version(cell), ">", 0)).Then(clientv3.OpPut(key, string(data)), clientv3.OpPut(mac, approved.HostID),
			clientv3.OpPut(address, approved.HostID), clientv3.OpPut(credential, approved.HostID)).
			Else(clientv3.OpGet(key), clientv3.OpGet(mac), clientv3.OpGet(address), clientv3.OpGet(credential), clientv3.OpGet(cell))
		result, err := txn.Commit()
		if err != nil {
			return err
		}
		if result.Succeeded {
			continue
		}
		for index, want := range []string{string(data), approved.HostID, approved.HostID, approved.HostID} {
			items := result.Responses[index].GetResponseRange().Kvs
			if len(items) != 1 || string(items[0].Value) != want {
				return errors.New("host inventory conflicts with the regional record")
			}
		}
		if len(result.Responses[4].GetResponseRange().Kvs) != 1 {
			return errors.New("host inventory references an unknown cell")
		}
	}
	return nil
}

func (r *Region) Enrollment(ctx context.Context, id string) (*enrollment.Approval, *enrollment.Host, int64, error) {
	result, err := r.client.Txn(ctx).Then(clientv3.OpGet(r.hostKey("inventory", id)), clientv3.OpGet(r.hostKey("registered", id))).Commit()
	if err != nil {
		return nil, nil, 0, err
	}
	inventory := result.Responses[0].GetResponseRange().Kvs
	if len(inventory) == 0 {
		return nil, nil, 0, nil
	}
	var approved enrollment.Approval
	if err := json.Unmarshal(inventory[0].Value, &approved); err != nil || !approved.Valid() || approved.HostID != id {
		return nil, nil, 0, errors.New("invalid regional host approval")
	}
	registered := result.Responses[1].GetResponseRange().Kvs
	if len(registered) == 0 {
		return &approved, nil, inventory[0].ModRevision, nil
	}
	var host enrollment.Host
	if err := json.Unmarshal(registered[0].Value, &host); err != nil || host.HostID != id || len(host.Certificate) == 0 {
		return nil, nil, 0, errors.New("invalid regional host identity")
	}
	return &approved, &host, inventory[0].ModRevision, nil
}

func (r *Region) RedeemEnrollment(ctx context.Context, host enrollment.Host, revision int64) (bool, error) {
	identity := r.hostKey("registered", host.HostID)
	redeemed := r.hostKey("redeemed", host.HostID)
	data, _ := json.Marshal(host)
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(r.hostKey("inventory", host.HostID)), "=", revision),
		clientv3.Compare(clientv3.Version(identity), "=", 0), clientv3.Compare(clientv3.Version(redeemed), "=", 0)).
		Then(clientv3.OpPut(identity, string(data)), clientv3.OpPut(redeemed, host.KeySHA256)).Commit()
	return err == nil && result.Succeeded, err
}

// RevokeHost denies an issued identity without freeing its enrollment credential.
func (r *Region) RevokeHost(ctx context.Context, id string) error {
	key := r.hostKey("registered", id)
	for range 8 {
		current, err := r.client.Get(ctx, key)
		if err != nil {
			return err
		}
		if len(current.Kvs) == 0 {
			return errors.New("host identity was not found")
		}
		item := current.Kvs[0]
		var host enrollment.Host
		if err := json.Unmarshal(item.Value, &host); err != nil || host.HostID != id {
			return errors.New("invalid regional host identity")
		}
		if host.RevokedAt != nil {
			return nil
		}
		now := time.Now().UTC()
		host.RevokedAt = &now
		data, _ := json.Marshal(host)
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", item.ModRevision)).
			Then(clientv3.OpPut(key, string(data)), clientv3.OpDelete(r.hostKey("live", id))).Commit()
		if err != nil || result.Succeeded {
			return err
		}
	}
	return errors.New("host identity changed concurrently")
}
