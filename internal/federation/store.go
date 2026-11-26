package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const pathLease = 15

type Pair struct {
	ID          string         `json:"id"`
	RemoteFarm  string         `json:"remoteFarm"`
	Routes      []netip.Prefix `json:"routes"`
	Established time.Time      `json:"establishedAt"`
}

func pairingID(a, b string) string {
	if b < a {
		a, b = b, a
	}
	digest := sha256.Sum256([]byte("ocean/farm-pair/v1\x00" + a + "\x00" + b))
	return hex.EncodeToString(digest[:16])
}

func (s *Service) Bootstrap(ctx context.Context) error {
	key := s.root + "/policy"
	result, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0),
		clientv3.Compare(clientv3.Version(s.region+"/metadata"), ">", 0)).
		Then(clientv3.OpPut(key, s.policy)).
		Else(clientv3.OpGet(key), clientv3.OpGet(s.region+"/metadata", clientv3.WithCountOnly())).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	stored := result.Responses[0].GetResponseRange().Kvs
	if len(stored) != 1 || string(stored[0].Value) != s.policy || result.Responses[1].GetResponseRange().Count != 1 {
		return errors.New("local farm metadata or federation policy differs from the configured farm")
	}
	return nil
}

func (s *Service) Ready(ctx context.Context) error {
	result, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.Value(s.root+"/policy"), "=", s.policy),
		clientv3.Compare(clientv3.Version(s.region+"/metadata"), ">", 0)).Commit()
	if err != nil {
		return err
	}
	if !result.Succeeded {
		return errors.New("local federation policy is unavailable")
	}
	return nil
}

func (s *Service) remember(ctx context.Context, farm string) (int64, error) {
	routes := s.cfg.Policy.Peers[farm].Imports
	pair := Pair{ID: pairingID(s.cfg.Policy.Farm, farm), RemoteFarm: farm, Routes: routes, Established: time.Now().UTC()}
	key := s.root + "/pairs/" + farm
	data, _ := json.Marshal(pair)
	result, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0),
		clientv3.Compare(clientv3.Value(s.root+"/policy"), "=", s.policy)).
		Then(clientv3.OpPut(key, string(data))).
		Else(clientv3.OpGet(key), clientv3.OpGet(s.root+"/policy")).Commit()
	if err != nil {
		return 0, err
	}
	if result.Succeeded {
		return result.Header.Revision, nil
	}
	stored := result.Responses[0].GetResponseRange().Kvs
	policy := result.Responses[1].GetResponseRange().Kvs
	var value Pair
	if len(policy) != 1 || string(policy[0].Value) != s.policy ||
		len(stored) != 1 || json.Unmarshal(stored[0].Value, &value) != nil || value.ID != pair.ID ||
		value.RemoteFarm != farm || !slices.Equal(value.Routes, routes) || value.Established.IsZero() {
		return 0, errors.New("durable farm pairing conflicts with the approved route exchange")
	}
	return stored[0].ModRevision, nil
}

func (s *Service) markPathLive(ctx context.Context, farm string, pairRevision int64) error {
	pair := s.root + "/pairs/" + farm
	path := s.root + "/paths/" + farm + "/" + s.cfg.Path
	current, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(pair), "=", pairRevision),
		clientv3.Compare(clientv3.Value(s.root+"/policy"), "=", s.policy)).Then(clientv3.OpGet(path)).Commit()
	if err != nil {
		return err
	}
	if !current.Succeeded {
		return errors.New("federation pairing changed while checking a path")
	}
	var revision int64
	if paths := current.Responses[0].GetResponseRange().Kvs; len(paths) == 1 {
		revision = paths[0].ModRevision
		lease := clientv3.LeaseID(paths[0].Lease)
		if lease != 0 {
			if result, err := s.client.KeepAliveOnce(ctx, lease); err == nil && result.TTL > 0 {
				return nil
			}
		}
	}
	next, err := s.client.Grant(ctx, pathLease)
	if err != nil {
		return err
	}
	result, err := s.client.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(path), "=", revision),
		clientv3.Compare(clientv3.ModRevision(pair), "=", pairRevision),
		clientv3.Compare(clientv3.Value(s.root+"/policy"), "=", s.policy)).
		Then(clientv3.OpPut(path, s.cfg.Policy.Peers[farm].Paths[s.cfg.Path].String(), clientv3.WithLease(next.ID))).Commit()
	if err == nil && !result.Succeeded {
		// Another replica may already have reported this path.
		_, _ = s.client.Revoke(ctx, next.ID)
	}
	return err
}
