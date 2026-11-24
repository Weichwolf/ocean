package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type workloadConfig struct {
	SecretsKeyFile   string          `json:"secretsKeyFile"`
	DefaultPlacement PlacementPolicy `json:"defaultPlacement"`
}

type workloadControl struct {
	sealer           cipher.AEAD
	manifest         string
	defaultPlacement PlacementPolicy
}

func openWorkloadControl(config *workloadConfig) (*workloadControl, error) {
	if config == nil {
		return nil, nil
	}
	policy := config.DefaultPlacement
	if !filepath.IsAbs(config.SecretsKeyFile) || !validCapacity(policy.Quota) || len(policy.Pools) == 0 || len(policy.Pools) > 16 {
		return nil, errors.New("workloads require a secrets key and an explicit default placement policy")
	}
	policy.Pools = slices.Clone(policy.Pools)
	slices.Sort(policy.Pools)
	for index, pool := range policy.Pools {
		if !identifier.MatchString(pool) || index > 0 && policy.Pools[index-1] == pool {
			return nil, errors.New("workload placement pools must be distinct identifiers")
		}
	}
	key, err := readSealingKey(config.SecretsKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	sealer, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(struct {
		KeyDigest string          `json:"keyDigest"`
		Placement PlacementPolicy `json:"defaultPlacement"`
	}{fmt.Sprintf("%x", sha256.Sum256(key)), policy})
	if err != nil {
		return nil, err
	}
	return &workloadControl{sealer: sealer, manifest: string(manifest), defaultPlacement: policy}, nil
}

func (r *Region) bootstrapWorkloads(ctx context.Context) error {
	key := r.root + "/workloads/config"
	if r.workloads == nil {
		configured, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && configured.Count != 0 {
			return errors.New("workload configuration is required for this region")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.workloads.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.workloads.manifest {
		return errors.New("workload configuration differs from the regional record")
	}
	return nil
}
