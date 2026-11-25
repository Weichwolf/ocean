package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type storageConfig struct {
	KeyFile            string   `json:"keyFile"`
	Workers            []string `json:"workers"`
	FencePublicKeyFile string   `json:"fencePublicKeyFile"`
}

type storageControl struct {
	sealer   cipher.AEAD
	workers  []string
	manifest string
	fencer   ed25519.PublicKey
}

func openStorageControl(config *storageConfig) (*storageControl, error) {
	if config == nil {
		return nil, nil
	}
	workers := slices.Clone(config.Workers)
	slices.Sort(workers)
	if !filepath.IsAbs(config.KeyFile) || len(workers) < 2 || len(workers) > 16 {
		return nil, errors.New("storage requires a protected key file and at least two approved workers")
	}
	for index, node := range workers {
		if !identifier.MatchString(node) || index > 0 && node == workers[index-1] {
			return nil, errors.New("storage worker identities must be unique")
		}
	}
	key, err := readSealingKey(config.KeyFile)
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
	manifest, _ := json.Marshal(struct {
		KeyDigest string   `json:"keyDigest"`
		Workers   []string `json:"workers"`
	}{fmt.Sprintf("%x", sha256.Sum256(key)), workers})
	fencer, err := loadFencerKey(config.FencePublicKeyFile)
	if err != nil {
		return nil, err
	}
	return &storageControl{sealer: sealer, workers: workers, manifest: string(manifest), fencer: fencer}, nil
}

func (r *Region) bootstrapStorage(ctx context.Context) error {
	key := r.root + "/storage/config"
	if r.storage == nil {
		configured, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && configured.Count != 0 {
			return errors.New("storage configuration is required for this region")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.storage.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.storage.manifest {
		return errors.New("storage configuration differs from the regional record")
	}
	return nil
}

func loadFencerKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("the fencing public key requires an absolute path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, rest := pem.Decode(data)
	if decoded == nil || decoded.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, errors.New("invalid fencing public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("fencing requires an Ed25519 public key")
	}
	return key, nil
}

func (r *Region) bootstrapFencing(ctx context.Context) error {
	key := r.root + "/storage/fencing/key"
	if r.storage == nil || r.storage.fencer == nil {
		current, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && current.Count != 0 {
			return errors.New("the region requires its configured fencing authority")
		}
		return err
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(r.storage.fencer))
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, expected)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != expected {
		return errors.New("fencing authority differs from the regional record")
	}
	return nil
}
