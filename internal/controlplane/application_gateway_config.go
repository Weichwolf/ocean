package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type applicationGatewayConfig struct {
	CertificateKeyFile string        `json:"certificateKeyFile"`
	Slots              []gatewaySlot `json:"slots"`
}

type gatewaySlot struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

type gatewayControl struct {
	sealer   cipher.AEAD
	slots    []gatewaySlot
	manifest string
}

func openGatewayControl(config *applicationGatewayConfig) (*gatewayControl, error) {
	if config == nil {
		return nil, nil
	}
	if !filepath.IsAbs(config.CertificateKeyFile) {
		return nil, errors.New("Application Gateways require an absolute certificate key path")
	}
	slots, err := configuredGatewaySlots(config.Slots)
	if err != nil {
		return nil, err
	}
	key, err := readSealingKey(config.CertificateKeyFile)
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
		KeyDigest string        `json:"keyDigest"`
		Slots     []gatewaySlot `json:"slots"`
	}{fmt.Sprintf("%x", sha256.Sum256(key)), slots})
	if err != nil {
		return nil, err
	}
	return &gatewayControl{sealer: sealer, slots: slots, manifest: string(manifest)}, nil
}

func configuredGatewaySlots(configured []gatewaySlot) ([]gatewaySlot, error) {
	if len(configured) == 0 || len(configured) > 64 {
		return nil, errors.New("one to 64 gateway slots are required")
	}
	slots := slices.Clone(configured)
	slices.SortFunc(slots, func(left, right gatewaySlot) int {
		return strings.Compare(left.Name, right.Name)
	})
	for index, slot := range slots {
		if !identifier.MatchString(slot.Name) || index > 0 && slots[index-1].Name == slot.Name ||
			len(slot.Hosts) != 2 || slot.Hosts[0] == slot.Hosts[1] ||
			!identifier.MatchString(slot.Hosts[0]) || !identifier.MatchString(slot.Hosts[1]) {
			return nil, errors.New("each gateway slot requires a unique name and two distinct gateway hosts")
		}
	}
	return slots, nil
}

func readSealingKey(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		(stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Size() != 32 {
		return nil, errors.New("the encryption key must be a private 32-byte file")
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 || !slices.ContainsFunc(key, func(value byte) bool { return value != 0 }) {
		return nil, errors.New("invalid encryption key")
	}
	return key, nil
}

func (r *Region) bootstrapApplicationGateways(ctx context.Context) error {
	key := r.root + "/application-gateways/config"
	if r.gatewayControl == nil {
		record, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && record.Count != 0 {
			return errors.New("Application Gateway configuration is required for this region")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.gatewayControl.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.gatewayControl.manifest {
		return errors.New("Application Gateway configuration differs from the regional record")
	}
	return nil
}
