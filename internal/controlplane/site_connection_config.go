package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type wireGuardConfig struct {
	Slots             []gatewaySlot  `json:"slots"`
	ProtectedPrefixes []netip.Prefix `json:"protectedPrefixes"`
}

func configureWireGuard(config *wireGuardConfig, ingress *gatewayControl) (*wireGuardConfig, error) {
	if config == nil {
		return nil, nil
	}
	slots, err := configuredGatewaySlots(config.Slots)
	if err != nil {
		return nil, err
	}
	if ingress != nil {
		if len(slots)+len(ingress.slots) > 64 {
			return nil, errors.New("the region supports up to 64 gateway slots")
		}
		for _, slot := range slots {
			if slices.ContainsFunc(ingress.slots, func(https gatewaySlot) bool { return slot.Name == https.Name }) {
				return nil, errors.New("WireGuard and HTTPS slots need distinct names")
			}
		}
	}
	if len(config.ProtectedPrefixes) == 0 || len(config.ProtectedPrefixes) > 32 {
		return nil, errors.New("WireGuard needs one to 32 protected IPv4 prefixes")
	}
	for index, prefix := range config.ProtectedPrefixes {
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || slices.ContainsFunc(config.ProtectedPrefixes[:index], prefix.Overlaps) {
			return nil, errors.New("protected WireGuard prefixes must be disjoint canonical IPv4 networks")
		}
	}
	return &wireGuardConfig{Slots: slots, ProtectedPrefixes: slices.Clone(config.ProtectedPrefixes)}, nil
}

func (r *Region) bootstrapWireGuard(ctx context.Context) error {
	key := r.root + "/wireguard/config"
	if r.wireGuard == nil {
		record, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && record.Count != 0 {
			return errors.New("WireGuard configuration is required for this region")
		}
		return err
	}
	manifest, err := json.Marshal(r.wireGuard)
	if err != nil {
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, string(manifest))).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	records := result.Responses[0].GetResponseRange().Kvs
	if len(records) != 1 || string(records[0].Value) != string(manifest) {
		return errors.New("WireGuard configuration differs from the regional record")
	}
	return nil
}
