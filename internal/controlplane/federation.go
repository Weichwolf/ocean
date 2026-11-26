package controlplane

import (
	"errors"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/federation"
	"github.com/Weichwolf/ocean/internal/service"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type federationSettings struct {
	federation.Config
	Etcd etcdConfig `json:"etcd"`
}

// LoadFederation connects a federation listener to its farm's existing quorum.
func LoadFederation(path string) (config.Server, service.Hooks, error) {
	settings, err := config.Load(path, federationSettings{})
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	connection, err := settings.Etcd.clientConfig()
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	client, err := clientv3.New(connection)
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	peer, err := federation.Open(settings.Config, client)
	if err != nil {
		return config.Server{}, service.Hooks{}, errors.Join(err, client.Close())
	}
	return settings.Server, service.Hooks{Startup: peer.Bootstrap, Readiness: peer.Ready,
		Reconcile: peer.Reconcile, Handler: peer.Handler(), Close: client.Close}, nil
}
