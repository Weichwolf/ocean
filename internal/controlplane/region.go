package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/service"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type settings struct {
	config.Server
	Region         *regionConfig      `json:"region"`
	Identity       *identity.Config   `json:"identity"`
	HostEnrollment *enrollment.Config `json:"hostEnrollment"`
}

type regionConfig struct {
	Name                string     `json:"name"`
	InitialCell         string     `json:"initialCell"`
	OperationController *bool      `json:"operationController"`
	Etcd                etcdConfig `json:"etcd"`
}

type etcdConfig struct {
	Endpoints       []string `json:"endpoints"`
	CAFile          string   `json:"caFile"`
	CertificateFile string   `json:"certificateFile"`
	KeyFile         string   `json:"keyFile"`
}

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load configures the regional store and binds its lifecycle to the API listener.
func Load(path string) (config.Server, service.Hooks, error) {
	cfg, err := config.Load(path, settings{Server: config.Server{ListenAddress: "127.0.0.1:8080"}})
	if err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	if err := cfg.Server.Validate(); err != nil {
		return config.Server{}, service.Hooks{}, err
	}
	if cfg.HostEnrollment != nil && (cfg.Region == nil || cfg.TLS == nil || !cfg.TLS.OptionalClientCA) {
		return config.Server{}, service.Hooks{}, errors.New("host enrollment requires a region and TLS with optional client certificates")
	}
	var hooks service.Hooks
	var hosts *enrollment.Authority
	var compatibility *identity.Compatibility
	if cfg.Identity != nil {
		if cfg.Identity.Onboarding != nil && cfg.Region == nil {
			return config.Server{}, service.Hooks{}, errors.New("tenant onboarding requires a regional store")
		}
		compatibility, err = cfg.Identity.OpenCompatibility()
		if err != nil {
			return config.Server{}, service.Hooks{}, err
		}
	}
	if cfg.Region != nil {
		region, err := openRegion(*cfg.Region)
		if err != nil {
			return config.Server{}, service.Hooks{}, err
		}
		hooks.Startup = region.bootstrap
		hooks.Readiness = region.ready
		hooks.Close = region.client.Close
		if cfg.HostEnrollment != nil {
			authority, inventory, err := enrollment.Open(*cfg.HostEnrollment, region)
			if err != nil {
				_ = region.client.Close()
				return config.Server{}, service.Hooks{}, err
			}
			hosts = authority
			hooks.Startup = func(ctx context.Context) error {
				if err := region.bootstrap(ctx); err != nil {
					return err
				}
				return region.seedHostInventory(ctx, inventory)
			}
		}
		if cfg.Region.OperationController == nil || *cfg.Region.OperationController {
			hooks.Reconcile = region.reconcileOperations
		}
		if compatibility != nil {
			compatibility.EnableSubscriptions(cfg.Region.Name, region.lookupSubscription)
			if cfg.Identity.Onboarding != nil {
				if err := compatibility.EnableOnboarding(*cfg.Identity.Onboarding, region); err != nil {
					_ = region.client.Close()
					return config.Server{}, service.Hooks{}, err
				}
			}
			if cfg.Identity.Cloud != nil {
				compatibility.EnableSubscriptionGrants(region.hasSubscriptionGrant)
				resources := arm.Server{Origin: cfg.Identity.Cloud.ResourceManager, Location: cfg.Region.Name,
					Authenticate: compatibility.AuthenticateARM, Groups: region, Roles: region, Operations: region, Inventory: region, Networks: region,
					PrincipalExists: compatibility.RolePrincipalExists}
				hooks.Handler = resources.Handler(compatibility.Handler())
			}
		}
	}
	if hooks.Handler == nil && compatibility != nil {
		hooks.Handler = compatibility.Handler()
	}
	if hosts != nil {
		hooks.Handler = hosts.Handler(hooks.Handler)
	}
	return cfg.Server, hooks, nil
}

// Region owns the initial metadata for one region. Resource providers use their
// own key prefixes for operations and reservations under the same region root.
type Region struct {
	client *clientv3.Client
	root   string
	keys   [2]string
	values [2]string
}

func openRegion(cfg regionConfig) (*Region, error) {
	if !identifier.MatchString(cfg.Name) || !identifier.MatchString(cfg.InitialCell) {
		return nil, errors.New("region name and initialCell must be lowercase identifiers")
	}
	connection, err := cfg.Etcd.clientConfig()
	if err != nil {
		return nil, err
	}
	root := "/ocean/v1/regions/" + cfg.Name
	keys, values := initialRecords(root, cfg.Name, cfg.InitialCell)
	client, err := clientv3.New(connection)
	if err != nil {
		return nil, fmt.Errorf("open regional etcd client: %w", err)
	}
	return &Region{client: client, root: root, keys: keys, values: values}, nil
}

func initialRecords(root, name, cell string) ([2]string, [2]string) {
	region := struct {
		Name        string `json:"name"`
		InitialCell string `json:"initialCell"`
	}{Name: name, InitialCell: cell}
	cellRecord := struct {
		Name   string `json:"name"`
		Region string `json:"region"`
	}{Name: cell, Region: name}
	regionJSON, _ := json.Marshal(region)
	cellJSON, _ := json.Marshal(cellRecord)
	return [2]string{root + "/metadata", root + "/cells/" + cell + "/metadata"}, [2]string{string(regionJSON), string(cellJSON)}
}

func (region *Region) bootstrap(ctx context.Context) error {
	result, err := region.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(region.keys[0]), "=", 0), clientv3.Compare(clientv3.Version(region.keys[1]), "=", 0)).
		Then(clientv3.OpPut(region.keys[0], region.values[0]), clientv3.OpPut(region.keys[1], region.values[1])).
		Else(clientv3.OpGet(region.keys[0]), clientv3.OpGet(region.keys[1])).Commit()
	if err != nil {
		return fmt.Errorf("bootstrap region: %w", err)
	}
	if result.Succeeded {
		return nil
	}
	return region.verify(result)
}

func (region *Region) ready(ctx context.Context) error {
	result, err := region.client.Txn(ctx).Then(clientv3.OpGet(region.keys[0]), clientv3.OpGet(region.keys[1])).Commit()
	if err != nil {
		return err
	}
	return region.verify(result)
}

func (region *Region) verify(result *clientv3.TxnResponse) error {
	if len(result.Responses) != len(region.keys) {
		return errors.New("etcd response lacks the regional metadata records")
	}
	for index, response := range result.Responses {
		values := response.GetResponseRange().GetKvs()
		if len(values) != 1 || string(values[0].Value) != region.values[index] {
			return fmt.Errorf("regional metadata differs from the configuration at %s", region.keys[index])
		}
	}
	return nil
}

func (cfg etcdConfig) clientConfig() (clientv3.Config, error) {
	if len(cfg.Endpoints) == 0 {
		return clientv3.Config{}, errors.New("region.etcd.endpoints is required")
	}
	for _, endpoint := range cfg.Endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return clientv3.Config{}, errors.New("etcd endpoints must be HTTPS origins")
		}
	}
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return clientv3.Config{}, fmt.Errorf("read etcd CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return clientv3.Config{}, errors.New("etcd CA file contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		return clientv3.Config{}, fmt.Errorf("load etcd client certificate: %w", err)
	}
	return clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: 3 * time.Second,
		TLS: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}, nil
}
