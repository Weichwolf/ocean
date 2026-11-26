package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/costmanagement"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/service"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
)

type settings struct {
	config.Server
	Region         *regionConfig      `json:"region"`
	Identity       *identity.Config   `json:"identity"`
	HostEnrollment *enrollment.Config `json:"hostEnrollment"`
}

type regionConfig struct {
	Name                string                     `json:"name"`
	InitialCell         string                     `json:"initialCell"`
	OperationController *bool                      `json:"operationController"`
	Etcd                etcdConfig                 `json:"etcd"`
	PublicIPv4Addresses []netip.Addr               `json:"publicIPv4Addresses"`
	ApplicationGateways *applicationGatewayConfig  `json:"applicationGateways"`
	WireGuard           *wireGuardConfig           `json:"wireGuard"`
	IPsec               *ipsecConfig               `json:"ipsec,omitempty"`
	Workloads           *workloadConfig            `json:"workloads"`
	Storage             *storageConfig             `json:"storage"`
	SMBMembers          []smbBinding               `json:"smbMembers,omitempty"`
	VirtualMachines     *vmConfig                  `json:"virtualMachines,omitempty"`
	DesktopLaunch       *desktopLaunchConfig       `json:"desktopLaunch,omitempty"`
	Telemetry           *telemetryConfig           `json:"telemetry"`
	CostManagement      *costmanagement.RateConfig `json:"costManagement,omitempty"`
	FunctionPlans       bool                       `json:"functionPlans"`
	FunctionDomain      string                     `json:"functionDomain,omitempty"`
	FunctionRegistry    string                     `json:"functionRegistry,omitempty"`
	FunctionSCMDomain   string                     `json:"functionScmDomain,omitempty"`
	FunctionSlots       bool                       `json:"functionSlots,omitempty"`
	ManagedDirectories  *enrollment.Capacity       `json:"managedDirectories,omitempty"`
	DirectoryFenceKey   string                     `json:"directoryFencePublicKeyFile,omitempty"`
	RackProvisioning    *rackProvisioningConfig    `json:"rackProvisioning,omitempty"`
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
	if cfg.Region != nil && cfg.Region.DesktopLaunch != nil && cfg.HostEnrollment == nil {
		return config.Server{}, service.Hooks{}, errors.New("desktop launch requires enrolled gateway hosts")
	}
	if cfg.Region != nil && cfg.Region.RackProvisioning != nil && cfg.HostEnrollment == nil {
		return config.Server{}, service.Hooks{}, errors.New("rack provisioning requires host enrollment")
	}
	if cfg.Region != nil && cfg.Region.ManagedDirectories != nil &&
		(cfg.Identity == nil || cfg.Identity.Onboarding == nil || cfg.Identity.Cloud == nil ||
			cfg.Region.Workloads == nil || !validCapacity(*cfg.Region.ManagedDirectories)) {
		return config.Server{}, service.Hooks{}, errors.New("managed directories require tenant onboarding, workload placement and positive controller capacity")
	}
	if cfg.Region != nil && (cfg.Region.ApplicationGateways != nil || cfg.Region.WireGuard != nil || cfg.Region.IPsec != nil ||
		cfg.Region.Workloads != nil || cfg.Region.Storage != nil || cfg.Region.Telemetry != nil) && cfg.HostEnrollment == nil {
		return config.Server{}, service.Hooks{}, errors.New("gateway and workload execution require enrolled hosts")
	}
	if cfg.Region != nil && cfg.Region.FunctionSCMDomain != "" && (!functions.ValidSCMDomain(cfg.Region.FunctionSCMDomain) ||
		cfg.Region.FunctionSCMDomain == cfg.Region.FunctionDomain || !cfg.Region.FunctionPlans || cfg.Region.FunctionDomain == "" ||
		cfg.Region.Workloads == nil || cfg.Region.Storage == nil || cfg.Identity == nil || cfg.Identity.Cloud == nil ||
		cfg.Identity.Cloud.StorageEndpoint == "") {
		return config.Server{}, service.Hooks{}, errors.New("Functions SCM requires a dedicated DNS domain, workload execution, storage, and the ARM Functions service")
	}
	if cfg.Region != nil && cfg.Region.FunctionSlots && cfg.Region.FunctionSCMDomain == "" {
		return config.Server{}, service.Hooks{}, errors.New("Functions slots require the authenticated SCM endpoint")
	}
	var hooks service.Hooks
	var hosts *enrollment.Authority
	var compatibility *identity.Compatibility
	if cfg.Identity != nil {
		if cfg.Identity.Onboarding != nil && cfg.Region == nil {
			return config.Server{}, service.Hooks{}, errors.New("tenant onboarding requires a regional store")
		}
		if cfg.Region != nil && cfg.Region.FunctionSCMDomain != "" {
			cfg.Identity.Cloud.FunctionsSCMDomain = cfg.Region.FunctionSCMDomain
		}
		compatibility, err = cfg.Identity.OpenCompatibility()
		if err != nil {
			return config.Server{}, service.Hooks{}, err
		}
	}
	if cfg.Region != nil {
		if cfg.Region.Telemetry != nil {
			for _, endpoint := range cfg.Region.Telemetry.Etcd.Endpoints {
				if slices.Contains(cfg.Region.Etcd.Endpoints, endpoint) {
					return config.Server{}, service.Hooks{}, errors.New("telemetry requires separate etcd endpoints")
				}
			}
		}
		region, err := openRegion(*cfg.Region)
		if err != nil {
			return config.Server{}, service.Hooks{}, err
		}
		hooks.Startup = region.bootstrap
		hooks.Readiness = region.ready
		hooks.Close = region.close
		if cfg.HostEnrollment != nil {
			authority, inventory, err := enrollment.Open(*cfg.HostEnrollment, region)
			if err != nil {
				_ = region.close()
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
			hooks.Reconcile = func(ctx context.Context, logger *slog.Logger) {
				if region.workloads != nil {
					go region.reconcileReplicaSets(ctx, logger)
				}
				if cfg.Region.FunctionSCMDomain != "" {
					go region.reconcileFunctionPackageStages(ctx, logger)
				}
				if region.vms != nil {
					go region.reconcileVMFences(ctx, logger)
				}
				if cfg.Region.ManagedDirectories != nil {
					go region.reconcileManagedDirectories(ctx, logger)
				}
				if region.rack != nil {
					go region.reconcileRackHosts(ctx, logger)
				}
				region.reconcileOperations(ctx, logger)
			}
		}
		if compatibility != nil {
			compatibility.EnableSubscriptions(cfg.Region.Name, region.lookupSubscription)
			if cfg.Identity.Onboarding != nil {
				if err := compatibility.EnableOnboarding(*cfg.Identity.Onboarding, region); err != nil {
					_ = region.close()
					return config.Server{}, service.Hooks{}, err
				}
			}
			if cfg.Region.ManagedDirectories != nil {
				if err := compatibility.EnableManagedDirectories(region); err != nil {
					_ = region.close()
					return config.Server{}, service.Hooks{}, err
				}
			}
			if cfg.Identity.Cloud != nil {
				compatibility.EnableSubscriptionGrants(region.hasSubscriptionGrant)
				resources := arm.Server{Origin: cfg.Identity.Cloud.ResourceManager, Location: cfg.Region.Name, StorageSuffix: cfg.Identity.Cloud.StorageEndpoint,
					Authenticate: compatibility.AuthenticateARM, Groups: region, Roles: region, Operations: region, Monitor: region, Inventory: region, Networks: region, Deployments: region,
					GatewayDeployments: region, SiteConnections: region, FunctionPlans: cfg.Region.FunctionPlans, PrincipalExists: compatibility.RolePrincipalExists}
				if region.cost != nil {
					resources.CostManagement = region
				}
				if region.ipsec != nil {
					resources.VPN = region
				}
				if region.workloads != nil {
					resources.Containers = region
					resources.ReplicaSets = region
				}
				if region.storage != nil {
					resources.Storage = region
				}
				if region.smb != nil {
					resources.SMBShares = region
				}
				if region.vms != nil {
					resources.VirtualMachines = region
					if cfg.Region.ManagedDirectories != nil {
						resources.Desktops = region
						resources.AuthenticateDesktop = compatibility.AuthenticateDesktop
						if region.desktopLaunch != nil {
							resources.DesktopLaunch = region
							if len(region.desktopLaunch.nativeGuests) != 0 {
								resources.DesktopNative = region
							}
							if len(region.desktopLaunch.brokers) != 0 {
								resources.DesktopCIFS = region
							}
						}
					}
				}
				if cfg.Region.FunctionPlans && cfg.Region.FunctionDomain != "" && cfg.Identity.Cloud.StorageEndpoint != "" &&
					region.workloads != nil && region.storage != nil {
					resources.Functions = region
					resources.FunctionDomain = cfg.Region.FunctionDomain
					resources.FunctionRegistry = cfg.Region.FunctionRegistry
					if cfg.Region.FunctionSCMDomain != "" {
						resources.FunctionPackages = region
						resources.FunctionSCMDomain = cfg.Region.FunctionSCMDomain
						resources.AuthenticateSCM = compatibility.AuthenticateFunctionSCM
					}
					if cfg.Region.FunctionSlots {
						resources.FunctionSlots = region
					}
				}
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
	client            *clientv3.Client
	name              string
	root              string
	keys              [2]string
	values            [2]string
	publicIPv4        []netip.Addr
	gatewayControl    *gatewayControl
	wireGuard         *wireGuardConfig
	ipsec             *ipsecControl
	workloads         *workloadControl
	directoryCapacity enrollment.Capacity
	directoryFencer   ed25519.PublicKey
	storage           *storageControl
	smb               *smbControl
	vms               *vmControl
	desktopLaunch     *desktopLaunchControl
	telemetry         *telemetryControl
	cost              *costManagementControl
	rack              *rackProvisioning
	cell              string
}

func openRegion(cfg regionConfig) (*Region, error) {
	if !identifier.MatchString(cfg.Name) || !identifier.MatchString(cfg.InitialCell) {
		return nil, errors.New("region name and initialCell must be lowercase identifiers")
	}
	if cfg.CostManagement != nil && (cfg.Telemetry == nil || cfg.Workloads == nil) {
		return nil, errors.New("cost management requires workload execution and the independent telemetry store")
	}
	rackProvisioning, err := openRackProvisioning(cfg.RackProvisioning)
	if err != nil {
		return nil, err
	}
	cost, err := openCostManagement(cfg.CostManagement)
	if err != nil {
		return nil, err
	}
	publicIPv4, err := configuredPublicIPs(cfg.PublicIPv4Addresses)
	if err != nil {
		return nil, err
	}
	gatewayControl, err := openGatewayControl(cfg.ApplicationGateways)
	if err != nil {
		return nil, err
	}
	wireGuard, err := configureWireGuard(cfg.WireGuard, gatewayControl)
	if err != nil {
		return nil, err
	}
	ipsec, err := openIPsec(cfg.IPsec, publicIPv4)
	if err != nil {
		return nil, err
	}
	workloads, err := openWorkloadControl(cfg.Workloads)
	if err != nil {
		return nil, err
	}
	storage, err := openStorageControl(cfg.Storage)
	if err != nil {
		return nil, err
	}
	smbMembers, err := openSMBControl(cfg.SMBMembers, storage, cfg.ManagedDirectories != nil)
	if err != nil {
		return nil, err
	}
	vms, err := openVMControl(cfg.VirtualMachines, workloads, storage)
	if err != nil {
		return nil, err
	}
	desktopLaunch, err := openDesktopLaunch(cfg.DesktopLaunch, vms != nil && cfg.ManagedDirectories != nil, smbMembers)
	if err != nil {
		return nil, err
	}
	directoryFencer, err := loadFencerKey(cfg.DirectoryFenceKey)
	if err != nil {
		return nil, err
	}
	if directoryFencer != nil && cfg.ManagedDirectories == nil {
		return nil, errors.New("a directory fencing key requires managed directories")
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
	telemetry, err := openTelemetry(cfg.Telemetry)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("open telemetry backend: %w", err)
	}
	region := &Region{name: cfg.Name, client: client, telemetry: telemetry, cost: cost, root: root, keys: keys, values: values, publicIPv4: publicIPv4,
		gatewayControl: gatewayControl, wireGuard: wireGuard, ipsec: ipsec, workloads: workloads, storage: storage, cell: cfg.InitialCell,
		directoryFencer: directoryFencer, vms: vms, desktopLaunch: desktopLaunch, smb: smbMembers, rack: rackProvisioning}
	if cfg.ManagedDirectories != nil {
		region.directoryCapacity = *cfg.ManagedDirectories
	}
	return region, nil
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
	if !result.Succeeded {
		if err := region.verify(result); err != nil {
			return err
		}
	}
	if err := region.bootstrapPublicIPPool(ctx); err != nil {
		return err
	}
	if err := region.bootstrapApplicationGateways(ctx); err != nil {
		return err
	}
	if err := region.bootstrapWireGuard(ctx); err != nil {
		return err
	}
	if err := region.bootstrapIPsec(ctx); err != nil {
		return err
	}
	if err := region.bootstrapWorkloads(ctx); err != nil {
		return err
	}
	if err := region.bootstrapManagedDirectories(ctx); err != nil {
		return err
	}
	if err := region.bootstrapDirectoryFencing(ctx); err != nil {
		return err
	}
	if err := region.bootstrapStorage(ctx); err != nil {
		return err
	}
	if err := region.bootstrapSMB(ctx); err != nil {
		return err
	}
	if err := region.bootstrapVirtualMachines(ctx); err != nil {
		return err
	}
	if err := region.bootstrapDesktopLaunch(ctx); err != nil {
		return err
	}
	return region.bootstrapFencing(ctx)
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
		DialOptions: []grpc.DialOption{grpc.WithContextDialer(dialEtcd)},
		TLS: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}, nil
}
