package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type desktopLaunchConfig struct {
	SigningKeyFile string                `json:"signingKeyFile"`
	Gateways       []string              `json:"gateways"`
	SMBBrokers     []desktopBrokerConfig `json:"smbBrokers,omitempty"`
	NativeGuests   []desktopNativeConfig `json:"nativeGuests,omitempty"`
}

type desktopLaunchControl struct {
	signer         ed25519.PrivateKey
	gateways       []string
	manifest       string
	brokerManifest string
	brokers        map[[sha256.Size]byte]desktopBrokerGuest
	brokerScopes   map[string]arm.SubscriptionScope
	nativeGuests   map[[sha256.Size]byte]desktopNativeGuest
	nativeManifest string
}

func openDesktopLaunch(cfg *desktopLaunchConfig, haveProviders bool, smb *smbControl) (*desktopLaunchControl, error) {
	if cfg == nil {
		return nil, nil
	}
	if !haveProviders || len(cfg.Gateways) < 2 || len(cfg.Gateways) > 16 {
		return nil, errors.New("desktop launch requires virtual machines, managed directories and 2 to 16 gateways")
	}
	gateways := slices.Clone(cfg.Gateways)
	slices.Sort(gateways)
	for i, gateway := range gateways {
		if !identifier.MatchString(gateway) || i > 0 && gateway == gateways[i-1] {
			return nil, errors.New("desktop launch gateway IDs must be unique lowercase host identifiers")
		}
	}
	seed, err := readSealingKey(cfg.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load desktop launch signing seed: %w", err)
	}
	defer clear(seed)
	signer := ed25519.NewKeyFromSeed(seed)
	brokers, publicBrokers, err := configureDesktopBrokers(cfg.SMBBrokers, smb)
	if err != nil {
		return nil, err
	}
	native, nativeManifest, err := configureDesktopNative(cfg.NativeGuests)
	if err != nil {
		return nil, err
	}
	brokerScopes := make(map[string]arm.SubscriptionScope, len(brokers))
	for _, binding := range publicBrokers {
		for _, guest := range binding.Guests {
			brokerScopes[guest.MachineID] = binding.Scope
		}
	}
	for fingerprint, guest := range native {
		if broker, ok := brokers[fingerprint]; ok &&
			(broker.machineID != guest.machineID || brokerScopes[broker.machineID] != guest.scope) {
			return nil, errors.New("a desktop certificate must bind the same machine and tenant for native access and SMB")
		}
	}
	manifest, err := json.Marshal(struct {
		Gateways  []string `json:"gateways"`
		PublicKey []byte   `json:"publicKey"`
	}{gateways, signer[ed25519.SeedSize:]})
	if err != nil {
		return nil, err
	}
	control := &desktopLaunchControl{signer: signer, gateways: gateways, manifest: string(manifest), brokers: brokers, brokerScopes: brokerScopes,
		nativeGuests: native, nativeManifest: nativeManifest}
	if len(publicBrokers) != 0 {
		data, err := json.Marshal(publicBrokers)
		if err != nil {
			return nil, err
		}
		control.brokerManifest = string(data)
	}
	return control, nil
}

func (r *Region) bootstrapDesktopLaunch(ctx context.Context) error {
	var manifest, brokers, native string
	if r.desktopLaunch != nil {
		manifest, brokers, native = r.desktopLaunch.manifest, r.desktopLaunch.brokerManifest, r.desktopLaunch.nativeManifest
	}
	if err := r.bootstrapDesktopManifest(ctx, r.root+"/desktop-launch/config", manifest); err != nil {
		return err
	}
	if err := r.bootstrapDesktopManifest(ctx, r.root+"/desktop-launch/kerberos-config", brokers); err != nil {
		return err
	}
	return r.bootstrapDesktopManifest(ctx, r.root+"/desktop-launch/native-config", native)
}

func (r *Region) bootstrapDesktopManifest(ctx context.Context, key, manifest string) error {
	if manifest == "" {
		read, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && read.Count != 0 {
			return errors.New("the region requires its desktop launch configuration")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != manifest {
		return errors.New("desktop launch configuration differs from the regional record")
	}
	return nil
}

func (r *Region) LaunchPersonalDesktop(ctx context.Context, principal identity.DesktopPrincipal, address arm.ResourceAddress, gateway string, certificate []byte) (arm.DesktopLaunch, error) {
	access, err := r.resolveGatewayDesktop(ctx, principal, address, gateway, certificate, true)
	if err != nil {
		return arm.DesktopLaunch{}, err
	}
	access.ExpiresAt = access.ExpiresAt.Truncate(time.Second)
	password, err := desktop.IssueLaunch(r.desktopLaunch.signer, access.MachineID, access.User, time.Now(), access.ExpiresAt)
	if err != nil {
		return arm.DesktopLaunch{}, arm.ErrDesktopDenied
	}
	return arm.DesktopLaunch{DesktopSession: access, Credential: password}, nil
}

func (r *Region) RenewPersonalDesktop(ctx context.Context, principal identity.DesktopPrincipal, address arm.ResourceAddress, gateway string, certificate []byte) (arm.DesktopSession, error) {
	return r.resolveGatewayDesktop(ctx, principal, address, gateway, certificate, false)
}

func (r *Region) resolveGatewayDesktop(ctx context.Context, principal identity.DesktopPrincipal, address arm.ResourceAddress, gateway string, certificate []byte, launch bool) (arm.DesktopSession, error) {
	guards, err := r.desktopGatewayGuards(ctx, gateway, certificate)
	if err != nil {
		return arm.DesktopSession{}, err
	}
	return r.resolvePersonalDesktop(ctx, principal, address, desktopAccessOptions{gatewayGuards: guards, launch: launch})
}

func (r *Region) desktopGatewayGuards(ctx context.Context, gateway string, certificate []byte) ([]clientv3.Cmp, error) {
	if r.desktopLaunch == nil || len(certificate) == 0 || !slices.Contains(r.desktopLaunch.gateways, gateway) {
		return nil, arm.ErrDesktopGateway
	}
	registered, live := r.hostKey("registered", gateway), r.hostKey("live", gateway)
	result, err := r.client.Txn(ctx).Then(clientv3.OpGet(registered), clientv3.OpGet(live)).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.authorizeHostRole(gateway, certificate, "gateway", result); err != nil {
		if errors.Is(err, enrollment.ErrHostDenied) {
			return nil, arm.ErrDesktopGateway
		}
		return nil, err
	}
	return []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(registered), "=", result.Responses[0].GetResponseRange().Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(live), "=", result.Responses[1].GetResponseRange().Kvs[0].ModRevision),
	}, nil
}

func (r *Region) desktopPrivateNIC(ctx context.Context, scope arm.SubscriptionScope, target vmRecord, revision int64) (vmNIC, []clientv3.Cmp, error) {
	key := r.vmNICKey(scope, target.NIC)
	result, err := r.client.Get(ctx, key, clientv3.WithRev(revision))
	if err != nil {
		return vmNIC{}, nil, err
	}
	if len(result.Kvs) != 1 {
		return vmNIC{}, nil, arm.ErrDesktopOffline
	}
	nic, err := decodeVMNIC(result.Kvs[0].Value, target.NIC)
	if err != nil {
		return vmNIC{}, nil, err
	}
	parent, subnet, tenantSubnet := arm.SubnetParent(scope, nic.SubnetID)
	if nic.VM == nil || nic.VM.Key() != target.Address.Key() || nic.VMID != target.MachineID || !nic.IP.IsPrivate() || !tenantSubnet {
		return vmNIC{}, nil, arm.ErrDesktopOffline
	}
	ownerKey := r.subnetNetworkPlacements(scope, parent, subnet) + nic.IP.String()
	owner, err := r.client.Get(ctx, ownerKey, clientv3.WithRev(revision))
	if err != nil {
		return vmNIC{}, nil, err
	}
	if len(owner.Kvs) != 1 || string(owner.Kvs[0].Value) != nic.Lease {
		return vmNIC{}, nil, arm.ErrDesktopOffline
	}
	return nic, []clientv3.Cmp{
		clientv3.Compare(clientv3.ModRevision(key), "=", result.Kvs[0].ModRevision),
		clientv3.Compare(clientv3.ModRevision(ownerKey), "=", owner.Kvs[0].ModRevision),
	}, nil
}
