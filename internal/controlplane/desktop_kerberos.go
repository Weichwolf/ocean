package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type desktopGuestCertificate struct {
	MachineID   string `json:"machineId"`
	Certificate string `json:"certificateSha256"`
}

type desktopBrokerConfig struct {
	TenantID       string                    `json:"tenantId"`
	SubscriptionID string                    `json:"subscriptionId"`
	Account        string                    `json:"account"`
	KeytabFile     string                    `json:"keytabFile"`
	ConfigFile     string                    `json:"kerberosConfigFile"`
	Guests         []desktopGuestCertificate `json:"guests"`
}

type desktopBrokerManifest struct {
	Scope     arm.SubscriptionScope     `json:"scope"`
	Principal string                    `json:"principal"`
	Service   string                    `json:"service"`
	Guests    []desktopGuestCertificate `json:"guests"`
}

type desktopBrokerGuest struct {
	broker    desktop.CIFSBroker
	machineID string
}

var desktopBrokerAccount = regexp.MustCompile(`^[a-z][a-z0-9-]{0,19}$`)

func configureDesktopBrokers(settings []desktopBrokerConfig, smb *smbControl) (map[[sha256.Size]byte]desktopBrokerGuest, []desktopBrokerManifest, error) {
	if len(settings) == 0 {
		return nil, nil, nil
	}
	if smb == nil || len(settings) > 64 {
		return nil, nil, errors.New("desktop Kerberos brokers require configured tenant SMB members")
	}
	brokers := make(map[[sha256.Size]byte]desktopBrokerGuest)
	machines := make(map[string]bool)
	seen := make(map[arm.SubscriptionScope]bool)
	manifest := make([]desktopBrokerManifest, 0, len(settings))
	for _, cfg := range settings {
		scope := arm.SubscriptionScope{TenantID: cfg.TenantID, SubscriptionID: cfg.SubscriptionID}
		binding, ok := smb.bindings[scope]
		if !ok || seen[scope] || !desktopBrokerAccount.MatchString(cfg.Account) || len(cfg.Guests) < 1 || len(cfg.Guests) > 256 {
			return nil, nil, errors.New("invalid desktop Kerberos broker configuration")
		}
		seen[scope] = true
		if !validBrokerFile(cfg.KeytabFile, 0077) || !validBrokerFile(cfg.ConfigFile, 0022) {
			return nil, nil, errors.New("desktop Kerberos broker files must be private and absolute")
		}
		realm := strings.ToUpper(binding.Member.DNSDomain)
		broker := desktop.CIFSBroker{Principal: cfg.Account + "@" + realm, KeytabFile: cfg.KeytabFile,
			ConfigFile: cfg.ConfigFile, DNSDomain: binding.Member.DNSDomain,
			Service: "cifs/" + strings.ToLower(binding.Member.ServerName) + "." + binding.Member.DNSDomain + "@" + realm}
		guests := slices.Clone(cfg.Guests)
		slices.SortFunc(guests, func(a, b desktopGuestCertificate) int { return strings.Compare(a.MachineID, b.MachineID) })
		for i, guest := range guests {
			digest, err := hex.DecodeString(guest.Certificate)
			if err != nil || len(digest) != sha256.Size || !enrollment.ValidDirectoryJoinID(guest.MachineID) || machines[guest.MachineID] {
				return nil, nil, errors.New("invalid or duplicate desktop guest certificate binding")
			}
			fingerprint := [sha256.Size]byte(digest)
			if _, present := brokers[fingerprint]; present {
				return nil, nil, errors.New("desktop guest certificates must have separate identities")
			}
			machines[guest.MachineID] = true
			guests[i].Certificate = hex.EncodeToString(digest)
			brokers[fingerprint] = desktopBrokerGuest{broker: broker, machineID: guest.MachineID}
		}
		manifest = append(manifest, desktopBrokerManifest{Scope: scope, Principal: broker.Principal, Service: broker.Service, Guests: guests})
	}
	slices.SortFunc(manifest, func(a, b desktopBrokerManifest) int { return strings.Compare(a.Scope.TenantID, b.Scope.TenantID) })
	return brokers, manifest, nil
}

func validBrokerFile(path string, denied os.FileMode) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&denied != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner != nil && (owner.Uid == 0 || owner.Uid == uint32(os.Geteuid()))
}

func (r *Region) DesktopCIFSCache(ctx context.Context, certificate []byte, input desktop.KerberosRequest) ([]byte, error) {
	if r.desktopLaunch == nil || len(certificate) == 0 {
		return nil, desktop.ErrLaunchDenied
	}
	guest, ok := r.desktopLaunch.brokers[sha256.Sum256(certificate)]
	if !ok || !strings.HasSuffix(input.User, "@"+guest.broker.DNSDomain) {
		return nil, desktop.ErrLaunchDenied
	}
	public := ed25519.PublicKey(r.desktopLaunch.signer[ed25519.SeedSize:])
	receipt, expires, err := desktop.VerifyLaunch(public, guest.machineID, input.User, input.Credential, time.Now())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	lease, err := r.client.Grant(ctx, 90)
	if err != nil {
		return nil, err
	}
	key := r.root + "/desktop-launch/redemptions/" + guest.machineID + "/" + receipt
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, "", clientv3.WithLease(lease.ID))).Commit()
	if err != nil {
		return nil, err
	}
	if !result.Succeeded {
		_, _ = r.client.Revoke(ctx, lease.ID)
		return nil, desktop.ErrLaunchDenied
	}
	return guest.broker.Acquire(ctx, input.User)
}
