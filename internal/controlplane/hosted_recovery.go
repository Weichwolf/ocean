package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/Weichwolf/ocean/internal/arm"
)

type hostedRecoveryTarget struct {
	OperatorPool    string   `json:"operatorPool"`
	MetadataOrigins []string `json:"metadataOrigins"`
	KeyDirectory    string   `json:"keyDirectory"`
}

func (p *hostedRegionPolicy) validateRecoveryTargets() error {
	for name, target := range p.RecoveryTargets {
		if !identifier.MatchString(name) || !p.allowsPool(target.OperatorPool) || len(target.MetadataOrigins) == 0 ||
			!validHostedDirectory(target.KeyDirectory) {
			return errors.New("hosted recovery targets require an approved operator pool, metadata origins and a private key directory")
		}
		slices.Sort(target.MetadataOrigins)
		for i, origin := range target.MetadataOrigins {
			if !validEtcdOrigin(origin) || i > 0 && target.MetadataOrigins[i-1] == origin {
				return errors.New("hosted recovery metadata origins must be distinct HTTPS origins")
			}
		}
	}
	return nil
}

func (cfg regionConfig) authorizeRecoveryTarget(name, destination string) (hostedRecoveryTarget, error) {
	if cfg.HostedWorkplace == nil {
		if name != "" {
			return hostedRecoveryTarget{}, errors.New("a named recovery target requires hosted regional policy")
		}
		return hostedRecoveryTarget{}, nil
	}
	if err := cfg.HostedWorkplace.validate(); err != nil {
		return hostedRecoveryTarget{}, err
	}
	target, registered := cfg.HostedWorkplace.RecoveryTargets[name]
	if !registered || !slices.Equal(slices.Sorted(slices.Values(cfg.Etcd.Endpoints)), target.MetadataOrigins) {
		return hostedRecoveryTarget{}, errors.New("the restored metadata origins do not match an approved recovery target")
	}
	if filepath.Clean(destination) != destination || filepath.Dir(destination) != target.KeyDirectory || filepath.Base(destination) == "." {
		return hostedRecoveryTarget{}, errors.New("the recovery key destination is outside the approved target directory")
	}
	return target, nil
}

func (r *Region) verifyRecoveryTarget(ctx context.Context, scope arm.SubscriptionScope, target hostedRecoveryTarget) error {
	if r.hosted != nil {
		if r.deletionLedger == nil {
			return errors.New("hosted key recovery requires the independent deletion ledger")
		}
		if err := r.ready(ctx); err != nil {
			return err
		}
		if _, err := r.readPlacementSubscription(ctx, scope); err != nil {
			return err
		}
		if _, err := r.hostedPoolGuard(ctx, scope, target.OperatorPool, 0); err != nil {
			return errors.Join(errors.New("the tenant policy does not authorize this recovery target"), err)
		}
		return nil
	}
	rows, err := r.client.Get(ctx, r.keys[0])
	if err != nil || len(rows.Kvs) == 0 {
		return err // Older standalone storage backups can omit regional metadata.
	}
	var metadata struct {
		Hosted *hostedRegionPolicy `json:"hostedWorkplace"`
	}
	if json.Unmarshal(rows.Kvs[0].Value, &metadata) != nil || metadata.Hosted != nil {
		return errors.New("hosted metadata requires its original policy and an approved recovery target")
	}
	return nil
}

func (target hostedRecoveryTarget) openKeyDirectory() (*os.Root, error) {
	return openPrivateHostedDirectory(target.KeyDirectory, "recovery")
}

func validHostedDirectory(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func openPrivateHostedDirectory(path, purpose string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err == nil {
		status, owner := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm()&0077 == 0 && owner && status.Uid == uint32(os.Geteuid()) {
			return root, nil
		}
		err = fmt.Errorf("the %s directory must be private and owned by the current process", purpose)
	}
	return nil, errors.Join(err, root.Close())
}
