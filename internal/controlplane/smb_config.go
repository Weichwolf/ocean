package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/smb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type smbBinding struct {
	TenantID       string     `json:"tenantId"`
	SubscriptionID string     `json:"subscriptionId"`
	HostID         string     `json:"hostId"`
	Member         smb.Member `json:"member"`
	StandbyHostID  string     `json:"standbyHostId,omitempty"`
	StateKeyFile   string     `json:"stateKeyFile,omitempty"`
}

func (b smbBinding) scope() arm.SubscriptionScope {
	return arm.SubscriptionScope{TenantID: b.TenantID, SubscriptionID: b.SubscriptionID}
}

type smbControl struct {
	bindings map[arm.SubscriptionScope]smbBinding
	hosts    map[string]smbBinding
	states   map[arm.SubscriptionScope][]byte
	manifest string
}

func smbStateLabel(binding smbBinding) []byte {
	return []byte("smb-member-state/" + binding.TenantID + "/" + binding.SubscriptionID + "/" + binding.Member.StateVolumeID)
}

func openSMBControl(bindings []smbBinding, storage *storageControl, directories bool) (*smbControl, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	if storage == nil || !directories {
		return nil, errors.New("SMB members require managed directories and regional encrypted storage")
	}
	control := &smbControl{bindings: make(map[arm.SubscriptionScope]smbBinding), hosts: make(map[string]smbBinding),
		states: make(map[arm.SubscriptionScope][]byte)}
	domains := make(map[string]bool)
	stateVolumes := make(map[string]bool)
	digests := make(map[arm.SubscriptionScope]string)
	for _, binding := range bindings {
		if !validScope(binding.scope()) || !identifier.MatchString(binding.HostID) || len(binding.Member.Shares) != 0 ||
			binding.Member.Validate() != nil || domains[binding.Member.DomainSID] ||
			control.hosts[binding.HostID].HostID != "" || control.bindings[binding.scope()].HostID != "" {
			return nil, errors.New("SMB members need unique hosts and directory identities, with shares assigned by the regional service")
		}
		domains[binding.Member.DomainSID] = true
		binding.Member.Shares = nil
		if binding.StandbyHostID != "" {
			if !identifier.MatchString(binding.StandbyHostID) || binding.StandbyHostID == binding.HostID ||
				control.hosts[binding.StandbyHostID].HostID != "" || binding.Member.StateVolumeID == "" ||
				stateVolumes[binding.Member.StateVolumeID] || !filepath.IsAbs(binding.StateKeyFile) || len(storage.fencer) == 0 {
				return nil, errors.New("redundant SMB requires a dedicated standby, encrypted member state and a fencing authority")
			}
			key, err := readSealingKey(binding.StateKeyFile)
			if err != nil {
				return nil, err
			}
			control.states[binding.scope()] = storage.sealer.Seal(nil, nil, key, smbStateLabel(binding))
			digests[binding.scope()] = fmt.Sprintf("%x", sha256.Sum256(key))
			clear(key)
			stateVolumes[binding.Member.StateVolumeID] = true
			control.hosts[binding.StandbyHostID] = binding
		} else if binding.Member.StateVolumeID != "" || binding.StateKeyFile != "" {
			return nil, errors.New("SMB member state is only configurable with an approved standby")
		}
		control.bindings[binding.scope()] = binding
		control.hosts[binding.HostID] = binding
	}
	ordered := slices.SortedFunc(maps.Values(control.bindings), func(a, b smbBinding) int {
		return strings.Compare(a.HostID, b.HostID)
	})
	type manifestRow struct {
		smbBinding
		StateKeyDigest string `json:"stateKeyDigest,omitempty"`
		FenceKeyDigest string `json:"fenceKeyDigest,omitempty"`
	}
	manifest := make([]manifestRow, 0, len(ordered))
	for _, binding := range ordered {
		row := manifestRow{smbBinding: binding, StateKeyDigest: digests[binding.scope()]}
		if binding.StandbyHostID != "" {
			row.StateKeyFile = ""
			row.FenceKeyDigest = fmt.Sprintf("%x", sha256.Sum256(storage.fencer))
		}
		manifest = append(manifest, row)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	control.manifest = string(data)
	return control, nil
}

func (r *Region) bootstrapSMB(ctx context.Context) error {
	key := r.root + "/smb/config"
	if r.smb == nil {
		configured, err := r.client.Get(ctx, key, clientv3.WithCountOnly())
		if err == nil && configured.Count != 0 {
			return errors.New("SMB member configuration is required for this region")
		}
		return err
	}
	result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, r.smb.manifest)).Else(clientv3.OpGet(key)).Commit()
	if err != nil {
		return err
	}
	if !result.Succeeded {
		items := result.Responses[0].GetResponseRange().Kvs
		if len(items) != 1 || string(items[0].Value) != r.smb.manifest {
			return errors.New("SMB member configuration differs from the regional record")
		}
	}
	for _, binding := range r.smb.bindings {
		key := r.smbOwnerKey(binding)
		initial := smbOwner{HostID: binding.HostID, Generation: operationID()}
		result, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(key), "=", 0)).
			Then(putJSON(key, initial)).Else(clientv3.OpGet(key)).Commit()
		if err != nil {
			return err
		}
		if !result.Succeeded {
			if _, _, err := readSMBOwner(binding, result.Responses[0].GetResponseRange().Kvs); err != nil {
				return err
			}
		}
	}
	return nil
}
