package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
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
}

func (b smbBinding) scope() arm.SubscriptionScope {
	return arm.SubscriptionScope{TenantID: b.TenantID, SubscriptionID: b.SubscriptionID}
}

type smbControl struct {
	bindings map[arm.SubscriptionScope]smbBinding
	hosts    map[string]smbBinding
	manifest string
}

func openSMBControl(bindings []smbBinding, storage *storageControl, directories bool) (*smbControl, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	if storage == nil || !directories {
		return nil, errors.New("SMB members require managed directories and regional encrypted storage")
	}
	control := &smbControl{bindings: make(map[arm.SubscriptionScope]smbBinding), hosts: make(map[string]smbBinding)}
	domains := make(map[string]bool)
	for _, binding := range bindings {
		if !validScope(binding.scope()) || !identifier.MatchString(binding.HostID) || len(binding.Member.Shares) != 0 ||
			binding.Member.Validate() != nil || domains[binding.Member.DomainSID] ||
			control.hosts[binding.HostID].HostID != "" || control.bindings[binding.scope()].HostID != "" {
			return nil, errors.New("SMB members need unique hosts and directory identities, with shares assigned by the regional service")
		}
		domains[binding.Member.DomainSID] = true
		binding.Member.Shares = nil
		control.bindings[binding.scope()] = binding
		control.hosts[binding.HostID] = binding
	}
	ordered := slices.SortedFunc(maps.Values(control.hosts), func(a, b smbBinding) int {
		return strings.Compare(a.HostID, b.HostID)
	})
	data, err := json.Marshal(ordered)
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
	if err != nil || result.Succeeded {
		return err
	}
	items := result.Responses[0].GetResponseRange().Kvs
	if len(items) != 1 || string(items[0].Value) != r.smb.manifest {
		return errors.New("SMB member configuration differs from the regional record")
	}
	return nil
}
