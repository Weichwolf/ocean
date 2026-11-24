package controlplane

import (
	"context"
	"strings"

	"github.com/Weichwolf/ocean/internal/arm"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) groupInventoryReferencesPrefix(scope arm.SubscriptionScope, group string) string {
	return r.armPrefix(scope) + "resource-links/" + strings.ToLower(group) + "/"
}

func (r *Region) dependentsPrefix(scope arm.SubscriptionScope, target arm.ResourceAddress) string {
	return r.groupInventoryReferencesPrefix(scope, target.Group) + strings.ToLower(target.Path) + ":/"
}

// inventoryReferenceChanges reads new targets at the same revision as the
// owner and emits the comparisons and index changes for the owner transaction.
func (r *Region) inventoryReferenceChanges(ctx context.Context, scope arm.SubscriptionScope, owner arm.ResourceAddress,
	previous, next *arm.InventoryResource, revision int64) ([]clientv3.Cmp, []clientv3.Op, error) {
	before, after := resourceReferences(previous), resourceReferences(next)
	var additions []arm.ResourceAddress
	var mutations []clientv3.Op
	suffix := strings.ToLower(owner.Path)
	for key, ref := range before {
		if _, kept := after[key]; !kept {
			mutations = append(mutations, clientv3.OpDelete(r.dependentsPrefix(scope, ref)+suffix))
		}
	}
	var reads []clientv3.Op
	for key, ref := range after {
		if _, existing := before[key]; !existing {
			additions = append(additions, ref)
			reads = append(reads, clientv3.OpGet(r.inventoryPrefix(scope)+key, clientv3.WithRev(revision), clientv3.WithKeysOnly()))
		}
	}
	if len(reads) == 0 {
		return nil, mutations, nil
	}
	targets, err := r.client.Txn(ctx).Then(reads...).Commit()
	if err != nil {
		return nil, nil, err
	}
	conditions := make([]clientv3.Cmp, 0, len(additions))
	for index, ref := range additions {
		keys := targets.Responses[index].GetResponseRange().Kvs
		if len(keys) != 1 {
			return nil, nil, arm.ErrLinkedResourceMissing
		}
		target := keys[0]
		conditions = append(conditions, clientv3.Compare(clientv3.CreateRevision(string(target.Key)), "=", target.CreateRevision))
		mutations = append(mutations, clientv3.OpPut(r.dependentsPrefix(scope, ref)+suffix, ""))
	}
	return conditions, mutations, nil
}

func resourceReferences(resource *arm.InventoryResource) map[string]arm.ResourceAddress {
	if resource == nil || len(resource.References) == 0 {
		return nil
	}
	references := make(map[string]arm.ResourceAddress, len(resource.References))
	for _, ref := range resource.References {
		references[ref.Key()] = ref
	}
	return references
}
