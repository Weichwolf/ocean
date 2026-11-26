package controlplane

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) hostedDirectoryReceiptKey(scope arm.SubscriptionScope, generation string) string {
	return r.armPrefix(scope) + "hosted-suspensions/directory/" + generation
}

func (r *Region) ReportDirectorySuspension(ctx context.Context, host string, certificate []byte, tenant, generation string) error {
	binding, err := r.readDirectoryController(ctx, host, certificate, tenant, generation)
	if err != nil {
		return err
	}
	suspension, err := r.HostedOffboarding(ctx, tenant)
	if err != nil {
		return err
	}
	if suspension == nil || suspension.SubscriptionID != binding.directory.SubscriptionID {
		return enrollment.ErrDirectoryAssignmentChanged
	}
	decision, err := json.Marshal(suspension)
	if err != nil {
		return err
	}
	guard := clientv3.Compare(clientv3.Value(r.offboardingMarker(tenant)), "=", string(decision))
	scope := arm.SubscriptionScope{TenantID: tenant, SubscriptionID: binding.directory.SubscriptionID}
	audit := r.auditOp(scope, arm.AuditEvent{Time: time.Now().UTC(), Actor: host, Action: "Ocean.Hosted/offboarding/stopDirectoryController",
		Target: "/ocean/tenants/" + tenant + "/directory", Outcome: workload.Suspended})
	return r.recordHostedWorkerReceipt(ctx, host, r.hostedDirectoryReceiptKey(scope, generation), audit, append(binding.guards, guard))
}
