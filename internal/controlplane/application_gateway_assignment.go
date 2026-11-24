package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (r *Region) gatewayHostAuthorized(id string, certificate []byte, snapshot *clientv3.TxnResponse) error {
	registered := snapshot.Responses[0].GetResponseRange().Kvs
	available := snapshot.Responses[1].GetResponseRange().Kvs
	if len(registered) != 1 || len(available) != 1 || available[0].Lease == 0 {
		return enrollment.ErrHostDenied
	}
	var host enrollment.Host
	var live enrollment.Availability
	if json.Unmarshal(registered[0].Value, &host) != nil || json.Unmarshal(available[0].Value, &live) != nil ||
		host.HostID != id || live.HostID != id || host.Cell != live.Cell || host.Pool != live.Pool {
		return errors.New("invalid gateway host registration or availability")
	}
	if host.RevokedAt != nil || !bytes.Equal(host.Certificate, certificate) ||
		!slices.Contains(host.Roles, "gateway") || !slices.Contains(live.Roles, "gateway") {
		return enrollment.ErrHostDenied
	}
	return nil
}

func (r *Region) gatewayAssignments(ctx context.Context, id string, certificate []byte) ([]gatewayRecord, error) {
	prefix := r.gatewayTaskKey(id, "")
	snapshot, err := r.client.Txn(ctx).Then(
		clientv3.OpGet(r.hostKey("registered", id)),
		clientv3.OpGet(r.hostKey("live", id)),
		clientv3.OpGet(prefix, clientv3.WithPrefix(), clientv3.WithLimit(65)),
	).Commit()
	if err != nil {
		return nil, err
	}
	if err := r.gatewayHostAuthorized(id, certificate, snapshot); err != nil {
		return nil, err
	}
	items := snapshot.Responses[2].GetResponseRange().Kvs
	if len(items) > 64 {
		return nil, errors.New("invalid gateway assignment configuration")
	}
	result := make([]gatewayRecord, 0, len(items))
	for _, item := range items {
		slot := strings.TrimPrefix(string(item.Key), prefix)
		recordKey := string(item.Value)
		if !identifier.MatchString(slot) || !strings.HasPrefix(recordKey, r.root+"/tenants/") {
			return nil, errors.New("invalid gateway assignment")
		}
		records, err := r.client.Get(ctx, recordKey, clientv3.WithRev(snapshot.Header.Revision))
		if err != nil {
			return nil, err
		}
		if len(records.Kvs) != 1 {
			return nil, errors.New("gateway assignment has no desired state")
		}
		var record gatewayRecord
		if err := json.Unmarshal(records.Kvs[0].Value, &record); err != nil ||
			r.gatewayRecordKey(record.Scope, record.Resource) != recordKey || record.Slot != slot ||
			record.OperationID == "" || len(record.Hosts) != 2 || !slices.Contains(record.Hosts, id) {
			return nil, errors.New("invalid gateway desired state")
		}
		result = append(result, record)
	}
	return result, nil
}

func (r *Region) HTTPSAssignments(ctx context.Context, id string, certificate []byte) ([]enrollment.HTTPSAssignment, error) {
	records, err := r.gatewayAssignments(ctx, id, certificate)
	if err != nil {
		return nil, err
	}
	result := make([]enrollment.HTTPSAssignment, 0)
	for _, record := range records {
		if record.Site != nil {
			continue
		}
		assignment := enrollment.HTTPSAssignment{
			Slot: record.Slot, Generation: record.generation(), Delete: record.DeleteOperation != "", PublicIPv4: record.PublicIPv4,
		}
		if !assignment.Delete {
			if r.gatewayControl == nil {
				return nil, errors.New("HTTPS gateway assignment requires the certificate envelope key")
			}
			recordKey := r.gatewayRecordKey(record.Scope, record.Resource)
			bundle, err := r.gatewayControl.sealer.Open(nil, nil, record.EncryptedCertificate, []byte(recordKey+"/"+record.OperationID))
			if err != nil {
				return nil, errors.New("HTTPS gateway certificate envelope could not be opened")
			}
			assignment.Hostname, assignment.Backend = record.Hostname, record.Backend
			assignment.BackendSubnet, assignment.CertificateBundle = record.BackendSubnet, bundle
		}
		result = append(result, assignment)
	}
	return result, nil
}

func (r *Region) WireGuardAssignments(ctx context.Context, id string, certificate []byte) ([]enrollment.WireGuardAssignment, error) {
	records, err := r.gatewayAssignments(ctx, id, certificate)
	if err != nil {
		return nil, err
	}
	result := make([]enrollment.WireGuardAssignment, 0)
	for _, record := range records {
		if record.Site == nil {
			continue
		}
		if len(record.Site.Peers) != 2 {
			return nil, errors.New("invalid WireGuard peer assignments")
		}
		assignment := enrollment.WireGuardAssignment{
			Slot: record.Slot, Generation: record.generation(), Delete: record.DeleteOperation != "",
		}
		if !assignment.Delete {
			assignment.Peer = record.Site.Peers[slices.Index(record.Hosts, id)]
			assignment.LocalPrefixes, assignment.CustomerPrefixes = record.Site.LocalPrefixes, record.Site.CustomerPrefixes
			assignment.ProtectedPrefixes = record.Site.ProtectedPrefixes
		}
		result = append(result, assignment)
	}
	return result, nil
}
