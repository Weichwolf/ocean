package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Weichwolf/ocean/internal/rack"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type rackDeployment struct {
	ID                 string    `json:"id"`
	ProfileDigest      string    `json:"profileDigest"`
	CredentialDigest   string    `json:"credentialDigest,omitempty"`
	ExpiresAt          time.Time `json:"expiresAt,omitzero"`
	ActivationPrepared bool      `json:"activationPrepared"`
	ActivationAccepted bool      `json:"activationAccepted"`
	EnrollmentReleased bool      `json:"enrollmentReleased"`
}

func (r *Region) reconcileRackInstallation(ctx context.Context, feed string, assignment rackAssignment, assignmentRevision int64, policy rackPolicy) error {
	asset := assignment.Asset
	deploymentKey := r.rackKey("deployments", asset.HostID)
	job, revision, err := r.loadRackDeployment(ctx, deploymentKey)
	if err != nil || job.EnrollmentReleased {
		return err
	}
	if revision != 0 && job.ProfileDigest != r.rackDeploymentProfile(policy) {
		return errors.New("rack installation profile differs from the committed deployment")
	}

	// Each attempt has a 40-second deadline. The lease covers it even if the
	// controller exits after submitting a request to the site.
	lease, err := r.client.Grant(ctx, 60)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = r.client.Revoke(cleanup, lease.ID)
	}()
	lock := r.rackKey("installationLocks", asset.HostID)
	currentFeed := clientv3.Compare(clientv3.Value(r.rackKey("inventory", "feed")), "=", feed)
	acquired, err := r.client.Txn(ctx).If(clientv3.Compare(clientv3.Version(lock), "=", 0),
		clientv3.Compare(clientv3.ModRevision(r.rackKey("hosts", asset.HostID)), "=", assignmentRevision),
		clientv3.Compare(clientv3.ModRevision(deploymentKey), "=", revision), currentFeed).
		Then(clientv3.OpPut(lock, "held", clientv3.WithLease(lease.ID))).Commit()
	if err != nil || !acquired.Succeeded {
		return err
	}
	guards := []clientv3.Cmp{clientv3.Compare(clientv3.LeaseValue(lock), "=", lease.ID), currentFeed,
		clientv3.Compare(clientv3.ModRevision(deploymentKey), "=", revision)}

	if err := r.rack.bmcs[asset.Rack].Verify(ctx, asset); err != nil {
		return err
	}
	node, err := r.rack.ironic.VerifiedNode(ctx, asset)
	if err != nil {
		return err
	}
	if node.Maintenance || node.Management != "redfish" || node.Power != "redfish" || node.Storage != "noop" ||
		(node.InspectionMode != "redfish" && node.InspectionMode != "agent") ||
		node.ResourceClass != r.rack.install.Config.ResourceClass {
		return errors.New("Ironic node is unavailable or outside the commissioning profile")
	}
	if node.Instance != "" && (job.ID == "" || node.Instance != job.ID) {
		return errors.New("Ironic node is allocated to a different installation")
	}
	if job.CredentialDigest != "" && node.Instance != job.ID {
		return errors.New("Ironic removed the committed installation allocation")
	}
	switch node.State {
	case "inspect failed", "clean failed", "deploy failed", "error":
		return fmt.Errorf("Ironic requires site recovery from %s", node.State)
	}
	if job.ActivationPrepared && !job.ActivationAccepted &&
		(node.Target == "active" || node.State == "deploying" || node.State == "wait call-back" || node.State == "deploy wait") {
		job.ActivationAccepted = true
		return r.recordRackDeployment(ctx, deploymentKey, job, guards)
	}
	if node.Target != "" {
		return nil
	}
	switch node.State {
	case "enroll", "manageable":
		if revision != 0 {
			return errors.New("Ironic returned an allocated host to commissioning")
		}
		return r.commissionRackNode(ctx, node, policy)
	case "available", "active":
		return r.installRackNode(ctx, assignment, policy, node, deploymentKey, job, guards)
	case "verifying", "inspecting", "inspect wait", "cleaning", "clean wait", "deploying", "wait call-back", "deploy wait":
		return nil
	default:
		return fmt.Errorf("Ironic node is in an unsupported installation state %q", node.State)
	}
}

func (r *Region) rackDeploymentProfile(policy rackPolicy) string {
	input, _ := json.Marshal(policy.Resolvers)
	digest := sha256.Sum256(append([]byte(r.rack.install.Digest+"\n"), input...))
	return hex.EncodeToString(digest[:])
}

func (r *Region) loadRackDeployment(ctx context.Context, key string) (rackDeployment, int64, error) {
	result, err := r.client.Get(ctx, key)
	if err != nil || len(result.Kvs) == 0 {
		return rackDeployment{}, 0, err
	}
	var job rackDeployment
	item := result.Kvs[0]
	if json.Unmarshal(item.Value, &job) != nil || job.ID == "" || job.ProfileDigest == "" ||
		(job.CredentialDigest == "") != job.ExpiresAt.IsZero() ||
		job.ActivationPrepared && job.CredentialDigest == "" || (job.ActivationAccepted || job.EnrollmentReleased) && !job.ActivationPrepared {
		return rackDeployment{}, 0, errors.New("invalid regional rack deployment record")
	}
	return job, item.ModRevision, nil
}

func (r *Region) commissionRackNode(ctx context.Context, node rack.IronicNode, policy rackPolicy) error {
	switch {
	case node.State == "enroll":
		return r.rack.ironic.Transition(ctx, node.UUID, "manage", nil)
	case node.Inspection.IsZero():
		return r.rack.ironic.Transition(ctx, node.UUID, "inspect", nil)
	default:
		if err := r.qualifyRackInspection(node, policy); err != nil {
			return err
		}
		return r.rack.ironic.Transition(ctx, node.UUID, "provide", nil)
	}
}

func (r *Region) qualifyRackInspection(node rack.IronicNode, policy rackPolicy) error {
	cfg := r.rack.install.Config
	if node.ResourceClass != cfg.ResourceClass || node.Inspection.IsZero() ||
		node.Properties.Cores < policy.MinimumCPU || node.Properties.Memory < policy.MinimumMemoryMiB ||
		node.Properties.Disk < cfg.MinimumDiskGiB || node.Properties.CPUArch != cfg.CPUArchitecture {
		return errors.New("Ironic inspection did not meet the approved installation profile")
	}
	return nil
}

func (r *Region) installRackNode(ctx context.Context, assignment rackAssignment, policy rackPolicy, node rack.IronicNode,
	key string, job rackDeployment, guards []clientv3.Cmp) error {
	installer := r.rack.install
	if err := r.qualifyRackInspection(node, policy); err != nil {
		return err
	}
	if job.ID == "" {
		if node.State != "available" || len(node.InstanceInfo) != 0 {
			return errors.New("Ironic node has an existing deployment")
		}
		job.ID = operationID()
		job.ProfileDigest = r.rackDeploymentProfile(policy)
		return r.recordRackDeployment(ctx, key, job, guards)
	}
	allocation, err := r.rack.ironic.Allocation(ctx, job.ID)
	if err != nil {
		return err
	}
	if allocation == nil {
		if node.Instance != "" || job.CredentialDigest != "" || node.State != "available" || len(node.InstanceInfo) != 0 {
			return errors.New("Ironic deployment no longer has its regional allocation")
		}
		return r.rack.ironic.Allocate(ctx, job.ID, node.UUID, installer.Config.ResourceClass)
	}
	if allocation.State == "allocating" && node.State == "available" {
		return nil
	}
	if allocation.State != "active" || allocation.Node != node.UUID || node.Instance != job.ID {
		return errors.New("Ironic allocation did not bind the verified asset")
	}
	token, digest := installer.Credential(r.name, assignment.Asset.HostID, job.ID)
	if job.CredentialDigest == "" {
		if node.State != "available" || len(node.InstanceInfo) != 0 {
			return errors.New("Ironic deployed the allocation before Ocean prepared it")
		}
		job.CredentialDigest, job.ExpiresAt = digest, time.Now().UTC().Add(time.Hour)
		return r.recordRackDeployment(ctx, key, job, guards)
	}
	if job.CredentialDigest != digest || !time.Now().Before(job.ExpiresAt) {
		return errors.New("rack installation credential expired or changed")
	}
	if node.State == "active" {
		if !job.ActivationPrepared || !installer.Image.Matches(node) {
			return errors.New("Ironic did not deploy the pinned Debian image")
		}
		return r.releaseRackEnrollment(ctx, assignment, policy, key, job, guards)
	}
	if job.ActivationAccepted {
		return errors.New("Ironic returned an activated installation to available")
	}
	if len(node.InstanceInfo) == 0 {
		return r.rack.ironic.SetImage(ctx, node.UUID, installer.Image)
	}
	if !installer.Image.Matches(node) || len(node.InstanceInfo) != 4 {
		return errors.New("Ironic instance contains an unexpected image configuration")
	}
	if !job.ActivationPrepared {
		job.ActivationPrepared = true
		return r.recordRackDeployment(ctx, key, job, guards)
	}
	seed, err := installer.Seed(assignment.Asset, job.ID, assignment.DNSName, token, assignment.Address, policy.Gateway, policy.Resolvers)
	if err != nil {
		return err
	}
	if err := r.rack.ironic.Transition(ctx, node.UUID, "active", &seed); err != nil {
		return err
	}
	job.ActivationAccepted = true
	return r.recordRackDeployment(ctx, key, job, guards)
}

func (r *Region) recordRackDeployment(ctx context.Context, key string, job rackDeployment, guards []clientv3.Cmp) error {
	data, _ := json.Marshal(job)
	result, err := r.client.Txn(ctx).If(guards...).Then(clientv3.OpPut(key, string(data))).Commit()
	if err == nil && !result.Succeeded {
		return errors.New("regional rack deployment changed concurrently")
	}
	return err
}

func (r *Region) releaseRackEnrollment(ctx context.Context, assignment rackAssignment, policy rackPolicy, key string, job rackDeployment,
	guards []clientv3.Cmp) error {
	id := assignment.Asset.HostID
	approval := policy.placement()
	approval.HostID, approval.MAC, approval.Address = id, assignment.Asset.BootMAC, assignment.Address.Addr().String()
	approval.TokenSHA256, approval.ExpiresAt = job.CredentialDigest, job.ExpiresAt
	if !approval.Valid() {
		return errors.New("invalid rack enrollment approval")
	}
	job.EnrollmentReleased = true
	approvedData, _ := json.Marshal(approval)
	jobData, _ := json.Marshal(job)
	approvalKey, credential := r.hostKey("inventory", id), r.hostKey("credential", job.CredentialDigest)
	result, err := r.client.Txn(ctx).If(append(guards, clientv3.Compare(clientv3.Version(approvalKey), "=", 0),
		clientv3.Compare(clientv3.Version(credential), "=", 0), clientv3.Compare(clientv3.Version(r.hostKey("registered", id)), "=", 0),
		clientv3.Compare(clientv3.Value(r.hostKey("mac", approval.MAC)), "=", id),
		clientv3.Compare(clientv3.Value(r.hostKey("address", approval.Address)), "=", id))...).
		Then(clientv3.OpPut(key, string(jobData)), clientv3.OpPut(approvalKey, string(approvedData)), clientv3.OpPut(credential, id)).Commit()
	if err == nil && !result.Succeeded {
		return errors.New("rack enrollment conflicts with the regional deployment")
	}
	return err
}
