//go:build e2e

package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const desktopLabHost = "desktop-compute"

func (f regionalGraphFixture) verifyDesktops(t *testing.T, r *Region, scope arm.SubscriptionScope) {
	t.Helper()
	defer f.startWorker(t)()
	const group = "desktop-lab"
	seedVMScope(t, f.ctx, r, scope, group)
	vmA := seedDesktopLabVM(t, f, r, scope, group, "vm-a", workload.VMLinux)
	vmB := seedDesktopLabVM(t, f, r, scope, group, "vm-b", workload.VMLinux)
	windows := seedDesktopLabVM(t, f, r, scope, group, "vm-c", workload.VMWindows)
	lease, err := r.client.Grant(f.ctx, 85)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := json.Marshal(enrollment.Availability{HostID: desktopLabHost, Cell: r.cell, VMRuntime: true})
	if err != nil {
		t.Fatal(err)
	}
	hostKey := r.hostKey("live", desktopLabHost)
	if _, err := r.client.Put(f.ctx, hostKey, string(worker), clientv3.WithLease(lease.ID)); err != nil {
		t.Fatal(err)
	}
	password := "Oc9-" + operationID() + operationID()
	adminToken := f.sign(f.api.URL, f.tenant.Administrator)
	unassignedToken := f.sign(f.api.URL, operationID())
	az := f.loginCLI(t, password, adminToken, unassignedToken)
	f.observe()
	var user enrollment.DirectoryUserView
	if err := json.Unmarshal(az(false, "ad", "user", "create", "--user-principal-name", "desktop@ad.runtime.test", "--display-name",
		"Desktop Fixture", "--mail-nickname", "desktop", "--password", password, "-o", "json"), &user); err != nil || !user.Enabled {
		t.Fatalf("create a managed Samba desktop user: %v", err)
	}
	f.observe()
	var securityGroup enrollment.DirectoryGroupView
	if err := json.Unmarshal(az(false, "ad", "group", "create", "--display-name", "Desktop Group",
		"--mail-nickname", "desktop-group", "-o", "json"), &securityGroup); err != nil || !securityGroup.Security {
		t.Fatalf("create a managed Samba desktop group: %v", err)
	}
	url := func(name string) string {
		address := arm.ResourceAddress{Group: group, Path: arm.DesktopType + "/" + name}
		return f.api.URL + address.ID(scope) + "?api-version=" + arm.DesktopAPIVersion
	}
	userPolicy := arm.DesktopPolicy{VirtualMachineID: vmA.ID(scope), PrincipalType: "User", PrincipalID: user.ID}
	groupPolicy := arm.DesktopPolicy{VirtualMachineID: vmB.ID(scope), PrincipalType: "Group", PrincipalID: securityGroup.ID}
	put := func(name, wantError string, policy arm.DesktopPolicy) desktopAssignment {
		t.Helper()
		f.observe()
		data, err := json.Marshal(map[string]any{"location": r.name, "properties": policy})
		if err != nil {
			t.Fatal(err)
		}
		out := az(wantError != "", "rest", "--method", "put", "--url", url(name), "--body", string(data), "-o", "json")
		if wantError != "" {
			if !bytes.Contains(out, []byte(wantError)) {
				t.Fatalf("desktop request expected %s: %s", wantError, out)
			}
			return desktopAssignment{}
		}
		var view struct {
			Properties desktopAssignment `json:"properties"`
		}
		if err := json.Unmarshal(out, &view); err != nil || view.Properties.DesktopPolicy != policy ||
			!enrollment.ValidDirectoryJoinID(view.Properties.AssignmentID) || view.Properties.ProvisioningState != vmSucceeded {
			t.Fatalf("invalid desktop projection: %s", out)
		}
		return view.Properties
	}
	provider := az(false, "rest", "--method", "get", "--url", f.api.URL+"/subscriptions/"+scope.SubscriptionID+"/providers/Ocean.Desktop?api-version=2024-11-01", "-o", "json")
	if !bytes.Contains(provider, []byte("personalDesktops")) {
		t.Fatal("the enabled provider did not publish the personal desktop resource")
	}
	assigned := put("desktop-a", "", userPolicy)
	if repeat := put("desktop-a", "", userPolicy); repeat != assigned {
		t.Fatal("the same PUT changed the personal desktop assignment")
	}
	second := put("desktop-b", "", groupPolicy)
	if assigned.MachineID == second.MachineID || assigned.DirectoryID != second.DirectoryID {
		t.Fatal("the two desktops did not bind separate Linux machines in one directory")
	}
	browserUser := identity.DesktopPrincipal{Tenant: f.tenant, DirectoryID: assigned.DirectoryID, UserID: user.ID, ExpiresAt: time.Now().Add(3 * time.Minute)}
	check := func(name string, subject identity.DesktopPrincipal, assignment desktopAssignment, expected error) {
		t.Helper()
		f.observe()
		admission, err := r.AuthorizePersonalDesktop(f.ctx, subject, arm.ResourceAddress{Group: group, Path: arm.DesktopType + "/" + name})
		if expected != nil {
			if !errors.Is(err, expected) || admission != (arm.DesktopAdmission{}) {
				t.Fatalf("desktop %s expected rejection %v, got %+v %v", name, expected, admission, err)
			}
		} else if err != nil || admission.AssignmentID != assignment.AssignmentID || admission.MachineID != assignment.MachineID ||
			admission.ExpiresAt.After(time.Now().Add(15*time.Second)) || !admission.ExpiresAt.After(time.Now()) {
			t.Fatalf("unexpected live desktop permission: %+v %v", admission, err)
		}
	}
	check("desktop-a", browserUser, assigned, nil)
	if _, err := r.client.Delete(f.ctx, hostKey); err != nil {
		t.Fatal(err)
	}
	check("desktop-a", browserUser, assigned, arm.ErrDesktopOffline)
	if _, err := r.client.Put(f.ctx, hostKey, string(worker), clientv3.WithLease(lease.ID)); err != nil {
		t.Fatal(err)
	}
	check("desktop-b", browserUser, second, arm.ErrDesktopDenied)
	otherUser := browserUser
	otherUser.UserID = operationID()
	check("desktop-a", otherUser, assigned, arm.ErrDesktopDenied)
	f.observe()
	az(false, "ad", "group", "member", "add", "--group", securityGroup.ID, "--member-id", user.ID, "-o", "none")
	check("desktop-b", browserUser, second, nil)
	f.observe()
	az(false, "ad", "group", "member", "remove", "--group", securityGroup.ID, "--member-id", user.ID, "-o", "none")
	removedAt := time.Now()
	check("desktop-b", browserUser, second, arm.ErrDesktopDenied)
	t.Logf("the first authorization check after removing the AD group member returned denial in %s", time.Since(removedAt).Round(time.Millisecond))
	put("duplicate", "DesktopBindingConflict", userPolicy)
	put("desktop-a", "DesktopBindingConflict", groupPolicy)
	put("missing", "InvalidDesktopPolicy", arm.DesktopPolicy{VirtualMachineID: vmA.ID(scope), PrincipalID: operationID(), PrincipalType: "User"})
	put("wrong-type", "InvalidDesktopPolicy", arm.DesktopPolicy{VirtualMachineID: vmA.ID(scope), PrincipalID: user.ID, PrincipalType: "Group"})
	put("windows", "InvalidDesktopVM", arm.DesktopPolicy{VirtualMachineID: windows.ID(scope), PrincipalID: user.ID, PrincipalType: "User"})
	foreign := arm.SubscriptionScope{TenantID: operationID(), SubscriptionID: operationID()}
	put("foreign-vm", "InvalidDesktopVM", arm.DesktopPolicy{VirtualMachineID: vmA.ID(foreign), PrincipalID: user.ID, PrincipalType: "User"})
	foreignURL := strings.Replace(url("desktop-a"), scope.SubscriptionID, foreign.SubscriptionID, 1)
	if out := az(true, "rest", "--method", "get", "--url", foreignURL,
		"--skip-authorization-header", "--headers", "Authorization=Bearer "+adminToken); !bytes.Contains(out, []byte("SubscriptionNotFound")) {
		t.Fatalf("a cross-subscription read returned an unexpected error: %s", out)
	}
	if out := az(true, "rest", "--method", "get", "--url", url("desktop-a"),
		"--skip-authorization-header", "--headers", "Authorization=Bearer "+unassignedToken); !bytes.Contains(out, []byte("AuthorizationFailed")) {
		t.Fatalf("a same-tenant subject without a role could read the management resource: %s", out)
	}
	vmURL := f.api.URL + vmA.ID(scope) + "?api-version=" + arm.VirtualMachineAPIVersion
	if out := az(true, "rest", "--method", "delete", "--url", vmURL); !bytes.Contains(out, []byte("ResourceInUse")) {
		t.Fatalf("a VM with a desktop link was not protected: %s", out)
	}
	az(false, "rest", "--method", "post", "--url", f.api.URL+vmA.ID(scope)+"/powerOff?api-version="+arm.VirtualMachineAPIVersion)
	check("desktop-a", browserUser, assigned, arm.ErrDesktopOffline)
	f.observe()
	az(false, "ad", "user", "update", "--id", user.ID, "--account-enabled", "false", "-o", "none")
	check("desktop-a", browserUser, assigned, arm.ErrDesktopDenied)
	changedPolicy := arm.DesktopPolicy{VirtualMachineID: vmA.ID(scope), PrincipalType: "Group", PrincipalID: securityGroup.ID}
	if changed := put("desktop-a", "", changedPolicy); changed.AssignmentID == assigned.AssignmentID || changed.MachineID != assigned.MachineID {
		t.Fatal("a principal change must create a new assignment identity on the same machine")
	}
	put("desktop-a", "InvalidDesktopPolicy", userPolicy)
	out := az(false, "rest", "--method", "get", "--url", url("desktop-a"), "-o", "json")
	if !bytes.Contains(out, []byte(securityGroup.ID)) || bytes.Contains(out, []byte(user.ID)) {
		t.Fatalf("an invalid policy replaced the current assignment: %s", out)
	}
	az(false, "rest", "--method", "delete", "--url", url("desktop-a"))
	az(false, "rest", "--method", "delete", "--url", url("desktop-a"))
	check("desktop-a", browserUser, assigned, arm.ErrDesktopDenied)
	if out := az(true, "rest", "--method", "get", "--url", url("desktop-a")); !bytes.Contains(out, []byte("ResourceNotFound")) {
		t.Fatalf("a revoked assignment could still be read: %s", out)
	}
	az(false, "rest", "--method", "delete", "--url", vmURL)
	put("desktop-other", "InvalidDesktopVM", changedPolicy)
	t.Log("stock Azure CLI created managed AD identities, assigned two prepared VM records, and verified assignment versioning, invalid grants and VM deletion guards")
}

func seedDesktopLabVM(t *testing.T, f regionalGraphFixture, r *Region, scope arm.SubscriptionScope, group, name, osType string) arm.ResourceAddress {
	t.Helper()
	address := arm.ResourceAddress{Group: group, Path: arm.VirtualMachineType + "/" + name}
	now := time.Now().UTC()
	op := arm.Operation{ID: operationID(), Kind: createVM, Group: group, Actor: "fixture", Status: arm.OperationSucceeded, StartedAt: now, FinishedAt: &now}
	record := vmRecord{Address: address, MachineID: operationID(), Desired: workload.Running, Observed: workload.Running, Prepared: true,
		OSType: osType, Operation: op.ID, Creation: op.ID,
		Image:       arm.ResourceAddress{Group: group, Path: arm.VMImageType + "/" + name},
		NIC:         arm.ResourceAddress{Group: group, Path: arm.VMNetworkInterfaceType + "/" + name},
		DiskAddress: arm.ResourceAddress{Group: group, Path: arm.VMDiskType + "/" + name}}
	record.Request.Location = r.name
	record.Reservation.NeedsVMRuntime = true
	record.Reservation.HostID, record.Reservation.Cell = desktopLabHost, r.cell
	record.Disk = storage.VMDisk{ID: "vm-" + record.MachineID, SizeGiB: 32, ImageSHA256: strings.Repeat("a", 64), FirmwareSHA256: strings.Repeat("b", 64)}
	if _, err := r.client.Txn(f.ctx).Then(putJSON(r.vmKey(scope, address), record), putJSON(r.operationKey(scope, op.ID), op),
		putJSON(r.inventoryPrefix(scope)+address.Key(), projectVM(scope, record, vmSucceeded, now, now))).Commit(); err != nil {
		t.Fatal(err)
	}
	return address
}
