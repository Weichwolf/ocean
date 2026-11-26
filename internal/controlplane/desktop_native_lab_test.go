//go:build e2e

package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/Weichwolf/ocean/internal/arm"
	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/enrollment"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func (f regionalGraphFixture) verifyNativeDesktopAdmission(t *testing.T, r *Region, scope arm.SubscriptionScope, vmB arm.ResourceAddress,
	first, second desktopAssignment, user enrollment.DirectoryUserView, group enrollment.DirectoryGroupView, guests []desktopLabGateway,
	unknown *http.Client, az func(bool, ...string) []byte) {
	t.Helper()
	addressA := arm.ResourceAddress{Group: vmB.Group, Path: arm.DesktopType + "/desktop-a"}
	addressB := arm.ResourceAddress{Group: vmB.Group, Path: arm.DesktopType + "/desktop-b"}
	bind := func(guest desktopLabGateway, address arm.ResourceAddress, machineID string) desktopNativeConfig {
		return desktopNativeConfig{TenantID: scope.TenantID, SubscriptionID: scope.SubscriptionID, DesktopID: address.ID(scope),
			MachineID: machineID, Certificate: fmt.Sprintf("%x", sha256.Sum256(guest.certificate))}
	}
	bindings, manifest, err := configureDesktopNative([]desktopNativeConfig{
		bind(guests[0], addressA, first.MachineID), bind(guests[1], addressB, second.MachineID),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.desktopLaunch.nativeGuests, r.desktopLaunch.nativeManifest = bindings, manifest
	if err := r.bootstrapDesktopLaunch(f.ctx); err != nil {
		t.Fatal(err)
	}
	nic := vmNIC{Address: arm.ResourceAddress{Group: vmB.Group, Path: arm.VMNetworkInterfaceType + "/vm-b"},
		IP: netip.MustParseAddr("10.254.247.34"), VMID: second.MachineID, VM: &vmB, Lease: operationID(),
		SubnetID: "/subscriptions/" + scope.SubscriptionID + "/resourceGroups/" + vmB.Group + "/providers/Microsoft.Network/virtualNetworks/office/subnets/workforce"}
	nic.Config.Properties.IPConfigurations = []arm.VMIPConfiguration{{Name: "workforce"}}
	vnet, subnet, ok := arm.SubnetParent(scope, nic.SubnetID)
	if !ok {
		t.Fatal("invalid fixture subnet")
	}
	owner := r.subnetNetworkPlacements(scope, vnet, subnet) + nic.IP.String()
	if _, err := r.client.Txn(f.ctx).Then(putJSON(r.vmNICKey(scope, nic.Address), nic), clientv3.OpPut(owner, nic.Lease)).Commit(); err != nil {
		t.Fatal(err)
	}
	request := func(client *http.Client, account string, want int) {
		t.Helper()
		f.observe()
		body, err := json.Marshal(desktop.NativeAdmissionRequest{User: account})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.api.URL+desktop.NativeAdmissionPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != want || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("native desktop admission returned %d (%s), want %d", resp.StatusCode, resp.Header.Get("x-ms-error-code"), want)
		}
	}
	upn := strings.ToLower(user.UPN)
	request(f.api.Client(), upn, http.StatusForbidden)
	request(unknown, upn, http.StatusForbidden)
	request(guests[0].client, "outsider@other.runtime.test", http.StatusForbidden)
	request(guests[0].client, "desktop", http.StatusBadRequest)
	request(guests[0].client, "outsider@ad.runtime.test", http.StatusForbidden)
	request(guests[0].client, upn, http.StatusNoContent)
	request(guests[1].client, upn, http.StatusForbidden)
	az(false, "ad", "group", "member", "add", "--group", group.ID, "--member-id", user.ID, "-o", "none")
	request(guests[1].client, upn, http.StatusNoContent)
	az(false, "ad", "group", "member", "remove", "--group", group.ID, "--member-id", user.ID, "-o", "none")
	request(guests[1].client, upn, http.StatusForbidden)
	request(guests[0].client, upn, http.StatusNoContent)
	t.Log("private desktop certificates enforced separate live direct and group assignments, including denial after withdrawal")
}
