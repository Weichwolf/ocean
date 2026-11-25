//go:build e2e

package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/coreos/go-oidc/v3/oidc"
)

const federationLabDomain = "ad.ocean.web.test"

type ldapFixtureUser struct {
	ID             string              `json:"id"`
	FederationLink string              `json:"federationLink"`
	Enabled        bool                `json:"enabled"`
	Attributes     map[string][]string `json:"attributes"`
}

type ldapFixtureGroup struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Path       string              `json:"path"`
	Attributes map[string][]string `json:"attributes"`
}

type sambaDirectoryLab struct {
	ctx        context.Context
	admin      keycloakAdmin
	tenant     TenantReservation
	directory  ManagedDirectory
	primary    string
	connectors [2]string
	cloud      CloudEndpoints
	firstAdmin onboardingRequest
	value      func(string) string
	readerFile string
	group      func(context.Context, string) (enrollment.DirectoryGraphResult, error)
}

func keycloakSambaLab(t *testing.T, cloud CloudEndpoints) sambaDirectoryLab {
	t.Helper()
	return keycloakSambaExchangeLab(t, cloud, newClientSecret())
}

func keycloakSambaExchangeLab(t *testing.T, cloud CloudEndpoints, exchange string) sambaDirectoryLab {
	t.Helper()
	state := os.Getenv("OCEAN_E2E_SAMBA_FEDERATION_STATE")
	if state == "" {
		t.Skip("set OCEAN_E2E_SAMBA_FEDERATION_STATE for the disposable Samba replica pair")
	}
	value := func(name string) string {
		t.Helper()
		data, err := readPrivateFile(filepath.Join(state, name))
		if err != nil || data == "" {
			t.Fatalf("read fixture value %s: %v", name, err)
		}
		return data
	}
	primary := value("name") + "-dc1"
	if !strings.HasPrefix(primary, "ocean-web-ad-") {
		t.Fatal("use a disposable Samba federation fixture")
	}
	ctx, admin, tenant, cloud, firstAdmin := keycloakTenantExchangeLab(t, cloud, exchange)
	directory := ManagedDirectory{TenantID: tenant.TenantID, SubscriptionID: tenant.SubscriptionID, ID: value("directory-id"),
		Spec:        DirectorySpec{DNSName: federationLabDomain, NetBIOSName: "OCEANWEB", SubnetID: "/fixture/subnet"},
		RequestedAt: time.Now().Add(-time.Minute), ProvisionedAt: time.Now(), DomainSID: value("sid")}
	connectors := [2]string{"ldaps://127.0.0.1:" + value("port1"), "ldaps://127.0.0.1:" + value("port2")}
	return sambaDirectoryLab{ctx: ctx, admin: admin, tenant: tenant, directory: directory, primary: primary, connectors: connectors,
		cloud: cloud, firstAdmin: firstAdmin, value: value, readerFile: filepath.Join(state, "reader")}
}

func TestKeycloakDirectoryFederationLab(t *testing.T) {
	lab := keycloakSambaLab(t, CloudEndpoints{})
	ctx, admin, tenant, directory, connectors, primary, value := lab.ctx, lab.admin, lab.tenant, lab.directory, lab.connectors, lab.primary, lab.value
	bind := value("reader")
	if _, err := admin.ensureDirectoryFederation(ctx, tenant, directory, connectors, "Invalid-"+newUUID(), directoryKerberos{}); err == nil {
		t.Fatal("prepared LDAP federation with an invalid reader credential")
	}
	var unbound keycloakComponent
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/components/"+directory.ID,
		nil, &unbound); err != nil || status != http.StatusNotFound {
		t.Fatalf("a failed bind left an LDAP provider: status %d, %v", status, err)
	}
	federation, err := admin.ensureDirectoryFederation(ctx, tenant, directory, connectors, bind, directoryKerberos{})
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := admin.ensureDirectoryFederation(ctx, tenant, directory, connectors, bind, directoryKerberos{}); err != nil || replay != federation {
		t.Fatalf("replay directory federation: %v", err)
	}
	actor := "employee@" + federationLabDomain
	readUser := func(t *testing.T, upn string) *ldapFixtureUser {
		t.Helper()
		query := url.Values{"username": {upn}, "exact": {"true"}}
		var users []ldapFixtureUser
		if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users?"+query.Encode(), nil, &users); err != nil || status != http.StatusOK || len(users) > 1 {
			t.Fatalf("look up federated user: status %d, entries %d, %v", status, len(users), err)
		}
		if len(users) == 1 {
			return &users[0]
		}
		return nil
	}
	user := readUser(t, actor)
	guid := value("employee-guid")
	if user == nil || !user.Enabled || !tenantID.MatchString(user.ID) || user.FederationLink != federation.ProviderID ||
		!slices.Equal(user.Attributes[managedLDAPObjectID], []string{guid}) {
		t.Fatalf("the federated user did not preserve its AD object GUID: %+v", user)
	}
	for _, unscoped := range []string{managedLDAPReader, "outsider"} {
		if readUser(t, unscoped+"@"+federationLabDomain) != nil {
			t.Fatal("the provider imported an account from outside the workforce OU")
		}
	}
	var local ldapFixtureUser
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "/users/"+tenant.Administrator, nil, &local); err != nil ||
		status != http.StatusOK || local.ID != tenant.Administrator || local.FederationLink != "" || !local.Enabled {
		t.Fatalf("the existing tenant administrator changed: status %d, %v", status, err)
	}
	groupGUID := value("group-guid")
	groups := func(t *testing.T, expected bool) string {
		t.Helper()
		var memberships []ldapFixtureGroup
		groupPath := "/users/" + user.ID + "/groups?briefRepresentation=false"
		if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodGet, groupPath, nil, &memberships); err != nil || status != http.StatusOK {
			t.Fatalf("read mapped memberships: status %d, %v", status, err)
		}
		for _, membership := range memberships {
			if strings.EqualFold(membership.Path, federation.GroupPath+"/WebLab") {
				if !expected || !slices.Equal(membership.Attributes["objectGUID"], []string{groupGUID}) {
					t.Fatalf("unexpected LDAP membership or group object GUID: %+v", membership)
				}
				return membership.ID
			}
		}
		if expected {
			t.Fatalf("no mapped membership in the tenant group root: %+v", memberships)
		}
		return ""
	}
	groupID := groups(t, true)
	clientID := "ldap-password-probe-" + newUUID()
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodPost, "/clients", map[string]any{
		"clientId": clientID, "enabled": true, "protocol": "openid-connect", "publicClient": true,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": true, "fullScopeAllowed": false,
		"defaultClientScopes": []string{"basic"}, "optionalClientScopes": []string{},
		"protocolMappers": []keycloakMapper{mapper("probe audience", "audience", map[string]string{
			"included.custom.audience": clientID, "access.token.claim": "true",
		})},
	}, nil); err != nil || status != http.StatusCreated {
		t.Fatalf("create the disposable password probe: status %d, %v", status, err)
	}
	issuer := admin.endpoints[0] + "/realms/" + tenant.TenantID
	protocol := issuer + "/protocol/openid-connect"
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, admin.client), protocol+"/certs")
	verifier := oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: clientID})
	login := func(t *testing.T, upn, password string, wants int) {
		t.Helper()
		form := url.Values{"grant_type": {"password"}, "client_id": {clientID}, "username": {upn}, "password": {password}}
		var reply struct {
			Token string `json:"access_token"`
		}
		status, err := admin.request(ctx, http.MethodPost, protocol+"/token", "", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), &reply)
		if err != nil || status != wants || (reply.Token != "") != (wants == http.StatusOK) {
			t.Fatalf("LDAP password probe: status %d, expected %d, %v", status, wants, err)
		}
		if wants == http.StatusOK {
			verified, err := verifier.Verify(ctx, reply.Token)
			if err != nil || verified.Subject != user.ID {
				t.Fatalf("the signed access token did not preserve the mapped subject: %v", err)
			}
		}
	}
	password := value("employee")
	login(t, actor, password, http.StatusOK)
	login(t, "outsider@"+federationLabDomain, value("outsider"), http.StatusBadRequest)
	if ok := t.Run("fail over to the standby AD controller", func(t *testing.T) {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			if err := restartSambaFederationPrimary(cleanup, primary, directory.DomainSID); err != nil {
				t.Error(err)
			}
		})
		if _, err := sambaFederationPodman(ctx, "stop", "--time", "5", primary); err != nil {
			t.Fatal(err)
		}
		if replay, err := admin.ensureDirectoryFederation(ctx, tenant, directory, connectors, bind, directoryKerberos{}); err != nil || replay != federation {
			t.Fatalf("replay with one controller offline: %v", err)
		}
		started := time.Now()
		login(t, actor, password, http.StatusOK)
		fallback := readUser(t, actor)
		if fallback == nil || fallback.ID != user.ID || !slices.Equal(fallback.Attributes[managedLDAPObjectID], []string{guid}) ||
			groups(t, true) != groupID {
			t.Fatal("failover did not preserve the Keycloak subject and native user and group GUIDs")
		}
		t.Logf("fresh credential validation and unchanged IDs on the standby after %s", time.Since(started).Round(time.Millisecond))
	}); !ok {
		return
	}
	mutate := func(operation string, fields map[string]any, selector, member string) {
		t.Helper()
		if err := sambaFederationGraph(ctx, primary, operation, fields, selector, member); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := sambaFederationGraph(cleanup, primary, "userUpdate", map[string]any{"accountEnabled": true}, guid, ""); err != nil {
			t.Error(err)
		}
		if err := sambaFederationGraph(cleanup, primary, "groupMemberAdd", nil, groupGUID, guid); err != nil {
			t.Error(err)
		}
	})
	started := time.Now()
	mutate("groupMemberRemove", nil, groupGUID, guid)
	groups(t, false)
	t.Logf("group removal observed at the next request after %s", time.Since(started).Round(time.Millisecond))
	groupMembership := "/users/" + user.ID + "/groups/" + groupID
	if status, err := admin.directoryRequest(ctx, tenant.TenantID, http.MethodPut, groupMembership, nil, nil); err != nil || status < http.StatusBadRequest {
		t.Fatalf("the LDAP reader did not reject a group write: status %d, %v", status, err)
	}
	groups(t, false)
	mutate("groupMemberAdd", nil, groupGUID, guid)
	if groups(t, true) != groupID {
		t.Fatal("the mapped group ID changed after membership re-addition")
	}
	started = time.Now()
	mutate("userUpdate", map[string]any{"accountEnabled": false}, guid, "")
	if disabled := readUser(t, actor); disabled == nil || disabled.Enabled || disabled.ID != user.ID {
		t.Fatal("the account disable did not preserve and disable the original identity")
	}
	login(t, actor, password, http.StatusBadRequest)
	t.Logf("account disable and credential denial observed after %s", time.Since(started).Round(time.Millisecond))
	mutate("userUpdate", map[string]any{"accountEnabled": true}, guid, "")
	if recovered := readUser(t, actor); recovered == nil || !recovered.Enabled || recovered.ID != user.ID {
		t.Fatal("the re-enabled account did not recover the original Keycloak user")
	}
}

func restartSambaFederationPrimary(ctx context.Context, controller, sid string) error {
	if _, err := sambaFederationPodman(ctx, "start", controller); err != nil {
		return err
	}
	probe := []string{"exec", controller, "/usr/bin/python3", "/usr/local/lib/ocean-directory/controller.py"}
	ready := time.NewTicker(500 * time.Millisecond)
	defer ready.Stop()
	for {
		if output, err := sambaFederationPodman(ctx, slices.Concat(probe, []string{"startup-identity"})...); err == nil {
			offer := strings.Fields(string(output))
			if len(offer) != 2 || offer[0] != sid {
				return fmt.Errorf("restarted Samba fixture %s offered an unexpected domain SID", controller)
			}
			if _, err := sambaFederationPodman(ctx, slices.Concat(probe, []string{"authorize-startup", sid, offer[1]})...); err != nil {
				return err
			}
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Samba fixture authorization: %w", ctx.Err())
		case <-ready.C:
		}
	}
	for {
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, err := sambaFederationPodman(check, slices.Concat(probe, []string{"health"})...)
		cancel()
		if err == nil && strings.TrimSpace(string(output)) == sid {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Samba fixture availability: %w", ctx.Err())
		case <-ready.C:
		}
	}
}

func sambaFederationPodman(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "nice", append([]string{"-n", "10", "podman"}, args...)...).Output()
}

func sambaFederationGraph(ctx context.Context, controller, operation string, fields map[string]any, selector, member string) error {
	reply, err := runSambaFederationGraph(ctx, controller, operation, fields, selector, member)
	if err != nil {
		return err
	}
	if reply.Status != http.StatusNoContent {
		return fmt.Errorf("Samba federation fixture operation %s returned status %d", operation, reply.Status)
	}
	return nil
}

func runSambaFederationGraph(ctx context.Context, controller, operation string, fields map[string]any, selector, member string) (enrollment.DirectoryGraphResult, error) {
	var reply enrollment.DirectoryGraphResult
	payload, err := json.Marshal(map[string]any{"id": newUUID(), "expiresAt": time.Now().Add(time.Minute).Unix(),
		"operation": operation, "fields": fields, "selector": selector, "member": member})
	if err != nil {
		return reply, err
	}
	command := exec.CommandContext(ctx, "nice", "-n", "10", "podman", "exec", "-i", controller, "/usr/bin/python3",
		"/usr/local/lib/ocean-directory/controller.py", "graph")
	command.Stdin = bytes.NewReader(payload)
	result, err := command.Output()
	if err != nil {
		return reply, fmt.Errorf("Samba federation fixture operation %s: %w", operation, err)
	}
	if err := json.Unmarshal(result, &reply); err != nil {
		return reply, fmt.Errorf("decode Samba federation fixture result: %w", err)
	}
	return reply, nil
}
