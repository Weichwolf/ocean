//go:build e2e

package controlplane

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/identity"
)

type windowsGraphProof struct {
	RunID        string    `json:"runId"`
	Stage        string    `json:"stage"`
	Time         time.Time `json:"timestamp"`
	Machine      string    `json:"machine"`
	Edition      string    `json:"edition"`
	Controller   string    `json:"controller"`
	Principal    string    `json:"principal,omitempty"`
	AccountSID   string    `json:"accountSid,omitempty"`
	GroupPresent bool      `json:"groupPresent"`
	Kerberos     bool      `json:"kerberos"`
	ShareRead    bool      `json:"shareRead"`
	ShareError   int       `json:"shareError,omitempty"`
	SignInError  int       `json:"signInError,omitempty"`
}

func verifyRegionalWindowsGraph(t *testing.T, f regionalGraphFixture, hosts directoryKVMHosts, run string,
	backup windowsRecoveryArchive, writer identity.DirectoryControllerReadiness) {
	t.Helper()
	initial, rotated := "Win9-"+rand.Text(), "Win9-"+rand.Text()
	for name, secret := range map[string]string{"initial": initial, "rotated": rotated} {
		path := filepath.Join(hosts.state, "graph-fixture-"+name+".secret")
		writeWindowsRecoverySecret(t, path, []byte(secret))
		defer os.Remove(path)
	}

	runCLI := f.loginCLI(t, initial, rotated)
	ad := func(category string, args ...string) []byte {
		t.Helper()
		hosts.refresh(f.ctx, nil)
		return runCLI(false, append([]string{"ad", category}, args...)...)
	}
	upn := "graphprobe@" + backup.Identity.DNSName
	const userName, groupName, alias = "Windows Graph Probe", "Windows Graph Readers", "windows-graph-readers"
	var user enrollment.DirectoryUserView
	if err := json.Unmarshal(ad("user", "create", "--user-principal-name", upn, "--display-name", userName,
		"--mail-nickname", "graphprobe", "--password", initial, "-o", "json"), &user); err != nil ||
		!enrollment.ValidDirectoryJoinID(user.ID) || user.UPN != upn || !user.Enabled {
		t.Fatalf("the CLI did not create an enabled Windows fixture user: %v", err)
	}
	var shown enrollment.DirectoryUserView
	if err := json.Unmarshal(ad("user", "show", "--id", upn, "-o", "json"), &shown); err != nil || shown != user {
		t.Fatalf("the CLI did not read the new Windows fixture user: %v", err)
	}
	var users []enrollment.DirectoryUserView
	if err := json.Unmarshal(ad("user", "list", "--upn", upn, "-o", "json"), &users); err != nil ||
		len(users) != 1 || users[0] != user {
		t.Fatalf("the CLI did not list the new Windows fixture user: %v", err)
	}
	var group enrollment.DirectoryGroupView
	if err := json.Unmarshal(ad("group", "create", "--display-name", groupName, "--mail-nickname", alias, "-o", "json"), &group); err != nil ||
		!enrollment.ValidDirectoryJoinID(group.ID) || group.Alias != alias || !group.Security {
		t.Fatalf("the CLI did not create a Windows security group: %v", err)
	}
	var groups []enrollment.DirectoryGroupView
	if err := json.Unmarshal(ad("group", "list", "--display-name", groupName, "-o", "json"), &groups); err != nil ||
		len(groups) != 1 || groups[0] != group {
		t.Fatalf("the CLI did not list the Windows security group: %v", err)
	}
	native := func(category, id string) map[string]string {
		t.Helper()
		script := `set -eu
container=$(podman ps --filter label=ocean.directory-controller --format '{{.Names}}')
nice -n 10 podman exec "$container" /bin/sh -ec '
	config=$(find /var/lib/ocean-ad -path "*/etc/smb.conf")
	exec samba-tool "$1" show "$2" --attributes=objectSid,objectGUID,userAccountControl -s "$config"
' -- ` + category + " " + id
		out, err := hosts.ssh(f.ctx, hosts.names[0], script, nil)
		if err != nil {
			t.Fatalf("read native Windows fixture %s: %v: %s", category, err, out)
		}
		attributes := make(map[string]string)
		for line := range strings.SplitSeq(string(out), "\n") {
			if key, value, ok := strings.Cut(line, ": "); ok {
				attributes[key] = value
			}
		}
		return attributes
	}
	directoryUser := native("user", "graphprobe")
	directoryGroup := native("group", alias)
	accountSID, groupSID := directoryUser["objectSid"], directoryGroup["objectSid"]
	if directoryUser["objectGUID"] != user.ID || directoryGroup["objectGUID"] != group.ID || accountSID == groupSID ||
		!strings.HasPrefix(accountSID, backup.Identity.SID+"-") || !strings.HasPrefix(groupSID, backup.Identity.SID+"-") {
		t.Fatal("the Graph objects do not match their native Samba identities")
	}
	hosts.run(f.ctx, hosts.names[0], `set -eu
container=$(podman ps --filter label=ocean.directory-controller --format '{{.Names}}')
nice -n 10 podman exec "$container" /bin/sh -ec '
	config=$(find /var/lib/ocean-ad -path "*/etc/smb.conf")
	dir="${config%/etc/smb.conf}/windows-graph-probe"
	mkdir -m 0755 "$dir"
	printf "%s\n" "$1" >"$dir/probe.txt"
	chmod 0644 "$dir/probe.txt"
	printf "\n[ocean-graph-probe]\n\tpath = %s\n\tread only = yes\n\tvalid users = +OCEANLAB\\%s\n" "$dir" "$2" >>"$config"
	smbcontrol -s "$config" all reload-config
' -- `+run+" "+alias, nil)

	var observations []windowsGraphProof
	phasePath := filepath.Join(hosts.state, "graph-phase.json")
	defer os.Remove(phasePath)
	probe := func(stage, password string, member bool, signInErrors ...int) {
		t.Helper()
		start := time.Now().UTC()
		writeDirectoryLabResult(t, phasePath, map[string]any{
			"runId": run, "stage": stage, "upn": upn, "credential": password, "groupSid": groupSID,
			"controller": writer.DNSName, "address": writer.PrivateIPv4, "after": start,
		})
		t.Logf("Windows Graph probe stage %s ready. Submit a fresh Server Core probe.", stage)
		pollDirectoryLab(t, f.ctx, "Windows Graph result for "+stage, func() bool {
			hosts.refresh(f.ctx, nil)
			for _, line := range readWindowsProbeRecords[windowsGraphProof](t, hosts.state, "server-core", "OCEAN-REGIONAL-GRAPH ") {
				if line.RunID != run || line.Stage != stage || !line.Time.After(start) {
					continue
				}
				if line.Machine == "" || !strings.HasPrefix(line.Edition, "Server") || line.Controller != writer.DNSName ||
					!slices.Contains(signInErrors, line.SignInError) || len(observations) > 0 && line.Machine != observations[0].Machine {
					t.Fatalf("unexpected Windows sign-in result for %s: %+v", stage, line)
				}
				if line.SignInError == 0 && (!strings.EqualFold(line.Principal, upn) || line.AccountSID != accountSID ||
					!line.Kerberos || line.GroupPresent != member || line.ShareRead != member ||
					(member && line.ShareError != 0) || (!member && line.ShareError != 5)) {
					t.Fatalf("unexpected Windows Kerberos or SMB result for %s: %+v", stage, line)
				}
				if line.SignInError != 0 && (line.Principal != "" || line.Kerberos || line.ShareRead || line.GroupPresent) {
					t.Fatalf("failed sign-in unexpectedly accessed the share for %s: %+v", stage, line)
				}
				observations = append(observations, line)
				return true
			}
			return false
		})
	}

	memberCount := func(expected int) {
		t.Helper()
		var members []enrollment.DirectoryUserView
		err := json.Unmarshal(ad("group", "member", "list", "--group", group.ID, "-o", "json"), &members)
		if err != nil || len(members) != expected || expected == 1 && members[0].ID != user.ID {
			t.Fatalf("unexpected CLI membership count: %d, %v", len(members), err)
		}
	}
	memberCount(0)
	probe("before-membership", "initial", false, 0)
	ad("group", "member", "add", "--group", group.ID, "--member-id", user.ID, "-o", "none")
	memberCount(1)
	probe("with-membership", "initial", true, 0)
	ad("group", "member", "remove", "--group", group.ID, "--member-id", user.ID, "-o", "none")
	memberCount(0)
	probe("after-removal", "initial", false, 0)
	ad("user", "update", "--id", user.ID, "--password", rotated, "-o", "none")
	probe("old-password", "initial", false, 1326)
	probe("rotated-password", "rotated", false, 0)
	ad("user", "update", "--id", user.ID, "--display-name", "Disabled Windows Graph Probe", "--account-enabled", "false", "-o", "none")
	if err := json.Unmarshal(ad("user", "show", "--id", user.ID, "-o", "json"), &shown); err != nil ||
		shown.Enabled || shown.ID != user.ID || shown.DisplayName != "Disabled Windows Graph Probe" || shown.Alias != user.Alias {
		t.Fatalf("the CLI did not report the disabled native user: %v", err)
	}
	directoryUser = native("user", "graphprobe")
	const accountDisabled = 2
	flags, err := strconv.ParseUint(directoryUser["userAccountControl"], 10, 32)
	if err != nil || flags&accountDisabled == 0 || directoryUser["objectSid"] != accountSID || directoryUser["objectGUID"] != user.ID {
		t.Fatalf("the original Samba account did not carry the disabled flag: %v", err)
	}
	// The Windows logon API can surface a generic account restriction.
	probe("disabled", "rotated", false, 1327, 1331)
	writeDirectoryLabResult(t, filepath.Join(hosts.state, "evidence", "regional-windows-graph.json"), map[string]any{
		"runId": run, "user": user.ID, "group": group.ID, "userSid": accountSID, "groupSid": groupSID,
		"disabledUserAccountControl": flags, "observations": observations,
	})
	t.Log("Stock Azure CLI changed native Samba user and group records through the regional Graph API. Fresh Windows sign-in, Kerberos and SMB probes verified the password and access changes.")
}
