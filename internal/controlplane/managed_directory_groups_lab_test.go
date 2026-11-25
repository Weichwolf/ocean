//go:build e2e

package controlplane

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

func (f regionalGraphFixture) verifyGroups(t *testing.T, cli func(bool, ...string) []byte, member, password string) {
	t.Helper()
	const name = "Ocean Marine Operators"
	const alias = "marine-operators"
	const description = "Private maritime operations"
	create := func() enrollment.DirectoryGroupView {
		t.Helper()
		var group enrollment.DirectoryGroupView
		out := cli(false, "create", "--display-name", name, "--mail-nickname", alias, "--description", description, "-o", "json")
		if json.Unmarshal(out, &group) != nil || !enrollment.ValidDirectoryJoinID(group.ID) || group.DisplayName != name ||
			group.Alias != alias || !group.Security || group.Mail || group.Description != description {
			t.Fatalf("the pinned CLI did not return the native security group: %s", out)
		}
		return group
	}
	scope := create()
	if repeat := create(); scope != repeat {
		t.Fatal("the CLI group replay returned another directory object")
	}
	var listed []enrollment.DirectoryGroupView
	if err := json.Unmarshal(cli(false, "list", "--display-name", "Ocean Marine", "-o", "json"), &listed); err != nil ||
		len(listed) != 1 || listed[0] != scope {
		t.Fatal("the native group was missing from filtered listing")
	}
	var shown enrollment.DirectoryGroupView
	if err := json.Unmarshal(cli(false, "show", "--group", scope.ID, "-o", "json"), &shown); err != nil || shown != scope {
		t.Fatal("the CLI group GUID did not resolve to the created security group")
	}

	directory := func(category, name, attribute string) string {
		t.Helper()
		cmd := exec.CommandContext(f.ctx, "nice", "-n", "10", "podman", "exec", f.container, "/bin/sh", "-ec", `
			config=$(find /var/lib/ocean-ad -path '*/etc/smb.conf')
			exec samba-tool "$1" show "$2" --attributes="$3" -s "$config"
		`, "--", category, name, attribute)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("check native Samba %s: %v: %s", category, err, output)
		}
		for line := range strings.SplitSeq(string(output), "\n") {
			if value, ok := strings.CutPrefix(line, attribute+": "); ok {
				return value
			}
		}
		t.Fatalf("missing %s in the native AD result", attribute)
		return ""
	}
	groupSID := directory("group", alias, "objectSid")
	if !regexp.MustCompile(`^S-1-5-21(-[0-9]{1,10}){4}$`).MatchString(groupSID) ||
		!strings.HasPrefix(groupSID, f.sid+"-") ||
		directory("group", alias, "objectGUID") != scope.ID {
		t.Fatal("the Graph group does not point at the native group SID and GUID")
	}
	outside := directory("user", "employee", "objectGUID")
	if rejected := cli(true, "member", "add", "--group", scope.ID, "--member-id", outside, "-o", "none"); !bytes.Contains(rejected, []byte("managed group was not found")) {
		t.Fatal("the managed profile could add a user outside the workforce scope")
	}

	prepare := exec.CommandContext(f.ctx, "nice", "-n", "10", "podman", "exec", f.container, "/bin/sh", "-ec", `
		config=$(find /var/lib/ocean-ad -path '*/etc/smb.conf')
		dir="${config%/etc/smb.conf}/group-probe"
		mkdir -m 0755 "$dir"
		printf 'Ocean restricted group file\n' >"$dir/probe.txt"
		chmod 0644 "$dir/probe.txt"
		printf '\n[ocean-group-probe]\n\tpath = %s\n\tread only = yes\n\tvalid users = +OCEANRUN\\%s\n' "$dir" "$1" >>"$config"
		smbcontrol -s "$config" all reload-config
	`, "--", alias)
	if out, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("configure the group-restricted test share: %v: %s", err, out)
	}
	probe := func(stage string, allow bool) {
		t.Helper()
		command := exec.CommandContext(f.ctx, "bash", filepath.Join(f.root, "lab/verify_group_smb.sh"),
			f.sambaImage, f.network, f.address)
		command.Stdin = strings.NewReader(password + "\n")
		out, err := command.CombinedOutput()
		if allow && (err != nil || !bytes.Contains(out, []byte("Ocean restricted group file"))) ||
			!allow && (err == nil || !bytes.Contains(out, []byte("NT_STATUS_ACCESS_DENIED"))) {
			t.Fatalf("fresh Kerberos SMB connection %s did not give access=%t: %v: %s", stage, allow, err,
				strings.ReplaceAll(string(out), password, "[directory password]"))
		}
	}
	members := func(count int) {
		t.Helper()
		var users []enrollment.DirectoryUserView
		if err := json.Unmarshal(cli(false, "member", "list", "--group", scope.ID, "-o", "json"), &users); err != nil || len(users) != count ||
			count == 1 && (users[0].ID != member || users[0].Kind != "#microsoft.graph.user") {
			t.Fatal("the CLI did not report the actual group membership")
		}
	}
	badBody := strings.NewReader(`{"@odata.id":"https://foreign.ocean.test/v1.0/directoryObjects/` + member + `"}`)
	request, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.graph.URL+"/v1.0/groups/"+scope.ID+"/members/$ref", badBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.sign(f.graph.URL, f.tenant.Administrator))
	reply, err := f.graph.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, reply.Body)
	reply.Body.Close()
	if reply.StatusCode != http.StatusBadRequest {
		t.Fatal("Graph accepted a member reference from an unrecognized origin")
	}

	members(0)
	probe("before membership", false)
	cli(false, "member", "add", "--group", scope.ID, "--member-id", member, "-o", "none")
	cli(false, "member", "add", "--group", scope.ID, "--member-id", member, "-o", "none")
	members(1)
	probe("with membership", true)
	cli(false, "member", "remove", "--group", scope.ID, "--member-id", member, "-o", "none")
	cli(false, "member", "remove", "--group", scope.ID, "--member-id", member, "-o", "none")
	members(0)
	probe("after membership removal", false)
	t.Log("Azure CLI 2.93.0 created and listed an AD security group and added and removed a workforce member. Fresh Debian Kerberos SMB sessions verified denial, granted file access, and revocation.")
}
