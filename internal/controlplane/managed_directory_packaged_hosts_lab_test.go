//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Weichwolf/ocean/internal/lab"
)

const packagedDirectoryClient = "farm-1-node-03"

const packagedDirectoryWorker = `cd /
uid=$(id -u ocean-agent)
worker() { sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" "$@"; }
`

func (f *directoryKVMHosts) startPackagedAgents(ctx context.Context, region *Region, guests []lab.GuestStatus, origin, image string, ca []byte) {
	f.t.Helper()
	tokens := f.approve(ctx, region, guests)
	config := "/etc/ocean-agent/"
	state := "/var/lib/ocean-agent/" + f.directory
	networkConfig := []byte(`{"privateFabric":"work0","protectedPrefixes":["10.231.0.0/16","10.233.0.0/16","10.234.0.0/16","169.254.0.0/16"]}`)
	for i, host := range f.names {
		f.run(ctx, host, "set -eu\n"+packagedDirectoryWorker+`
test -f /usr/lib/systemd/user/ocean-agent.service
test -f /usr/lib/systemd/system/ocean-container-network.service
test "$(dpkg-query -W -f='${db:Status-Status}' ocean-agent)" = installed
worker nice -n 10 podman image exists `+image+`
test -z "$(worker nice -n 10 podman ps -q --filter label=ocean.directory-controller)"
sudo install -d -o ocean-agent -g ocean-agent -m 0700 `+state, nil)
		settings, _ := json.Marshal(map[string]any{"listenAddress": "127.0.0.1:8081", "enrollment": map[string]any{
			"origin": origin, "hostId": host, "managementInterface": "mgmt0", "caFile": config + "directory-lab-ca.pem",
			"tokenFile": state + "/join-token", "stateDirectory": state, "directoryImage": image,
		}})
		for name, data := range map[string][]byte{"config.json": settings, "directory-lab-ca.pem": ca, "workload-network.json": networkConfig} {
			f.run(ctx, host, "sudo tee "+config+name+" >/dev/null", bytes.NewReader(data))
		}
		f.run(ctx, host, "sudo -u ocean-agent sh -c 'umask 077; cat >"+state+"/join-token'", strings.NewReader(tokens[i]))
		f.run(ctx, host, "set -eu\n"+packagedDirectoryWorker+`
sudo systemctl daemon-reload
worker systemctl --user daemon-reload
worker systemctl --user restart ocean-agent.service
sudo systemctl enable --now ocean-container-network.service`, nil)
	}
}

func (f directoryKVMHosts) packagedAttachment(ctx context.Context, host, address string) string {
	f.t.Helper()
	out, err := f.ssh(ctx, host, "set -eu\n"+packagedDirectoryWorker+`
name=$(worker nice -n 10 podman ps --filter label=ocean.directory-controller --format '{{.Names}}')
pid=$(worker nice -n 10 podman inspect --format '{{.State.Pid}}' "$name")
test "$(cat "/run/ocean-workload-network/$name.ready")" = "$pid"
test "$(sudo systemctl show --value --property=Nice ocean-container-network.service)" = 10
test "$(worker systemctl --user show --value --property=Nice ocean-agent.service)" = 10
test "$(ps -p "$pid" -o ni= | tr -d ' ')" = 10
dpkg-query -W -f='${Version}\n' ocean-agent
sudo nsenter --target "$pid" --net ip -o -4 addr show
`, nil)
	if err != nil {
		f.t.Fatalf("verify the packaged network attachment on %s: %v: %s", host, err, out)
	}
	version, addresses, ok := strings.Cut(string(out), "\n")
	if !ok || version == "" || !strings.Contains(addresses, " "+address+"/32 ") {
		f.t.Fatalf("the packaged network service did not attach %s on %s: %s", address, host, out)
	}
	return version
}

func (f directoryKVMHosts) stopPackagedAgents(ctx context.Context, online map[string]bool) {
	for _, host := range f.names {
		if !online[host] {
			continue
		}
		if f.t.Failed() {
			out, _ := f.ssh(ctx, host, packagedDirectoryWorker+`
sudo journalctl _UID="$uid" _SYSTEMD_USER_UNIT=ocean-agent.service --no-pager -n 24
sudo journalctl -u ocean-container-network.service --no-pager -n 24
for name in $(worker nice -n 10 podman ps -a -q --filter label=ocean.directory-controller); do
	worker nice -n 10 podman logs --tail 12 "$name"
done`, nil)
			f.t.Logf("packaged directory services on %s: %s", host, out)
		}
		_, err := f.ssh(ctx, host, packagedDirectoryWorker+`
sudo systemctl stop ocean-container-network.service
worker systemctl --user stop ocean-agent.service
for name in $(worker nice -n 10 podman ps -q --filter label=ocean.directory-controller); do
	worker nice -n 10 podman stop --time 3 "$name"
done
sudo unlink /var/lib/ocean-agent/`+f.directory+"/join-token", nil)
		if err != nil {
			f.t.Errorf("stop the packaged directory fixture on %s: %v", host, err)
		}
	}
}

func (f directoryKVMHosts) probePackagedDirectory(ctx context.Context, controller, address, domain string, password []byte) directoryClientProof {
	f.t.Helper()
	// The explicit KDC and server address force each probe through the chosen
	// controller. The discovery record and SMB service name still use DNS.
	script := fmt.Sprintf(`set -eu
node=%s
address=%s
domain=%s
realm=$(printf '%%s' "$domain" | tr '[:lower:]' '[:upper:]')
dir=$(mktemp -d)
trap 'kdestroy 2>/dev/null || true; rm -r -- "$dir"' EXIT
export KRB5_CONFIG="$dir/krb5.conf" KRB5CCNAME="FILE:$dir/cache"
printf '[libdefaults]\n default_realm = %%s\n dns_lookup_kdc = false\n dns_uri_lookup = false\n rdns = false\n[realms]\n %%s = {\n  kdc = %%s\n }\n' \
  "$realm" "$realm" "$address" >"$KRB5_CONFIG"
dig @"$address" +short +time=2 +tries=1 A "$node" | grep -Fx "$address" >/dev/null
dig @"$address" +short +time=2 +tries=1 SRV "_ldap._tcp.dc._msdcs.$domain" | grep -F " 389 $node." >/dev/null
kinit "Administrator@$realm" >/dev/null
klist -s
kvno "cifs/$node" >/dev/null
policy="$domain/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"
smbclient "//$node/SYSVOL" -I "$address" --use-kerberos=required -c "get $policy $dir/GPT.INI" >/dev/null
test -s "$dir/GPT.INI"
printf 'policySHA256=%%s\n' "$(sha256sum "$dir/GPT.INI" | cut -d ' ' -f 1)"
`, controller, address, domain)
	out, err := f.ssh(ctx, packagedDirectoryClient, script, bytes.NewReader(append(bytes.Clone(password), '\n')))
	var digest string
	for line := range strings.SplitSeq(string(out), "\n") {
		if value, ok := strings.CutPrefix(line, "policySHA256="); ok {
			digest = value
		}
	}
	if err != nil || !directoryLabDigest(digest) {
		f.t.Fatalf("Debian client DNS, Kerberos or SYSVOL check failed for %s: %v: %s", controller, err, out)
	}
	return directoryClientProof{Controller: controller, Address: address, PolicySHA256: digest}
}
