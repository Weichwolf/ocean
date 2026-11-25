#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || ! $1 =~ ^sha256:[a-f0-9]{64}$ ]]; then
    printf 'Usage: %s sha256:<local-controller-image-id>\n' "$0" >&2
    exit 2
fi
image=$1
umask 077
probe=$(mktemp -d)
name="ocean-directory-test-${probe##*.}"

net=$name
volume=$name
secret=$name
addr=10.254.247.11
tenant=$(cat /proc/sys/kernel/random/uuid)
p() { nice -n 10 podman "$@"; }
cleanup() {
    p rm --force --ignore "$name" >/dev/null
    p volume rm "$volume" >/dev/null || true
    p network rm "$net" >/dev/null || true
    p secret rm "$secret" >/dev/null || true
    rm -f "$probe/employee.secret"
    rmdir "$probe"
}
trap cleanup EXIT
p network create --internal --disable-dns --subnet 10.254.247.0/24 "$net" >/dev/null
p volume create "$volume" >/dev/null
printf 'Ocn9-%s\n' "$(openssl rand -hex 20)" | p secret create "$secret" - >/dev/null
printf 'Tst9-%s\n' "$(openssl rand -hex 20)" >"$probe/employee.secret"
start() {
    local id=$1
    shift
    p run --detach --name "$name" --network "$net" --ip "$addr" --hostname dc01 \
       --memory 768m --pids-limit 128 --security-opt=no-new-privileges \
       --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=NET_BIND_SERVICE \
       --uidmap 0:0:1 --uidmap 1:1:60000 --uidmap 3000000:60001:5535 \
       --gidmap 0:0:1 --gidmap 1:1:60000 --gidmap 3000000:60001:5535 \
       --mount "type=volume,source=$volume,target=/var/lib/ocean-ad" \
       --env OCEAN_AD_DNS_NAME=ad.runtime.test --env OCEAN_AD_NETBIOS_NAME=OCEANRUN \
       --env "OCEAN_AD_DIRECTORY_ID=$id" --env "OCEAN_AD_ADDRESS=$addr" "$@" "$image" >/dev/null
}
wait_dns() {
    local i
    for i in $(seq 1 60); do
        if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then
            p logs "$name" 2>&1 | tail -12 >&2
            exit 1
        fi
        if p run --rm --network "$net" --entrypoint /usr/bin/dig "$image" \
            +time=1 +tries=1 +short "@$addr" SRV _ldap._tcp.dc._msdcs.ad.runtime.test | grep -F '389 dc01.ad.runtime.test.'; then
            return
        fi
        sleep 0.25
    done
    p logs "$name" 2>&1 | tail -12 >&2
    exit 1
}
proof() {
    p run --rm -i --network "$net" --entrypoint /bin/sh "$image" -c '
        set -eu
        cache=$(mktemp -d)
        printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "[realms]" "AD.RUNTIME.TEST = {" \
            "kdc = 10.254.247.11" "}" >"$cache/krb5.conf"
        printf "\n10.254.247.11 dc01.ad.runtime.test dc01\n" >> /etc/hosts
        export KRB5_CONFIG="$cache/krb5.conf" KRB5CCNAME="FILE:$cache/ticket"
        kinit employee@AD.RUNTIME.TEST
        klist | grep -F krbtgt/AD.RUNTIME.TEST@AD.RUNTIME.TEST
        path="ad.runtime.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"
        smbclient //dc01.ad.runtime.test/sysvol -I 10.254.247.11 --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "get $path $cache/gpt.ini"
        sha256sum "$cache/gpt.ini" | cut -d " " -f 1
        if smbclient //dc01.ad.runtime.test/sysvol -I 10.254.247.11 --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "put $cache/gpt.ini $path" >"$cache/denied" 2>&1; then
            printf "Unprivileged employee could write policy\n" >&2
            exit 1
        fi
        grep -F NT_STATUS_ACCESS_DENIED "$cache/denied"
    ' <"$probe/employee.secret"
}
account() {
    p exec "$name" sh -c 'entry=$(find /var/lib/ocean-ad -path "*/etc/smb.conf"); samba-tool user show employee -s "$entry" |
      grep -E "^(objectSid|objectGUID):"'
}
start "$tenant"
for i in $(seq 1 40); do
    if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$name")" -ne 0
p rm "$name" >/dev/null
printf 'An initial bootstrap without its credential failed closed.\n'
start "$tenant" --secret "$secret,target=ocean-directory-bootstrap,mode=0400"
wait_dns
p exec -i "$name" /usr/bin/python3 -c '
from pathlib import Path
from samba.netcmd.main import samba_tool
import sys
config = next(Path("/var/lib/ocean-ad").glob("controller-*/etc/smb.conf"))
sys.exit(samba_tool("user", "create", "employee", sys.stdin.readline().rstrip("\n"), "-s", str(config)))
' <"$probe/employee.secret"
original=$(account)
printf '%s\n' "$original"
before=$(proof)
printf '%s\n' "$before"
p stop --time 15 "$name" >/dev/null
p rm "$name" >/dev/null
start "$tenant"
wait_dns
test "$original" = "$(account)"
after=$(proof)
printf '%s\n' "$after"
test "$(grep -Ex '[a-f0-9]{64}' <<<"$before")" = "$(grep -Ex '[a-f0-9]{64}' <<<"$after")"
printf 'Persistent controller reopened with identical employee SID and GUID without the bootstrap secret.\n'
p stop --time 15 "$name" >/dev/null
p rm "$name" >/dev/null
start "$(cat /proc/sys/kernel/random/uuid)"
for i in $(seq 1 12); do
    if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$name")" -ne 0
p logs "$name" 2>&1 | grep -F 'Directory controller failed (ValueError).'
printf 'A different directory ID could not reuse the existing controller volume.\n'
