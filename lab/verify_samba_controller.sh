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
replica="$name-replica"
replica_addr=10.254.247.12
tenant=$(cat /proc/sys/kernel/random/uuid)
p() { nice -n 10 podman "$@"; }
cleanup() {
    p rm --force --ignore "$name" "$replica" >/dev/null
    p volume rm "$volume" "$replica" >/dev/null || true
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
    local container=$1 address=$2 controller=$3 id=$4
    shift 4
    p run --detach --name "$container" --network "$net" --ip "$address" --hostname "dc0$controller" \
       --memory 768m --pids-limit 128 --security-opt=no-new-privileges \
       --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=NET_BIND_SERVICE \
       --uidmap 0:0:1 --uidmap 1:1:60000 --uidmap 3000000:60001:5535 \
       --gidmap 0:0:1 --gidmap 1:1:60000 --gidmap 3000000:60001:5535 \
       --mount "type=volume,source=$container,target=/var/lib/ocean-ad" \
       --env OCEAN_AD_DNS_NAME=ad.runtime.test --env OCEAN_AD_NETBIOS_NAME=OCEANRUN \
       --env "OCEAN_AD_CONTROLLER=$controller" --env "OCEAN_AD_DIRECTORY_ID=$id" \
       --env "OCEAN_AD_ADDRESS=$address" "$@" "$image" >/dev/null
}
wait_dns() {
    local container=$1 address=$2 controller=$3 i
    for i in $(seq 1 60); do
        if ! p inspect -f '{{.State.Running}}' "$container" | grep -Fxq true; then
            p logs "$container" 2>&1 | tail -12 >&2
            exit 1
        fi
        if p run --rm --network "$net" --entrypoint /usr/bin/dig "$image" \
            +time=1 +tries=1 +short "@$address" SRV _ldap._tcp.dc._msdcs.ad.runtime.test |
            grep -F "389 dc0$controller.ad.runtime.test."; then
            return
        fi
        sleep 0.25
    done
    p logs "$container" 2>&1 | tail -12 >&2
    exit 1
}
proof() {
    p run --rm -i --network "$net" --entrypoint /bin/sh "$image" -c '
        set -eu
        address=$1
        host="dc0$2.ad.runtime.test"
        cache=$(mktemp -d)
        printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
            "[realms]" "AD.RUNTIME.TEST = {" "kdc = $address" "}" >"$cache/krb5.conf"
        printf "\n%s %s\n" "$address" "$host" >> /etc/hosts
        export KRB5_CONFIG="$cache/krb5.conf" KRB5CCNAME="FILE:$cache/ticket"
        kinit employee@AD.RUNTIME.TEST
        klist | grep -F krbtgt/AD.RUNTIME.TEST@AD.RUNTIME.TEST
        path="ad.runtime.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"
        smbclient "//$host/sysvol" -I "$address" --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "get $path $cache/gpt.ini"
        sha256sum "$cache/gpt.ini" | cut -d " " -f 1
        if smbclient "//$host/sysvol" -I "$address" --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "put $cache/gpt.ini $path" >"$cache/denied" 2>&1; then
            printf "Unprivileged employee could write policy\n" >&2
            exit 1
        fi
        grep -F NT_STATUS_ACCESS_DENIED "$cache/denied"
    ' -- "$@" <"$probe/employee.secret"
}
account() {
    p exec "$1" sh -c 'entry=$(find /var/lib/ocean-ad -path "*/etc/smb.conf"); samba-tool user show employee -s "$entry" |
      grep -E "^(objectSid|objectGUID):"'
}
same_policy() {
    local hash
    hash=$(grep -Ex '[a-f0-9]{64}' <<<"$1")
    test "$hash" = "$(grep -Ex '[a-f0-9]{64}' <<<"$2")"
}
start "$name" "$addr" 1 "$tenant"
for i in $(seq 1 40); do
    if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$name")" -ne 0
p rm "$name" >/dev/null
printf 'An initial bootstrap without its credential failed closed.\n'
start "$name" "$addr" 1 "$tenant" --secret "$secret,target=ocean-directory-bootstrap,mode=0400"
wait_dns "$name" "$addr" 1
p exec -i "$name" /usr/bin/python3 -c '
from pathlib import Path
from samba.netcmd.main import samba_tool
import sys
config = next(Path("/var/lib/ocean-ad").glob("controller-*/etc/smb.conf"))
sys.exit(samba_tool("user", "create", "employee", sys.stdin.readline().rstrip("\n"), "-s", str(config)))
' <"$probe/employee.secret"
original=$(account "$name")
printf '%s\n' "$original"
before=$(proof "$addr" 1)
printf '%s\n' "$before"
p stop --time 15 "$name" >/dev/null
p rm "$name" >/dev/null
start "$name" "$addr" 1 "$tenant"
wait_dns "$name" "$addr" 1
test "$original" = "$(account "$name")"
after=$(proof "$addr" 1)
printf '%s\n' "$after"
same_policy "$before" "$after"
printf 'Persistent controller reopened with identical employee SID and GUID without the bootstrap secret.\n'
p volume create "$replica" >/dev/null
start "$replica" "$replica_addr" 2 "$tenant" --env "OCEAN_AD_PRIMARY=$addr" \
    --secret "$secret,target=ocean-directory-bootstrap,mode=0400"
wait_dns "$replica" "$replica_addr" 2
test "$original" = "$(account "$replica")"
p stop --time 15 "$name" >/dev/null
p rm "$replica" --force >/dev/null
start "$replica" "$replica_addr" 2 "$tenant" --env "OCEAN_AD_PRIMARY=$addr"
wait_dns "$replica" "$replica_addr" 2
test "$original" = "$(account "$replica")"
replicated=$(proof "$replica_addr" 2)
printf '%s\n' "$replicated"
same_policy "$before" "$replicated"
printf 'The replica reopened without the bootstrap secret and served Kerberos and SYSVOL with the primary stopped.\n'
p start "$name" >/dev/null
wait_dns "$name" "$addr" 1
p stop --time 15 "$replica" >/dev/null
after=$(proof "$addr" 1)
same_policy "$before" "$after"
printf 'The primary served Kerberos and SYSVOL with the replica stopped.\n'
p stop --time 15 "$name" >/dev/null
p rm "$name" >/dev/null
start "$name" "$addr" 1 "$(cat /proc/sys/kernel/random/uuid)"
for i in $(seq 1 12); do
    if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$name")" -ne 0
p logs "$name" 2>&1 | grep -F 'Directory controller failed (ValueError).'
printf 'A different directory ID could not reuse the existing controller volume.\n'
