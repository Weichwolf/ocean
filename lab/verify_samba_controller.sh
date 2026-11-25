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
    rm -f "$probe/employee.secret" "$probe/administrator.secret"
    rmdir "$probe"
}
trap cleanup EXIT
p network create --internal --disable-dns --subnet 10.254.247.0/24 "$net" >/dev/null
p volume create "$volume" >/dev/null
printf 'Ocn9-%s\n' "$(openssl rand -hex 20)" >"$probe/administrator.secret"
p secret create "$secret" "$probe/administrator.secret" >/dev/null
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
       --env "OCEAN_AD_REPLICA=$replica_addr" \
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
wait_health() {
    local container=$1 expected=$2 started=$SECONDS sid
    until sid=$(p exec "$container" /usr/bin/timeout 3 /usr/bin/python3 \
            /usr/local/lib/ocean-directory/controller.py health) && [[ "$sid" == "$expected" ]]; do
        if (( SECONDS - started >= 15 )); then
            p logs "$container" 2>&1 | tail -12 >&2
            return 1
        fi
        sleep 1
    done
    printf '%s verified its DNS, Kerberos-authenticated LDAP, and domain SID after %d seconds.\n' \
        "$container" "$(( SECONDS - started ))"
}
proof() {
    p run --rm -i --network "$net" --entrypoint /bin/sh "$image" -c '
        set -eu
        address=$1
        host="dc0$2.ad.runtime.test"
        cache=$(mktemp -d)
        printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
            "dns_lookup_kdc = true" "udp_preference_limit = 1" >"$cache/krb5.conf"
        printf "nameserver %s\noptions timeout:1 attempts:2\n" "$address" > /etc/resolv.conf
        test "$(dig +time=1 +tries=1 +short "$host" A)" = "$address"
        export KRB5_CONFIG="$cache/krb5.conf" KRB5CCNAME="FILE:$cache/ticket"
        timeout 10 kinit employee@AD.RUNTIME.TEST
        klist | grep -F krbtgt/AD.RUNTIME.TEST@AD.RUNTIME.TEST
        path="ad.runtime.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI"
        smbclient "//$host/sysvol" --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "get $path $cache/gpt.ini"
        sha256sum "$cache/gpt.ini" | cut -d " " -f 1
        if smbclient "//$host/sysvol" --use-kerberos=required \
            --use-krb5-ccache="$KRB5CCNAME" -c "put $cache/gpt.ini $path" >"$cache/denied" 2>&1; then
            printf "Unprivileged employee could write policy\n" >&2
            exit 1
        fi
        grep -F NT_STATUS_ACCESS_DENIED "$cache/denied"
        if [ "${3:-}" = guarded ]; then
            if smbclient "//$host/sysvol" --use-kerberos=required \
                --use-krb5-ccache="$KRB5CCNAME" -c "get ${path%/*}/ocean-guarded.txt $cache/guarded" \
                >"$cache/guard" 2>&1; then
                printf "Unprivileged employee could read guarded policy content\n" >&2
                exit 1
            fi
            grep -F NT_STATUS_ACCESS_DENIED "$cache/guard"
            if [ "$2" = 1 ]; then
                if smbclient "//$host/ocean-policy$" --use-kerberos=required --client-protection=encrypt \
                    --use-krb5-ccache="$KRB5CCNAME" -c "get sysvol.tar.gz $cache/export" >"$cache/exported" 2>&1; then
                    printf "Unprivileged employee could read the replication archive\n" >&2
                    exit 1
                fi
                grep -F NT_STATUS_ACCESS_DENIED "$cache/exported"
            fi
        fi
    ' -- "$@" <"$probe/employee.secret"
}
administrator_policy() {
    p run --rm -i --network "$net" --entrypoint /bin/sh "$image" -c '
        set -eu
        umask 077
        address=$1
        host="dc0$2.ad.runtime.test"
        action=$3
        employee_sid=$4
        cache=$(mktemp -d)
        printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
            "[realms]" "AD.RUNTIME.TEST = {" "kdc = $address" "}" >"$cache/krb5.conf"
        printf "nameserver %s\noptions timeout:1 attempts:2\n" "$address" > /etc/resolv.conf
        export KRB5_CONFIG="$cache/krb5.conf" KRB5CCNAME="FILE:$cache/ticket"
        timeout 10 kinit Administrator@AD.RUNTIME.TEST >&2
        gpo="{31B2F340-016D-11D2-945F-00C04FB984F9}"
        guarded="ad.runtime.test/Policies/$gpo/ocean-guarded.txt"
        smb="//${host}/sysvol"
        if [ "$action" = update ]; then
            printf "[General]\r\nVersion=1\r\n" > "$cache/gpt.ini"
            printf "Protected fixture policy data\n" > "$cache/guarded.txt"
            smbclient "$smb" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" \
                -c "put $cache/gpt.ini ${guarded%/*}/GPT.INI; put $cache/guarded.txt $guarded"
            smbcacls "$smb" "$guarded" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" \
                --add "ACL:$employee_sid:DENIED/0x0/READ"
        elif [ "$action" = read-only ]; then
            printf "[General]\r\nVersion=1\r\n" > "$cache/gpt.ini"
            if smbclient "$smb" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" \
                -c "put $cache/gpt.ini ${guarded%/*}/GPT.INI" >"$cache/write" 2>&1; then
                printf "The replica permitted a policy write\n" >&2
                exit 1
            fi
            grep -E "NT_STATUS_(ACCESS_DENIED|MEDIA_WRITE_PROTECTED)" "$cache/write"
        else
            smbcacls "$smb" "$guarded" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" \
                --query-security-info=7 --numeric --sddl
        fi
    ' -- "$@" "$employee_sid" <"$probe/administrator.secret"
}
gpo_version() {
    p exec -i "$1" /usr/bin/python3 - "${2:-}" <<'PY'
from pathlib import Path
import sys
import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

config = next(Path("/var/lib/ocean-ad").glob("controller-*/etc/smb.conf"))
lp = LoadParm()
lp.load(str(config))
database = SamDB(lp=lp, session_info=system_session())
gpo = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + str(database.domain_dn())
if sys.argv[1]:
    change = ldb.Message()
    change.dn = ldb.Dn(database, gpo)
    change["versionNumber"] = ldb.MessageElement(sys.argv[1], ldb.FLAG_MOD_REPLACE, "versionNumber")
    database.modify(change)
entry, = database.search(base=gpo, scope=ldb.SCOPE_BASE, attrs=["versionNumber"])
print(entry["versionNumber"][0].decode())
PY
}
directory_tool() {
    local controller=$1
    shift
    p exec "$controller" sh -ec '
        entry=$(find /var/lib/ocean-ad -path "*/etc/smb.conf")
        export KRB5_CONFIG="${entry%/etc/smb.conf}/private/krb5.conf"
        exec samba-tool "$@" -s "$entry"
    ' -- "$@"
}
account() {
    directory_tool "$1" user show employee | grep -E "^(objectSid|objectGUID):"
}
wait_membership() {
    local controller=$1 group=$2 expected=$3 started=$4 members
    while (( SECONDS - started < 45 )); do
        if members=$(directory_tool "$controller" group listmembers "$group" 2>/dev/null) && [[ "$members" == "$expected" ]]; then
            printf '%s replicated on %s in %d seconds (members: %s).\n' \
                "$group" "$controller" "$(( SECONDS - started ))" "${expected:-empty}"
            return
        fi
        sleep 1
    done
    printf 'Group membership failed to converge on %s for %s within 45 seconds.\n' "$controller" "$group" >&2
    directory_tool "$controller" drs showrepl -P >&2 || true
    return 1
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
employee_sid=$(awk '$1 == "objectSid:" { print $2 }' <<<"$original")
domain_sid=${employee_sid%-*}
wait_health "$name" "$domain_sid"
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
directory_tool "$name" group add LabPrimaryGroup
directory_tool "$name" group addmembers LabPrimaryGroup employee
wait_membership "$replica" LabPrimaryGroup employee "$SECONDS"
directory_tool "$replica" group add LabReplicaGroup
directory_tool "$replica" group addmembers LabReplicaGroup employee
wait_membership "$name" LabReplicaGroup employee "$SECONDS"
administrator_policy "$addr" 1 update
test "$(gpo_version "$name" 1)" = 1
policy_started=$SECONDS
expected_acl=$(administrator_policy "$addr" 1 read)
grep -Fq "$employee_sid" <<<"$expected_acl"
changed=$(proof "$addr" 1 guarded)
if same_policy "$before" "$changed"; then
    printf 'The fixture GPO did not change on the primary.\n' >&2
    exit 1
fi
while (( SECONDS - policy_started < 65 )); do
    if [[ "$(gpo_version "$replica")" == 1 ]] &&
       updated=$(proof "$replica_addr" 2 guarded 2>/dev/null) && same_policy "$changed" "$updated" &&
       replicated_acl=$(administrator_policy "$replica_addr" 2 read 2>/dev/null) &&
       [[ "$replicated_acl" == "$expected_acl" ]]; then
        break
    fi
    sleep 2
done
if (( SECONDS - policy_started >= 65 )); then
    p logs "$replica" 2>&1 | tail -28 >&2
    printf 'Updated GPO and its custom ACL did not converge in 65 seconds.\n' >&2
    exit 1
fi
printf 'Updated GPO bytes and custom ACL replicated in %d seconds.\n' "$(( SECONDS - policy_started ))"
p stop --time 15 "$name" >/dev/null
p rm "$replica" --force >/dev/null
start "$replica" "$replica_addr" 2 "$tenant" --env "OCEAN_AD_PRIMARY=$addr"
wait_dns "$replica" "$replica_addr" 2
wait_health "$replica" "$domain_sid"
test "$original" = "$(account "$replica")"
replicated=$(proof "$replica_addr" 2 guarded)
printf '%s\n' "$replicated"
same_policy "$changed" "$replicated"
test "$expected_acl" = "$(administrator_policy "$replica_addr" 2 read)"
test "$(gpo_version "$replica")" = 1
administrator_policy "$replica_addr" 2 read-only
printf 'The replica reopened without the bootstrap secret and served Kerberos and SYSVOL with the primary stopped.\n'
directory_tool "$replica" group removemembers LabPrimaryGroup employee
recovery_started=$SECONDS
p start "$name" >/dev/null
wait_dns "$name" "$addr" 1
wait_membership "$name" LabPrimaryGroup "" "$recovery_started"
p stop --time 15 "$replica" >/dev/null
wait_health "$name" "$domain_sid"
after=$(proof "$addr" 1 guarded)
same_policy "$changed" "$after"
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
