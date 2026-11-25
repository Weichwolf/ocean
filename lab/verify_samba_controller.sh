#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^sha256:[a-f0-9]{64}$ || ! ${2:-} =~ ^(--restore|--delegated-join|--hold-controller)?$ ]]; then
    printf 'Usage: %s sha256:<local-controller-image-id> [--restore|--delegated-join|--hold-controller]\n' "$0" >&2
    exit 2
fi
image=$1
if [[ ${2:-} == --delegated-join && ! ${OCEAN_E2E_ADCLI_IMAGE:-} =~ ^sha256:[a-f0-9]{64}$ ]]; then
    printf 'Set OCEAN_E2E_ADCLI_IMAGE to the local Debian join client image ID.\n' >&2
    exit 2
fi
if [[ ${2:-} == --hold-controller && ${OCEAN_E2E_DIRECTORY_HANDOFF:-} != /* ]]; then
    printf 'Set OCEAN_E2E_DIRECTORY_HANDOFF to a file in the private fixture directory.\n' >&2
    exit 2
fi
umask 077
probe=$(mktemp -d)
name="ocean-directory-test-${probe##*.}"

net=$name
volume=$name
secret=$name
addr=10.254.247.11
replica="$name-replica"
replica_addr=10.254.247.12
empty_primary="$name-empty"
replacement="$name-replacement"
recovered="$name-recovered"
expected_sid=""
tenant=$(cat /proc/sys/kernel/random/uuid)
p() { nice -n 10 podman "$@"; }
cleanup() {
    local storage
    p rm --force --ignore "$name" "$replica" "$empty_primary" "$replacement" "$recovered" >/dev/null
    for storage in "$volume" "$replica" "$empty_primary" "$replacement" "$recovered"; do
        if p volume exists "$storage"; then
            p volume rm "$storage" >/dev/null || true
        fi
    done
    p network rm "$net" >/dev/null || true
    p secret rm "$secret" >/dev/null || true
    rm -rf -- "$probe"
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
    p run --detach --name "$container" --network "$net" --ip "$address" --hostname "${controller_host:-dc0$controller}" \
       --memory 768m --pids-limit 128 --security-opt=no-new-privileges \
       --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=NET_BIND_SERVICE \
       --uidmap 0:0:1 --uidmap 1:1:60000 --uidmap 3000000:60001:5535 \
       --gidmap 0:0:1 --gidmap 1:1:60000 --gidmap 3000000:60001:5535 \
       --tmpfs /run/ocean-directory-startup:rw,mode=0700 \
       --mount "type=volume,source=$container,target=/var/lib/ocean-ad" \
       --env OCEAN_AD_DNS_NAME=ad.runtime.test --env OCEAN_AD_NETBIOS_NAME=OCEANRUN \
       --env "OCEAN_AD_CONTROLLER=$controller" --env "OCEAN_AD_DIRECTORY_ID=$id" \
       --env OCEAN_AD_REQUIRE_AUTHORIZATION=1 --env "OCEAN_AD_EXPECTED_SID=$expected_sid" \
       --env "OCEAN_AD_REPLICA=$replica_addr" \
       --env "OCEAN_AD_ADDRESS=$address" "$@" "$image" >/dev/null
}
wait_dns() {
    local container=$1 address=$2 controller=$3 i offer sid challenge
    local host=${4:-dc0$controller}
    for i in $(seq 1 60); do
        if ! p inspect -f '{{.State.Running}}' "$container" | grep -Fxq true; then
            p logs "$container" 2>&1 | tail -12 >&2
            p cp "$container:/var/log/samba/log.winbindd" - 2>/dev/null | tar -xO 2>/dev/null | tail -12 >&2 || true
            exit 1
        fi
        if offer=$(p exec "$container" /usr/bin/python3 /usr/local/lib/ocean-directory/controller.py startup-identity 2>/dev/null); then
            read -r sid challenge <<<"$offer"
            if [[ -z "$expected_sid" ]]; then
                [[ "$controller" == 1 ]]
                expected_sid=$sid
            fi
            [[ "$expected_sid" == "$sid" ]]
            if p run --rm --network "$net" --entrypoint /usr/bin/dig "$image" \
                +time=1 +tries=1 +short "@$address" SRV _ldap._tcp.dc._msdcs.ad.runtime.test |
                grep -qF "389 $host.ad.runtime.test."; then
                printf 'The controller exposed DNS before startup authorization.\n' >&2
                return 1
            fi
            p exec "$container" /usr/bin/python3 /usr/local/lib/ocean-directory/controller.py authorize-startup "$sid" "$challenge"
            printf 'Authorized the persisted SID for controller %s after verifying that DNS was closed.\n' "$controller"
        fi
        if p run --rm --network "$net" --entrypoint /usr/bin/dig "$image" \
            +time=1 +tries=1 +short "@$address" SRV _ldap._tcp.dc._msdcs.ad.runtime.test |
            grep -F "389 $host.ad.runtime.test."; then
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
        host="${4:-dc0$2}.ad.runtime.test"
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
            if [ "$2" = 1 ] && [ -z "${4:-}" ]; then
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
    local host=${4:-dc0$2}
    p run --rm -i --network "$net" --entrypoint /bin/sh "$image" -c '
        set -eu
        umask 077
        address=$1
        host="$2.ad.runtime.test"
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
    ' -- "$1" "$host" "$3" "$employee_sid" <"$probe/administrator.secret"
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
debian_join() {
    bash "$(dirname -- "$0")/run_adcli_probe.sh" "$OCEAN_E2E_ADCLI_IMAGE" "$net" "$addr" "$1" "$2"
}

join_request() {
    local action=$1 request=$2 machine=$3 expires=$4 payload=${5:-}
    printf '{"requestId":"%s","machineName":"%s","expiresAt":%s%s}\n' "$request" "$machine" "$expires" "$payload" |
        p exec -i "$name" /usr/bin/python3 /usr/local/lib/ocean-directory/controller.py "$action"
}

join_user() {
    python3 -c 'import json,sys; print(json.load(sys.stdin)["userPrincipalName"].split("@")[0])'
}

verify_delegated_join() {
    local first_id second_id expires password field receipt user sid probe_acl sweep started
    first_id=$(cat /proc/sys/kernel/random/uuid)
    second_id=$(cat /proc/sys/kernel/random/uuid)
    expires=$(($(date +%s) + 180))
    password="Join9-$(openssl rand -hex 27)"
    field=',"password":"'"$password"'"'
    receipt=$(join_request stage-join "$first_id" OCEANJOIN "$expires" "$field")
    test "$receipt" = "$(join_request stage-join "$first_id" OCEANJOIN "$expires" "$field")"
    user=$(join_user <<<"$receipt")
    sid=$(directory_tool "$name" user show "$user" --attributes=objectSid | awk '$1 == "objectSid:" { print $2 }')
    probe_acl='CN=OCEANJOIN,CN=Computers,DC=ad,DC=runtime,DC=test'
    directory_tool "$name" dsacl get --objectdn="$probe_acl" | grep -Fq "$sid"
    if join_request stage-join "$second_id" OCEANJOIN "$expires" "$field" >/dev/null 2>&1; then
        printf 'A different request adopted the prestaged computer.\n' >&2
        return 1
    fi
    directory_tool "$name" computer add OTHERPC
    local machine
    for machine in OTHERPC FRESHPC; do
        if debian_join "$machine" "$user" <<<"$password" >"$probe/denied-join.log" 2>&1; then
            printf 'The join principal was accepted for %s.\n' "$machine" >&2
            return 1
        fi
        grep -Ei 'access denied|insufficient (access|permissions)' "$probe/denied-join.log"
    done
    printf 'A valid delegated credential could neither reset another computer nor create a new one.\n'
    debian_join OCEANJOIN "$user" <<<"$password"
    if join_request stage-join "$first_id" OCEANJOIN "$expires" "$field" >/dev/null 2>&1; then
        printf 'The used authorization was staged again.\n' >&2
        return 1
    fi
    join_request close-join "$first_id" OCEANJOIN "$expires" >/dev/null
    join_request close-join "$first_id" OCEANJOIN "$expires" >/dev/null
    if debian_join OCEANJOIN "$user" <<<"$password" >"$probe/reused-join.log" 2>&1; then
        printf 'The closed authorization was reused.\n' >&2
        return 1
    fi
    grep -F 'credentials have been revoked' "$probe/reused-join.log"
    if directory_tool "$name" dsacl get --objectdn="$probe_acl" | grep -Fq "$sid"; then
        printf 'The revoked credential retained an explicit ACL.\n' >&2
        return 1
    fi
    printf 'Debian verified machine trust. Closing the authorization revoked the login and removed its ACEs.\n'

    expires=$(($(date +%s) + 12))
    receipt=$(join_request stage-join "$second_id" EXPIREDPC "$expires" "$field")
    user=$(join_user <<<"$receipt")
    sid=$(directory_tool "$name" user show "$user" --attributes=objectSid | awk '$1 == "objectSid:" { print $2 }')
    debian_join authenticate "$user" <<<"$password"
    sleep "$(( expires - $(date +%s) + 1 ))"
    if debian_join authenticate "$user" <<<"$password" >"$probe/expired-join.log" 2>&1; then
        printf 'The expired account could still get a new ticket.\n' >&2
        return 1
    fi
    grep -Ei 'credentials have been revoked|entry in database has expired|client.*expired' "$probe/expired-join.log"
    probe_acl='CN=EXPIREDPC,CN=Computers,DC=ad,DC=runtime,DC=test'
    started=$SECONDS
    while true; do
        sweep=$(directory_tool "$name" dsacl get --objectdn="$probe_acl")
        if ! grep -Fq "$sid" <<<"$sweep"; then
            break
        fi
        if (( SECONDS - started >= 15 )); then
            printf 'The expiration worker did not remove the delegated ACEs.\n' >&2
            return 1
        fi
        sleep 1
    done
    printf 'Kerberos refused the expired principal and the controller removed its ACEs in %d seconds after the refusal.\n' \
        "$(( SECONDS - started ))"
}

machine_trust() {
    p run --rm -i --network "$net" --hostname oceanmember \
        --mount "type=bind,source=$probe/member,target=/member" \
        --entrypoint /bin/sh "$image" -c '
        set -eu
        umask 077
        addr=$1 host=$2 action=$3
        printf "nameserver %s\noptions timeout:1 attempts:2\n" "$addr" >/etc/resolv.conf
        mkdir -p /member/private /member/state /member/cache
        printf "%s\n" "[global]" "security = ADS" "workgroup = OCEANRUN" "realm = AD.RUNTIME.TEST" \
            "netbios name = OCEANMEMBER" "private dir = /member/private" "state directory = /member/state" \
            "cache directory = /member/cache" >/member/smb.conf
        if [ "$action" = join ]; then
            ticket=$(mktemp -d)
            export KRB5_CONFIG="$ticket/krb5.conf" KRB5CCNAME="FILE:$ticket/cache"
            printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
                "[realms]" "AD.RUNTIME.TEST = {" "kdc = $addr" "}" >"$KRB5_CONFIG"
            timeout 10 kinit Administrator@AD.RUNTIME.TEST
            timeout 20 net ads join -s /member/smb.conf -S "$host" --no-dns-updates \
                --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME"
        else
            timeout 15 net ads testjoin -s /member/smb.conf -S "$host"
        fi
    ' -- "$@" <"$probe/administrator.secret"
}
verify_independent_restore() {
    local start_time=$SECONDS checksum restored machine
    local join_id join_expiry join_password join_fields join_receipt pending_user pending_sid flags
    local recovery_name=dc-recovery
    local path=/usr/local/lib/ocean-directory/controller.py
    mkdir "$probe/member"
    machine_trust "$addr" dc01.ad.runtime.test join
    machine_trust "$addr" dc01.ad.runtime.test test
    machine=$(directory_tool "$name" computer show OCEANMEMBER | grep '^objectGUID:')
    join_id=$(cat /proc/sys/kernel/random/uuid)
    join_expiry=$(($(date +%s) + 240))
    join_password="Join9-$(openssl rand -hex 27)"
    join_fields=',"password":"'"$join_password"'"'
    join_receipt=$(join_request stage-join "$join_id" RESTOREJOIN "$join_expiry" "$join_fields")
    pending_user=$(join_user <<<"$join_receipt")
    pending_sid=$(directory_tool "$name" user show "$pending_user" --attributes=objectSid | awk '$1 == "objectSid:" { print $2 }')
    directory_tool "$name" dsacl get --objectdn='CN=RESTOREJOIN,CN=Computers,DC=ad,DC=runtime,DC=test' | grep -Fq "$pending_sid"
    openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj '/CN=Ocean disposable backup probe' \
        -keyout "$probe/backup.key" -out "$probe/backup.crt" 2>"$probe/key.log"
    if ! p exec -i "$name" /usr/bin/python3 "$path" backup-domain \
            <"$probe/administrator.secret" >"$probe/backup.tar" 2>"$probe/backup.log"; then
        tail -25 "$probe/backup.log" >&2
        return 1
    fi
    checksum=$(sha256sum "$probe/backup.tar" | cut -d' ' -f1)
    openssl cms -encrypt -aes-256-gcm -binary -in "$probe/backup.tar" -outform DER \
        -out "$probe/backup.cms" "$probe/backup.crt"
    rm -- "$probe/backup.tar"
    printf 'Captured and encrypted the AD database and verified SYSVOL ACL backup in %d seconds.\n' \
        "$(( SECONDS - start_time ))"

    p rm --force "$name" "$replica" >/dev/null
    p volume rm "$volume" "$replica" >/dev/null
    printf 'Removed both original controller containers and their private state volumes.\n'
    p volume create "$recovered" >/dev/null
    local restore=(
        run --rm -i --network none --hostname "$recovery_name" --memory 768m --pids-limit 128
        --security-opt=no-new-privileges --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID
        --uidmap 0:0:1 --uidmap 1:1:60000 --uidmap 3000000:60001:5535
        --gidmap 0:0:1 --gidmap 1:1:60000 --gidmap 3000000:60001:5535
        --mount "type=volume,source=$recovered,target=/var/lib/ocean-ad"
        --env OCEAN_AD_DNS_NAME=ad.runtime.test --env OCEAN_AD_NETBIOS_NAME=OCEANRUN
        --env "OCEAN_AD_DIRECTORY_ID=$tenant" --env "OCEAN_AD_EXPECTED_SID=$domain_sid"
        --env "OCEAN_AD_ADDRESS=$addr" --env "OCEAN_AD_RECOVERY_NAME=$recovery_name" "$image" restore-domain
    )
    openssl cms -decrypt -binary -inform DER -recip "$probe/backup.crt" -inkey "$probe/backup.key" \
        -in "$probe/backup.cms" -out "$probe/backup.tar"
    if printf 'corrupt' | p "${restore[@]}" "$checksum" >"$probe/invalid-restore.log" 2>&1; then
        printf 'The restore accepted a corrupt archive.\n' >&2
        return 1
    fi
    start_time=$SECONDS
    if ! p "${restore[@]}" "$checksum" <"$probe/backup.tar" >"$probe/restore.log" 2>&1; then
        tail -35 "$probe/restore.log" >&2
        return 1
    fi
    rm -- "$probe/backup.tar"
    controller_host=$recovery_name start "$recovered" "$addr" 1 "$tenant" \
        --env "OCEAN_AD_RECOVERY_NAME=$recovery_name" --env OCEAN_AD_REQUIRE_AUTHORIZATION=0
    test "$(p wait "$recovered")" -ne 0
    p logs "$recovered" 2>&1 | grep -F 'Directory controller failed (DirectoryIdentityError).'
    p rm "$recovered" >/dev/null
    controller_host=$recovery_name start "$recovered" "$addr" 1 "$tenant" \
        --env "OCEAN_AD_RECOVERY_NAME=$recovery_name" --env OCEAN_AD_REPLICA=
    wait_dns "$recovered" "$addr" 1 "$recovery_name"
    wait_health "$recovered" "$domain_sid"
    test "$original" = "$(account "$recovered")"
    test "$machine" = "$(directory_tool "$recovered" computer show OCEANMEMBER | grep '^objectGUID:')"
    machine_trust "$addr" "$recovery_name.ad.runtime.test" test
    test "$(date +%s)" -lt "$join_expiry"
    flags=$(directory_tool "$recovered" user show "$pending_user" --attributes=userAccountControl |
        awk '$1 == "userAccountControl:" { print $2 }')
    (( flags & 2 ))
    if directory_tool "$recovered" dsacl get --objectdn='CN=RESTOREJOIN,CN=Computers,DC=ad,DC=runtime,DC=test' |
            grep -Fq "$pending_sid"; then
        printf 'Recovery restored the outstanding authorization ACL.\n' >&2
        return 1
    fi
    printf 'Recovery revoked the outstanding join account and removed its ACEs before their original deadline.\n'
    wait_membership "$recovered" LabPrimaryGroup employee "$SECONDS"
    wait_membership "$recovered" LabReplicaGroup employee "$SECONDS"
    test "$(gpo_version "$recovered")" = 1
    restored=$(proof "$addr" 1 guarded "$recovery_name")
    same_policy "$changed" "$restored"
    test "$expected_acl" = "$(administrator_policy "$addr" 1 read "$recovery_name")"
    printf 'Recovered the original SID, employee and machine GUIDs, machine trust, memberships, GPO version, contents and ACL in %d seconds.\n' \
        "$(( SECONDS - start_time ))"
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
if [[ ${2:-} == --hold-controller ]]; then
    printf '%s %s %s %s\n' "$name" "$net" "$addr" "$domain_sid" >"$OCEAN_E2E_DIRECTORY_HANDOFF.pending"
    mv -- "$OCEAN_E2E_DIRECTORY_HANDOFF.pending" "$OCEAN_E2E_DIRECTORY_HANDOFF"
    read -r _ || true
    exit
fi
if [[ ${2:-} == --delegated-join ]]; then
    verify_delegated_join
    exit
fi
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
if [[ ${2:-} == --restore ]]; then
    verify_independent_restore
    exit
fi
p stop --time 15 "$name" >/dev/null
p volume create "$empty_primary" >/dev/null
start "$empty_primary" "$addr" 1 "$tenant" --secret "$secret,target=ocean-directory-bootstrap,mode=0400"
for i in $(seq 1 40); do
    if ! p inspect -f '{{.State.Running}}' "$empty_primary" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$empty_primary")" -ne 0
p logs "$empty_primary" 2>&1 | grep -F 'Directory controller failed (DirectoryIdentityError).'
mountpoint=$(p volume inspect -f '{{.Mountpoint}}' "$empty_primary")
test -z "$(p unshare find "$mountpoint" -maxdepth 1 -name 'controller-*' -print)"
p rm "$empty_primary" >/dev/null
printf 'An empty primary volume could not create a second domain even with the original bootstrap password.\n'
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
old_account=$(directory_tool "$replica" computer show DC02 | grep '^objectGUID:')
p stop --time 15 "$replica" >/dev/null
wait_health "$name" "$domain_sid"
after=$(proof "$addr" 1 guarded)
same_policy "$changed" "$after"
printf 'The primary served Kerberos and SYSVOL with the replica stopped.\n'
p rm "$replica" >/dev/null
retired_generation=$(cat /proc/sys/kernel/random/uuid)
retire_replica() {
    p exec "$name" /usr/bin/python3 /usr/local/lib/ocean-directory/controller.py retire-replica "$retired_generation"
}
retire_replica
retire_replica
p volume create "$replacement" >/dev/null
replacement_started=$SECONDS
start "$replacement" "$replica_addr" 2 "$tenant" --env "OCEAN_AD_PRIMARY=$addr" \
    --secret "$secret,target=ocean-directory-bootstrap,mode=0400"
wait_dns "$replacement" "$replica_addr" 2
wait_health "$replacement" "$domain_sid"
retire_replica
test "$old_account" != "$(directory_tool "$replacement" computer show DC02 | grep '^objectGUID:')"
test "$original" = "$(account "$replacement")"
test "$(gpo_version "$replacement")" = 1
test "$expected_acl" = "$(administrator_policy "$replica_addr" 2 read)"
wait_membership "$replacement" LabReplicaGroup employee "$SECONDS"
p stop --time 15 "$name" >/dev/null
recovered=$(proof "$replica_addr" 2 guarded)
same_policy "$changed" "$recovered"
printf 'A new replica with an empty volume recovered the established domain, employee identity, GPO contents and ACL in %d seconds.\n' \
    "$(( SECONDS - replacement_started ))"
p rm "$name" >/dev/null
start "$name" "$addr" 1 "$(cat /proc/sys/kernel/random/uuid)"
for i in $(seq 1 12); do
    if ! p inspect -f '{{.State.Running}}' "$name" | grep -Fxq true; then break; fi
    sleep 0.25
done
test "$(p inspect -f '{{.State.ExitCode}}' "$name")" -ne 0
p logs "$name" 2>&1 | grep -F 'Directory controller failed (ValueError).'
printf 'A different directory ID could not reuse the existing controller volume.\n'
