#!/usr/bin/env bash
set -euo pipefail

image=$1 network=$2 address=$3
nice -n 10 podman run --rm -i --network "$network" --entrypoint /bin/sh "$image" -c '
    set -eu
    umask 077
    cache=$(mktemp -d)
    printf "nameserver %s\noptions timeout:1 attempts:2\n" "$1" >/etc/resolv.conf
    export KRB5_CONFIG="$cache/krb5.conf" KRB5CCNAME="FILE:$cache/ticket"
    printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
        "[realms]" "AD.RUNTIME.TEST = {" "kdc = $1" "}" >"$KRB5_CONFIG"
    timeout 10 kinit marine@AD.RUNTIME.TEST
    timeout 12 smbclient //dc01.ad.runtime.test/ocean-group-probe --use-kerberos=required \
        --use-krb5-ccache="$KRB5CCNAME" -c "get probe.txt $cache/probe"
    grep -Fx "Ocean restricted group file" "$cache/probe"
' -- "$address"
