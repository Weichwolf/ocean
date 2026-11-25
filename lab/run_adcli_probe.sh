#!/usr/bin/env bash
set -euo pipefail

image=$1 network=$2 address=$3 machine=$4 user=$5
nice -n 10 podman run --rm -i --network "$network" --entrypoint /bin/bash "$image" -c '
        set -euo pipefail
        umask 077
        printf "nameserver %s\noptions timeout:1 attempts:2\n" "$1" >/etc/resolv.conf
        private=$(mktemp -d)
        export KRB5_CONFIG="$private/krb5.conf" KRB5CCNAME="FILE:$private/ticket"
        printf "%s\n" "[libdefaults]" "default_realm = AD.RUNTIME.TEST" "rdns = false" \
            "[realms]" "AD.RUNTIME.TEST = {" "kdc = $1" "}" >"$KRB5_CONFIG"
        if [[ "$2" == authenticate ]]; then
            timeout 10 kinit "$3@AD.RUNTIME.TEST"
            exit
        fi
        timeout 20 adcli join --domain ad.runtime.test --domain-controller dc01.ad.runtime.test \
            --computer-name "$2" --host-fqdn "${2,,}.ad.runtime.test" --login-user "$3" \
            --stdin-password --host-keytab "$private/host.keytab"
        timeout 10 adcli testjoin --domain ad.runtime.test --domain-controller dc01.ad.runtime.test \
            --host-keytab "$private/host.keytab"
' -- "$address" "$machine" "$user"
