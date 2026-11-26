#!/bin/sh
set -eu

cloud=ovpn-cloud
site=ovpn-site
work=ovpn-work
customer=ovpn-client
base=/var/tmp/ocean-ipsec-profile
cloud_run=/dev/shm/ocean-ipsec-lab-profile-cloud
site_run=/dev/shm/ocean-ipsec-lab-profile-site

attach() {
    ip -n "$1" link add "$2" type veth peer name "$5" netns "$4"
    ip -n "$1" address add "$3" dev "$2"
    ip -n "$4" address add "$6" dev "$5"
    ip -n "$1" link set "$2" up
    ip -n "$4" link set "$5" up
}

daemon() {
    namespace=$1
    runtime=$2
    install -d -m 0700 "$runtime"
    cat > "$runtime/strongswan.conf" <<EOF
charon {
  load = random nonce openssl aes sha2 hmac kdf kernel-netlink socket-default vici
  install_routes = no
  plugins {
    vici {
      socket = "unix://$runtime/vici.sock"
    }
  }
}
EOF
    systemd-run --quiet --unit="ocean-ipsec-profile-$namespace" --property=Nice=10 \
        --setenv="STRONGSWAN_CONF=$runtime/strongswan.conf" /usr/bin/ip netns exec "$namespace" \
        /usr/bin/unshare --mount --propagation private /bin/sh -ceu \
        'mount -t tmpfs -o mode=755 tmpfs /run; exec /usr/lib/ipsec/charon'
    for attempt in $(seq 1 50); do
        if test -S "$runtime/vici.sock"; then
            return
        fi
        sleep 0.1
    done
    journalctl -u "ocean-ipsec-profile-$namespace" -n 12 --no-pager >&2
    return 1
}

setup() {
    test -d "$base"
    test ! -e "$cloud_run" && test ! -e "$site_run"
    for ns in "$cloud" "$site" "$work" "$customer"; do
        test ! -e "/run/netns/$ns"
    done
    touch "$base/owns-fixture"
    for ns in "$cloud" "$site" "$work" "$customer"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    attach "$cloud" wan0 198.18.24.9/32 "$site" wan0 198.18.24.2/30
    ip -n "$cloud" route add 198.18.24.2/32 dev wan0 scope link
    attach "$cloud" lan0 10.91.1.1/24 "$work" eth0 10.91.1.4/24
    attach "$site" lan0 10.92.1.1/24 "$customer" eth0 10.92.1.4/24
    ip -n "$work" route add default via 10.91.1.1
    ip -n "$customer" route add default via 10.92.1.1
    ip -n "$customer" address add 10.92.2.4/32 dev lo
    ip -n "$work" address add 10.231.1.18/32 dev lo
    ip -n "$cloud" route add 10.231.1.18/32 via 10.91.1.4
    ip -n "$site" route add 10.231.1.18/32 via 198.18.24.1 dev wan0
    ip -n "$site" link add customer42 type xfrm dev wan0 if_id 43
    ip -n "$site" link set customer42 up
    ip -n "$site" route add 10.91.1.0/24 dev customer42
    ip netns exec "$site" sysctl -qw net.ipv4.ip_forward=1
    daemon "$cloud" "$cloud_run"
    daemon "$site" "$site_run"
    install -d -m 0755 "$base/workload"
    printf '%s\n' "$1" > "$base/workload/identity"
    systemd-run --quiet --unit=ocean-ipsec-profile-http --property=Nice=10 \
        /usr/bin/ip netns exec "$work" /usr/bin/python3 -m http.server 18080 \
        --bind 10.91.1.4 --directory "$base/workload"
}

load_peer() {
    directory=$(mktemp -d "$site_run/swanctl-peer.XXXXXXXX")
    trap 'rm -f "$directory/swanctl.conf"; rmdir "$directory"' EXIT
    encoded=$(od -v -An -tx1 | tr -d ' \n')
    test "${#encoded}" -ge 32 && test "${#encoded}" -le 256
    umask 077
    cat > "$directory/swanctl.conf" <<EOF
connections {
  branch-office {
    version = 2
    local_addrs = 198.18.24.2
    remote_addrs = 198.18.24.1
    proposals = aes256-sha256-modp2048
    dpd_delay = 10s
    local {
      auth = psk
      id = 198.18.24.2
    }
    remote {
      auth = psk
      id = 198.18.24.1
    }
    children {
      branch-traffic {
        local_ts = 10.92.1.0/24
        remote_ts = 10.91.1.0/24
        esp_proposals = aes256-sha256-modp2048
        if_id_in = 43
        if_id_out = 43
      }
    }
  }
}
secrets {
  ike-branch {
    id-local = 198.18.24.2
    id-remote = 198.18.24.1
    secret = 0x$encoded
  }
}
EOF
    unset encoded
    if ! ip netns exec "$site" /usr/sbin/swanctl --load-all --clear --noprompt \
        --uri "unix://$site_run/vici.sock" --file "$directory/swanctl.conf" >/dev/null 2>&1; then
        echo 'The native strongSwan peer could not load its disposable configuration.' >&2
        return 1
    fi
}

cleanup() {
    if test ! -f "$base/owns-fixture"; then
        return
    fi
    systemctl stop ocean-ipsec-profile-http.service "ocean-ipsec-profile-$cloud.service" "ocean-ipsec-profile-$site.service" 2>/dev/null || true
    for ns in "$cloud" "$site" "$work" "$customer"; do
        if test -e "/run/netns/$ns"; then ip netns delete "$ns"; fi
    done
    rm -rf -- "$cloud_run" "$site_run"
}

case "$1" in
    setup) setup "$2" ;;
    peer-key) load_peer ;;
    peer-initiate) ip netns exec "$site" /usr/sbin/swanctl --initiate --child branch-traffic --timeout 10 --uri "unix://$site_run/vici.sock" ;;
    workload) ip netns exec "$customer" curl -fsS --max-time 2 http://10.91.1.4:18080/identity ;;
    reverse) ip netns exec "$work" ping -n -c 1 -W 1 10.92.1.4 ;;
    outside) ip netns exec "$customer" ping -n -c 1 -W 1 -I 10.92.2.4 10.91.1.4 ;;
    protected) ip netns exec "$customer" ping -n -c 1 -W 1 10.231.1.18 ;;
    routes) ip -n "$cloud" -4 route show proto 99 ;;
    tunnel) ip -n "$cloud" link show dev xfrm42 ;;
    address) ip -n "$cloud" -4 address show dev wan0 to 198.18.24.1/32 ;;
    cleanup) cleanup ;;
    *) exit 2 ;;
esac
