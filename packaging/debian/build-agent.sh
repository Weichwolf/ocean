#!/bin/sh
set -eu

version=$1
agent=$2
network_agent=$3
output=$4
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
dpkg --validate-version "$version"
architecture=$(dpkg-architecture -qDEB_HOST_ARCH)
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
chmod 0755 "$staging"

install -D -m 0755 "$agent" "$staging/usr/bin/ocean-agent"
install -D -m 0755 "$network_agent" "$staging/usr/bin/ocean-network-agent"
install -D -m 0755 "$source_dir/https-ready" "$staging/usr/libexec/ocean/https-ready"
install -D -m 0644 "$source_dir/ocean-agent.service" "$staging/usr/lib/systemd/user/ocean-agent.service"
install -D -m 0644 "$source_dir/ocean-network-agent.service" "$staging/usr/lib/systemd/system/ocean-network-agent.service"
install -D -m 0644 "$source_dir/ocean-https-agent.service" "$staging/usr/lib/systemd/system/ocean-https-agent.service"
install -D -m 0644 "$source_dir/agent.json" "$staging/etc/ocean-agent/config.json"
install -d -m 0755 "$staging/DEBIAN"
install -m 0755 "$source_dir/postinst" "$source_dir/prerm" "$staging/DEBIAN/"
printf '%s\n' /etc/ocean-agent/config.json > "$staging/DEBIAN/conffiles"
cat > "$staging/DEBIAN/control" <<EOF
Package: ocean-agent
Version: $version
Architecture: $architecture
Section: admin
Priority: optional
Maintainer: ocean contributors <development@ocean.invalid>
Depends: podman, uidmap, passt | slirp4netns, fuse-overlayfs, passwd (>= 1:4.15), systemd, dbus-user-session, iproute2, nftables
Suggests: haproxy, dnsmasq-base, keepalived, curl
Description: ocean node agent
 Runs the ocean node agent under a dedicated systemd user manager and checks
 the host's rootless Podman runtime before reporting readiness. Includes a
 system service to enforce workload network assignments on host router links.
EOF

mkdir -p -- "$output"
dpkg-deb --root-owner-group --build "$staging" "$output/ocean-agent_${version}_${architecture}.deb"
