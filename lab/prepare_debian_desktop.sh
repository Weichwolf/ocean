#!/bin/sh
# Run inside a disposable Debian 13 desktop fixture as root.
set -eu

test "$(id -u)" -eq 0
getent passwd debian >/dev/null
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
    xrdp xorgxrdp openbox xterm dbus-x11 adcli sssd-ad sssd-tools smbclient krb5-user

cat >/etc/systemd/network/05-ocean-guest.network <<'EOF'
[Match]
Type=ether

[Network]
DHCP=ipv4
IPv6AcceptRA=no

[DHCPv4]
ClientIdentifier=mac
EOF

# This lab snapshot keeps the one-time fixture account and its pinned host key.
touch /etc/cloud/cloud-init.disabled
adduser xrdp ssl-cert
sed -i 's/^security_layer=.*/security_layer=tls/' /etc/xrdp/xrdp.ini
printf '%s\n' 'exec openbox-session' | runuser -u debian -- tee /home/debian/.xsession >/dev/null
systemctl enable systemd-networkd ssh xrdp
