#!/bin/sh
# Run as root on the dedicated directory guest in the disposable VM lab.
set -eu

test "$(id -u)" -eq 0
ip -4 addr show dev work0 | grep -q '10.232.1.11/24'
state=/var/lib/ocean-desktop-pair-directory
install -d -m 0700 "$state"
ip address replace 10.232.1.29/32 dev work0
if ! test -f /var/lib/samba/private/sam.ldb; then
    hostnamectl set-hostname pair-dc.ad.pair.ocean.test
    if ! grep -Fxq '10.232.1.29 pair-dc.ad.pair.ocean.test pair-dc' /etc/hosts; then
        printf '%s\n' '10.232.1.29 pair-dc.ad.pair.ocean.test pair-dc' >> /etc/hosts
    fi
    systemctl disable --now smbd.service nmbd.service winbind.service
    if test -f /etc/samba/smb.conf; then
        mv /etc/samba/smb.conf "$state/initial-smb.conf"
    fi
    umask 077
    printf 'Pa9-%s\n' "$(openssl rand -hex 24)" > "$state/administrator"
    if ! samba-tool domain provision --realm=AD.PAIR.OCEAN.TEST --domain=OCEANPAIR \
        --server-role=dc --dns-backend=SAMBA_INTERNAL --host-name=pair-dc --host-ip=10.232.1.29 \
        --adminpass="$(cat "$state/administrator")" > "$state/provision.log" 2>&1; then
        echo 'Samba provisioning failed. Inspect the private provisioning log.' >&2
        exit 1
    fi
    sed -i '/^\[global\]/a\	bind interfaces only = yes\n\tinterfaces = lo 10.232.1.29/32' /etc/samba/smb.conf
fi
test -f "$state/administrator"
systemctl restart samba-ad-dc.service
