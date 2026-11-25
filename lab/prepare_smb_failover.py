#!/usr/bin/env python3
"""Prepare a shared Samba member identity in the disposable RBD lab."""

import argparse
import os
import shlex
import uuid
from pathlib import Path

from region import ssh

os.umask(0o077)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--state", required=True, type=Path)
parser.add_argument("--fixture", required=True, type=Path)
args = parser.parse_args()
state, fixture = args.state.resolve(), args.fixture.resolve()
if not fixture.is_dir() or fixture.stat().st_mode & 0o077:
    parser.error("the SMB fixture directory must be accessible only to its owner")
primary, standby = "farm-1-node-04", "farm-1-node-08"
name_path, key_path = fixture / "failover-state-id", fixture / "failover-state.key"
if not name_path.exists():
    name_path.write_text("smb-state-" + str(uuid.uuid4()))
if not key_path.exists():
    key_path.write_bytes(os.urandom(32))
name = name_path.read_text().strip()
try:
    if not name.startswith("smb-state-") or str(uuid.UUID(name[10:])) != name[10:]:
        raise ValueError
except ValueError:
    parser.error("the member-state fixture must name a lab RBD image")
if not key_path.is_file() or key_path.stat().st_mode & 0o077 or key_path.stat().st_size != 32:
    parser.error("the fixture requires a private 32-byte state volume key")

def execute(guest, script, payload=None, timeout=30):
    return ssh(state, guest, script, payload, timeout=timeout).decode().strip()


prepare = r"""
set -euo pipefail
umask 077
volume=$1
secret=$(mktemp /run/ocean-smb-state-key.XXXXXX)
mapper=ocean-lab-$volume
root=/srv/ocean-smb/volumes/$volume
rbd=(/usr/bin/rbd --conf /etc/ocean-smb/rbd/ceph.conf --id smb-lab --keyring /etc/ocean-smb/rbd/keyring)
mapped=
restore=0
cleanup() {
    result=$?
    set +e
    if mountpoint -q "$root"; then umount "$root" || result=1; fi
    if test -b "/dev/mapper/$mapper"; then cryptsetup close "$mapper" || result=1; fi
    if test -n "$mapped"; then "${rbd[@]}" device unmap "$mapped" || result=1; fi
    unlink "$secret" || result=1
    if test "$restore" = 1; then systemctl start winbind smbd || result=1; fi
    exit "$result"
}
trap cleanup EXIT
cat > "$secret"
test "$(wc -c < "$secret")" = 32
if ! "${rbd[@]}" info "ocean/$volume" >/dev/null 2>&1; then
    "${rbd[@]}" create --size 128M --image-feature layering,exclusive-lock "ocean/$volume"
fi
test "$("${rbd[@]}" info "ocean/$volume" --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["size"])')" = 134217728
mapped=$("${rbd[@]}" device map --exclusive --options ms_mode=secure,lock_timeout=8 "ocean/$volume")
test -b "$mapped"
if ! cryptsetup isLuks "$mapped"; then
    test -z "$(wipefs --noheadings "$mapped")"
    cryptsetup luksFormat --type luks2 --pbkdf-memory 32768 --iter-time 500 --batch-mode --key-file "$secret" "$mapped"
fi
cryptsetup open --type luks2 --key-file "$secret" "$mapped" "$mapper"
if ! blkid -p "/dev/mapper/$mapper" >/dev/null; then
    mkfs.ext4 -q -m 0 "/dev/mapper/$mapper"
fi
install -d -m 0700 "$root"
mount -t ext4 -o nodev,nosuid,noexec "/dev/mapper/$mapper" "$root"
if ! test -s "$root/member/private/secrets.tdb"; then
    systemctl is-active --quiet winbind
    systemctl is-active --quiet smbd
    restore=1
    systemctl stop smbd winbind
    test -s /var/lib/ocean-smb/private/secrets.tdb
    install -d -m 0700 "$root/member"
    stage=$(mktemp -d "$root/.member.XXXXXX")
    cp -a /var/lib/ocean-smb/private /var/lib/ocean-smb/state "$stage/"
    test -s "$stage/private/secrets.tdb"
    rmdir "$root/member"
    mv -T "$stage" "$root/member"
fi
test -s "$root/member/private/secrets.tdb"
sync -f "$root"
printf 'Prepared encrypted Samba machine state in %s\n' "$volume"
"""
execute(primary, "sudo systemctl stop ocean-smb-agent.service")
execute(primary, "sudo systemctl disable ocean-smb-agent.service winbind.service smbd.service nmbd.service")
execute(standby, "sudo systemctl disable --now ocean-smb-agent.service winbind.service smbd.service nmbd.service")
command = shlex.join(["sudo", "bash", "-c", prepare, "--", name])
print(execute(primary, command, key_path.read_bytes(), timeout=70))
execute(standby, "sudo install -d -m 0700 /etc/ocean-smb/rbd")
for file in ("ceph.conf", "keyring"):
    config = ssh(state, primary, f"sudo cat /etc/ocean-smb/rbd/{file}", timeout=15)
    execute(standby, f"sudo sh -c 'umask 077; cat > /etc/ocean-smb/rbd/{file}'", config)
standby_network = r"""
set -euo pipefail
cat > /etc/systemd/network/05-ocean-smb-work0.network <<'EOF'
[Match]
Name=work0

[Network]
Address=10.232.1.18/24
DNS=10.232.1.11
DNS=10.232.1.13
Domains=~ad.ocean.test
EOF
chmod 0644 /etc/systemd/network/05-ocean-smb-work0.network
networkctl reload
networkctl reconfigure work0
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = AD.OCEAN.TEST
    dns_lookup_kdc = false
    dns_uri_lookup = false
    rdns = false
[realms]
    AD.OCEAN.TEST = {
        kdc = 10.232.1.11
    }
EOF
chmod 0644 /etc/krb5.conf
for database in passwd group; do
    if ! grep -Eq "^${database}:.*[[:space:]]winbind([[:space:]]|$)" /etc/nsswitch.conf; then
        sed -i "/^${database}:/s/$/ winbind/" /etc/nsswitch.conf
    fi
done
for unit in winbind smbd; do
    install -d "/etc/systemd/system/$unit.service.d"
    printf '%s\n' '[Service]' 'Nice=10' > "/etc/systemd/system/$unit.service.d/70-ocean-smb.conf"
done
systemctl daemon-reload
"""
execute(standby, "sudo bash -s", standby_network.encode())
print(execute(standby, "ip -br -4 addr show dev work0; getent ahostsv4 dc01.ad.ocean.test"))
