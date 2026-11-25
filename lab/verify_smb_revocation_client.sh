#!/usr/bin/env bash
set -euo pipefail
umask 077
IFS= read -r password
address=$1 share=$2 nonce=$3
control="/tmp/ocean-smb-revocation-$nonce"
endpoint="//files04.ad.ocean.test/$share"
cache="/tmp/krb5cc_$(id -u)"
test ! -e "$cache"
private=$(mktemp -d)
mounted=false
cleanup() {
    if $mounted; then
        timeout 4 sudo umount --no-canonicalize "$private/mount" ||
            sudo umount --no-canonicalize --lazy "$private/mount"
    fi
    if [[ -f $cache ]]; then kdestroy -c "$cache"; fi
    unlink "$private/krb5.conf"
    unlink "$private/cached-only.conf"
    rmdir "$private/mount" "$private"
}
trap cleanup EXIT
mkdir "$private/mount"
export KRB5_CONFIG="$private/krb5.conf" KRB5CCNAME="FILE:$cache" SSSD_KRB5_LOCATOR_DISABLE=1
printf '%s\n' '[libdefaults]' 'default_realm = AD.OCEAN.TEST' 'dns_lookup_kdc = false' 'dns_uri_lookup = false' \
    '[realms]' 'AD.OCEAN.TEST = {' 'kdc = 10.232.1.13' '}' > "$KRB5_CONFIG"
sed 's/10\.232\.1\.13/127.0.0.1:9/' "$KRB5_CONFIG" > "$private/cached-only.conf"
printf '%s\n' "$password" | kinit smbwriter@AD.OCEAN.TEST
unset password
kvno cifs/files04.ad.ocean.test
smb=(smbclient "$endpoint" -I "$address" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" --client-protection=encrypt -c ls)
KRB5_CONFIG="$private/cached-only.conf" "${smb[@]}"

opts="ip=$address,vers=3.1.1,sec=krb5i,seal,nosharesock,cache=none,soft,echo_interval=3"
opts+=",cruid=$(id -u),uid=$(id -u),gid=$(id -g)"
sudo mount -t cifs "$endpoint" "$private/mount" -o "$opts"
mounted=true
timeout 90 python3 - "$control" "$private/mount/ocean-windows-$nonce.txt" "$nonce" <<'PY'
import errno
import os
from pathlib import Path
import sys
import time

control, file, nonce = sys.argv[1:]
control, file, marker = Path(control), Path(file), nonce.encode()
control.mkdir(mode=0o700)
denials = (errno.EIO, errno.ESTALE, errno.EBADF, errno.EACCES, errno.EPERM,
           errno.ENOTCONN, errno.EHOSTDOWN, errno.ETIMEDOUT)
handle = file.open("xb+", buffering=0)
outcome = None
try:
    handle.write(marker)
    os.fsync(handle.fileno())
    (control / "ready").touch()
    while not (control / "check").is_file():
        if (control / "abort").is_file():
            raise SystemExit(75)
        time.sleep(0.15)
    while True:
        try:
            written = os.pwrite(handle.fileno(), marker, 0)
            os.fsync(handle.fileno())
        except OSError as error:
            if error.errno not in denials:
                raise
            outcome = errno.errorcode[error.errno]
            break
        if written == 0:
            outcome = "zero-byte-write"
            break
        time.sleep(0.2)
finally:
    try:
        handle.close()
    except OSError as error:
        if not outcome or error.errno not in denials:
            raise
        outcome += "/" + errno.errorcode[error.errno]
if not outcome:
    raise RuntimeError("the old handle produced no denial")
print("oldHandle=" + outcome, flush=True)
PY
for attempt in $(seq 1 10); do
    if result=$(KRB5_CONFIG="$private/cached-only.conf" "${smb[@]}" 2>&1); then
        sleep 0.2
    elif grep -Fq 'tree connect failed: NT_STATUS_ACCESS_DENIED' <<< "$result"; then
        klist -s
        printf '%s\n' 'cachedTicketReconnect=ACCESS_DENIED'
        exit
    else
        printf '%s\n' "$result" >&2
        sleep 0.2
    fi
done
echo 'the cached ticket was not denied by the live SMB listener' >&2
exit 1
