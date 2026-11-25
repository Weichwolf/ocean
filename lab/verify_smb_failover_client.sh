#!/usr/bin/env bash
set -euo pipefail
umask 077
IFS= read -r password
mode=$1 address=$2 share=$3 run=$4
marker="ocean-failover-$run"
control="/tmp/$marker"
endpoint="//files04.ad.ocean.test/$share"
private=$(mktemp -d)
cache=$private/ticket
mounted=false
if [[ $mode != read && $mode != locked ]]; then
    cache="/tmp/krb5cc_$(id -u)"
    test ! -e "$cache"
fi
cleanup() {
    if $mounted; then
        timeout 4 sudo umount --no-canonicalize "$private/mount" ||
            sudo umount --no-canonicalize --lazy "$private/mount"
    fi
    if [[ -f $cache ]]; then kdestroy -c "$cache"; fi
    for name in krb5.conf downloaded; do
        if [[ -f $private/$name ]]; then unlink "$private/$name"; fi
    done
    rmdir "$private/mount" "$private"
}
trap cleanup EXIT
mkdir "$private/mount"
export KRB5_CONFIG="$private/krb5.conf" KRB5CCNAME="FILE:$cache" SSSD_KRB5_LOCATOR_DISABLE=1
printf '%s\n' '[libdefaults]' 'default_realm = AD.OCEAN.TEST' 'dns_lookup_kdc = false' \
    '[realms]' 'AD.OCEAN.TEST = {' 'kdc = 10.232.1.11' '}' > "$KRB5_CONFIG"
printf '%s\n' "$password" | kinit smbwriter@AD.OCEAN.TEST
unset password
kvno cifs/files04.ad.ocean.test
if [[ $mode == read || $mode == locked ]]; then
    smb=(smbclient "$endpoint" -I "$address" --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" --client-protection=encrypt)
    if [[ $mode == locked ]]; then
        if result=$("${smb[@]}" -c "get $marker $private/downloaded" 2>&1) ||
            ! grep -Fq NT_STATUS_FILE_LOCK_CONFLICT <<< "$result"; then
            printf 'Expected the existing byte-range lock to deny a read. Got %s\n' "$result" >&2
            exit 1
        fi
        exit
    fi
    "${smb[@]}" -c "get $marker-unlocked $private/downloaded"
    printf '%s' "$run" | cmp - "$private/downloaded"
    exit
fi

options="ip=$address,vers=3.1.1,sec=krb5i,seal,nosharesock,cache=none,soft,echo_interval=3"
options+=",cruid=$(id -u),uid=$(id -u),gid=$(id -g)"
sudo mount -t cifs "$endpoint" "$private/mount" -o "$options"
mounted=true
timeout 180 python3 - "$mode" "$control" "$private/mount/$marker" "$run" <<'PY'
import errno
import fcntl
import os
from pathlib import Path
import sys
import time

mode, control, file, nonce = sys.argv[1:]
control, file, marker = Path(control), Path(file), nonce.encode()
unlocked = file.with_name(file.name + "-unlocked")
if mode == "hold":
    control.mkdir(mode=0o700)
    with unlocked.open("xb", buffering=0) as handle:
        handle.write(marker)
        os.fsync(handle.fileno())
    with file.open("xb+", buffering=0) as handle:
        handle.write(marker)
        os.fsync(handle.fileno())
        fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB, 1)
        (control / "ready").touch()
        while not (control / "resume").is_file():
            if (control / "abort").is_file():
                raise SystemExit
            time.sleep(0.2)
        try:
            data = os.pread(handle.fileno(), len(marker), 0)
        except OSError as error:
            if error.errno not in (errno.EIO, errno.ESTALE, errno.EBADF, errno.ENOTCONN,
                                   errno.EHOSTDOWN, errno.ETIMEDOUT):
                raise
            print("oldHandle=" + errno.errorcode[error.errno])
        else:
            if data != marker:
                raise RuntimeError("old descriptor returned different data")
            print("oldHandle=client-reopened")
elif mode == "checkpoint":
    checkpoint = file.with_name(f"ocean-windows-{nonce}.txt")
    with checkpoint.open("xb", buffering=0) as handle:
        handle.write(marker)
        os.fsync(handle.fileno())
elif mode == "reopen":
    with file.open("r+b", buffering=0) as handle:
        fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB, 1)
        if handle.read() != marker:
            raise RuntimeError("replacement returned different acknowledged data")
        handle.seek(0, os.SEEK_END)
        handle.write(b":reopened")
        os.fsync(handle.fileno())
        fcntl.lockf(handle, fcntl.LOCK_UN, 1)
    if file.read_bytes() != marker + b":reopened":
        raise RuntimeError("replacement write did not persist across opens")
    file.unlink()
    unlocked.unlink()
else:
    raise RuntimeError("unknown failover probe")
PY
