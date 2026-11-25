set -euo pipefail
umask 077
IFS= read -r password
quota_mib=$1
cache=/tmp/krb5cc_$(id -u)
test ! -e "$cache"
private=$(mktemp -d)
mkdir "$private/a" "$private/b"

cleanup() {
    for name in a b; do
        if mountpoint -q "$private/$name"; then sudo umount "$private/$name"; fi
        rmdir "$private/$name"
    done
    unlink "$private/krb5.conf"
    if test -f "$cache"; then kdestroy -c "$cache"; fi
    rmdir "$private"
}
trap cleanup EXIT
export KRB5_CONFIG="$private/krb5.conf" KRB5CCNAME="FILE:$cache"
export SSSD_KRB5_LOCATOR_DISABLE=1
printf '%s\n' '[libdefaults]' 'default_realm = AD.OCEAN.TEST' \
    'dns_lookup_kdc = false' 'dns_uri_lookup = false' '[realms]' \
    'AD.OCEAN.TEST = {' 'kdc = 10.232.1.11' '}' > "$KRB5_CONFIG"
printf '%s\n' "$password" | kinit smbwriter@AD.OCEAN.TEST >/dev/null
kvno cifs/files04.ad.ocean.test >/dev/null
options="vers=3.1.1,sec=krb5i,seal,nosharesock,cache=none,cruid=$(id -u),uid=$(id -u),gid=$(id -g)"
for name in a b; do
    sudo mount -t cifs //files04.ad.ocean.test/company-files "$private/$name" -o "$options"
done

python3 - "$private" "$quota_mib" <<'PY'
import errno
import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

base = Path(sys.argv[1])
quota = int(sys.argv[2]) << 20
first = Path(tempfile.mkdtemp(prefix="ocean-quota-", dir=base / "a"))
second = base / "b" / first.name


def persist(path, payload):
    with path.open("wb") as file:
        file.write(payload)
        file.flush()
        os.fsync(file.fileno())


def verify_quota():
    start = Barrier(2, timeout=5)
    inputs = (b"a" * (1 << 20), b"b" * (1 << 20))

    def write_concurrently(path, data):
        start.wait()
        persist(path, data)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writes = [
            pool.submit(write_concurrently, first / "left", inputs[0]),
            pool.submit(write_concurrently, second / "right", inputs[1]),
        ]
        for write in writes:
            write.result()
    if (second / "left").read_bytes() != inputs[0] or (first / "right").read_bytes() != inputs[1]:
        raise RuntimeError("An acknowledged concurrent write was not visible to the other connection")
    try:
        persist(second / "over-quota", b"q" * quota)
    except OSError as error:
        if error.errno not in (errno.EDQUOT, errno.ENOSPC):
            raise
        return error.errno
    raise RuntimeError("The combined writes exceeded the configured share quota")


def verify_locks():
    contender = """
import errno
import fcntl
import sys

with open(sys.argv[1], "rb+") as file:
    try:
        fcntl.lockf(file, fcntl.LOCK_EX | fcntl.LOCK_NB, 1)
    except OSError as error:
        if error.errno not in (errno.EAGAIN, errno.EACCES):
            raise
        raise SystemExit(23)
"""
    command = [sys.executable, "-c", contender, str(second / "left")]
    with (first / "left").open("rb+") as writer:
        fcntl.lockf(writer, fcntl.LOCK_EX | fcntl.LOCK_NB, 1)
        if subprocess.run(command, check=False, timeout=8).returncode != 23:
            raise RuntimeError("The second SMB connection did not report a conflicting byte-range lock")
        fcntl.lockf(writer, fcntl.LOCK_UN, 1)
        subprocess.run(command, check=True, timeout=8)


try:
    quota_errno = verify_quota()
    (second / "over-quota").unlink(missing_ok=True)
    verify_locks()
    print(json.dumps({
        "shareQuotaBytes": quota,
        "acknowledgedConcurrentWriteBytes": 2 << 20,
        "quotaWriteErrno": quota_errno,
        "conflictingByteRangeLockDenied": True,
        "byteRangeLockAvailableAfterRelease": True,
    }))
finally:
    shutil.rmtree(first)
PY
