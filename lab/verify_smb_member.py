#!/usr/bin/env python3
"""Verify native Kerberos SMB access from the disposable managed-directory lab."""

import argparse
import json
import re
import secrets
import shlex
import time
from pathlib import Path

from region import ROOT, eventually, ssh
from verify_domain_join import CLIENT, DC, DOMAIN, FOREIGN, REALM, write_evidence

MEMBER = "farm-1-node-04"
MEMBER_NAME = f"files04.{DOMAIN}"
ADDRESS = "10.232.1.14"
SHARE = "company-files"
ACCOUNTS = ("smbwriter", "smbreader", "smbdenied")
WRITER_GROUP = "OceanShareWriters"
REVOCATION_BOUND_SECONDS = 20

CLIENT_PROBE = r"""
set -euo pipefail
umask 077
IFS= read -r password
account=$1
mode=$2
file=$3
share=$4
private=$(mktemp -d)
cleanup() {
    for name in ticket krb5.conf kdc.trace payload downloaded auth; do
        if test -f "$private/$name"; then unlink "$private/$name"; fi
    done
    rmdir "$private"
}
trap cleanup EXIT
export KRB5_CONFIG="$private/krb5.conf" KRB5CCNAME="FILE:$private/ticket"
export SSSD_KRB5_LOCATOR_DISABLE=1 KRB5_TRACE="$private/kdc.trace"
printf '%s\n' '[libdefaults]' 'default_realm = AD.OCEAN.TEST' \
    'dns_lookup_kdc = false' 'dns_uri_lookup = false' '[realms]' \
    'AD.OCEAN.TEST = {' 'kdc = 10.232.1.11' '}' > "$KRB5_CONFIG"
printf '%s\n' "$password" | kinit "$account@AD.OCEAN.TEST" >/dev/null
kvno cifs/files04.ad.ocean.test
if ! grep -Eq ' (dgram|stream) 10\.232\.1\.11:88' "$KRB5_TRACE" ||
    grep -Eq ' (dgram|stream) 10\.232\.1\.13:88' "$KRB5_TRACE"; then
    echo 'The ticket probe must use the writable controller' >&2
    exit 1
fi
endpoint="//files04.ad.ocean.test/$share"
smb=(smbclient "$endpoint"
    --use-kerberos=required --use-krb5-ccache="$KRB5CCNAME" --client-protection=encrypt)

expect_denial() {
    local expected=$1 result
    shift
    if result=$("$@" 2>&1) || ! grep -Fq "$expected" <<< "$result"; then
        printf 'Expected %s and got %s\n' "$expected" "$result" >&2
        return 1
    fi
    printf '%s\n' "$result"
}

printf '%s\n' 'ocean Kerberos SMB payload' > "$private/payload"
case "$mode" in
    writer)
        "${smb[@]}" -c "put $private/payload $file; get $file $private/downloaded"
        cmp "$private/payload" "$private/downloaded"
        sha256sum "$private/downloaded" | cut -d ' ' -f 1
        printf '%s\n' "username = $account" "password = $password" 'domain = OCEANLAB' > "$private/auth"
        expect_denial 'session setup failed: NT_STATUS_' \
            smbclient "$endpoint" -A "$private/auth" \
            --use-kerberos=off --client-protection=encrypt -c ls
        ;;
    reader)
        "${smb[@]}" -c "get $file $private/downloaded"
        cmp "$private/payload" "$private/downloaded"
        expect_denial 'NT_STATUS_ACCESS_DENIED' "${smb[@]}" -c "put $private/payload ${file}.denied"
        ;;
    denied)
        expect_denial 'tree connect failed: NT_STATUS_ACCESS_DENIED' "${smb[@]}" -c ls
        ;;
    checkpoint)
        "${smb[@]}" -c "put $private/payload $file"
        ;;
    cleanup)
        "${smb[@]}" -c "get $file $private/downloaded; del $file"
        cmp "$private/payload" "$private/downloaded"
        ;;
    *) exit 2 ;;
esac
"""


def private_password(path):
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError(f"Expected an owner-only credential file at {path}")
    password = path.read_bytes().rstrip(b"\n")
    if not password or b"\n" in password or b"\0" in password:
        raise RuntimeError(f"Expected a single credential at {path}")
    return password + b"\n"


def probe_client(state, share, user, mode, marker, password):
    command = shlex.join(["bash", "-c", CLIENT_PROBE, "--", user, mode, marker, share])
    return ssh(state, CLIENT, command, password, timeout=10).decode().strip()


def verify(state, fixture, share):
    passwords = {user: private_password(fixture / user) for user in ACCOUNTS}
    marker = "ocean-smb-" + secrets.token_hex(8) + ".bin"

    def on(guest, command, payload=None):
        return ssh(state, guest, command, payload, timeout=10).decode().strip()

    def client(user, mode):
        return probe_client(state, share, user, mode, marker, passwords[user])

    def membership(action):
        on(DC, shlex.join(["sudo", "samba-tool", "group", action, WRITER_GROUP, "smbwriter"]))

    on(CLIENT, f"sudo adcli testjoin --domain={DOMAIN} --domain-controller=dc01.{DOMAIN}")
    on(MEMBER, f"sudo net ads testjoin -S dc01.{DOMAIN}")
    listener = on(MEMBER, "sudo ss -H -ltn '( sport = :445 )'").splitlines()
    if len(listener) != 1 or listener[0].split()[3] != f"{ADDRESS}:445":
        raise RuntimeError("SMB is reachable on an unexpected interface or the private listener is missing")
    on(FOREIGN, f"""python3 -c 'import socket
from contextlib import closing
with closing(socket.socket()) as sock:
    sock.settimeout(2)
    if sock.connect_ex(("{ADDRESS}", 445)) == 0:
        raise SystemExit("A foreign tenant reached the SMB listener")'""")

    written = client("smbwriter", "writer").splitlines()
    try:
        checksums = [line for line in written if re.fullmatch(r"[0-9a-f]{64}", line)]
        if len(checksums) != 1 or f"cifs/{MEMBER_NAME}@{REALM}: kvno =" not in "\n".join(written):
            raise RuntimeError("The writer did not produce a CIFS service ticket and content checksum")
        client("smbreader", "reader")
        client("smbdenied", "denied")
        audit = on(MEMBER, "sudo journalctl --no-pager -t smbd_audit -o cat -n 150")
        entries = [line for line in audit.splitlines() if line.endswith("/" + marker)]
        for user, event in (("smbwriter", "pwrite_recv"), ("smbreader", "create_file")):
            if not any(line.startswith(f"OCEANLAB|{user}|10.232.1.12|{share}|{event}|ok|") for line in entries):
                raise RuntimeError(f"The SMB audit lacks the native identity and operation for {user}")

        start = time.monotonic()
        membership("removemembers")
        try:
            eventually(lambda: client("smbwriter", "denied"), REVOCATION_BOUND_SECONDS)
            elapsed = time.monotonic() - start
            if elapsed > REVOCATION_BOUND_SECONDS:
                raise RuntimeError("A new Kerberos SMB session exceeded the revocation bound")
        finally:
            membership("addmembers")
    finally:
        eventually(lambda: client("smbwriter", "cleanup"), REVOCATION_BOUND_SECONDS)
    return {
        "client": CLIENT,
        "member": MEMBER_NAME,
        "ticketIssuer": f"dc01.{DOMAIN}",
        "sambaVersion": on(CLIENT, "smbclient --version"),
        "contentSHA256": checksums[0],
        "privateListener": f"{ADDRESS}:445",
        "writerReadWrite": True,
        "readerReadOnly": True,
        "ungroupedAccessDenied": True,
        "foreignTenantConnectDenied": True,
        "passwordOnlyLoginDenied": True,
        "clientRequiredEncryption": True,
        "auditedPrincipals": [r"OCEANLAB\smbwriter", r"OCEANLAB\smbreader"],
        "freshKerberosRevocationSeconds": round(elapsed, 3),
        "freshKerberosRevocationBoundSeconds": REVOCATION_BOUND_SECONDS,
    }


def verify_quota(state, fixture):
    volume = (fixture / "rbd-volume-id").read_text().strip()
    if not re.fullmatch(r"vol-[0-9a-f-]{36}", volume):
        raise RuntimeError("The RBD quota fixture requires an allocated volume ID")
    path = f"/srv/ocean-smb/volumes/{volume}"

    def member(*args):
        return ssh(state, MEMBER, shlex.join(args), timeout=15).decode().strip()

    mapper = member("findmnt", "-nro", "SOURCE", "--mountpoint", path)
    if not mapper.startswith("/dev/mapper/"):
        raise RuntimeError("The quota test requires an encrypted share mount")
    encryption = member("sudo", "cryptsetup", "status", mapper)
    if not re.search(r"^\s*type:\s+LUKS2$", encryption, re.MULTILINE):
        raise RuntimeError("The share mount does not use LUKS2")
    device = re.search(r"^\s*device:\s+(/dev/rbd\d+)$", encryption, re.MULTILINE)
    mappings = json.loads(member("sudo", "rbd", "device", "list", "--format", "json"))
    if not device or not any(entry["name"] == volume and entry["device"] == device[1] for entry in mappings):
        raise RuntimeError("The encrypted filesystem is not using the assigned RBD image")
    quota_mib = 8
    quotas = member("sudo", "repquota", "-P", "-n", path)
    row = re.search(r"^#1\s+\S+\s+\d+\s+(\d+)\s+(\d+)", quotas, re.MULTILINE)
    if not row or (int(row[1]), int(row[2])) != (quota_mib * 1024, quota_mib * 1024):
        raise RuntimeError("The active filesystem does not have the expected project quota")

    script = (ROOT / "lab/verify_smb_quota.sh").read_text()
    command = shlex.join(["keyctl", "session", "-", "bash", "-c", script, "--", str(quota_mib)])
    output = ssh(state, CLIENT, command, private_password(fixture / "smbwriter"), timeout=45)
    result = json.loads(output.decode().strip().splitlines()[-1])
    return {"volumeId": volume, "encryption": "LUKS2", "blockDevice": device[1], **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--share", default=SHARE)
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--rbd-quota", action="store_true")
    variants.add_argument("--reader-denied", action="store_true")
    variants.add_argument("--checkpoint", choices=("write", "verify"))
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", args.share):
        parser.error("--share must be a simple SMB share name")
    for directory in (args.state, args.fixture):
        if not directory.is_dir() or directory.stat().st_mode & 0o077:
            parser.error(f"{directory} must be an owner-only fixture directory")
    if args.rbd_quota:
        if args.share != SHARE:
            parser.error("--rbd-quota requires the dedicated company-files fixture")
        write_evidence(args.state, "kerberos-smb-quota.json", verify_quota(args.state, args.fixture))
        print("Verified concurrent SMB writes, the RBD volume quota, and byte-range lock conflicts.")
    elif args.reader_denied:
        probe_client(args.state, args.share, "smbreader", "denied", "unused", private_password(args.fixture / "smbreader"))
        print("Verified that the SMB member denied the previous reader.")
    elif args.checkpoint:
        mode = "checkpoint" if args.checkpoint == "write" else "cleanup"
        probe_client(args.state, args.share, "smbwriter", mode, "ocean-managed-checkpoint.bin",
                     private_password(args.fixture / "smbwriter"))
        print(f"Completed the SMB data checkpoint action {args.checkpoint}.")
    else:
        write_evidence(args.state, "kerberos-smb-member.json", verify(args.state, args.fixture, args.share))
        print("Verified the native Debian Kerberos SMB session and fresh-ticket group revocation.")


if __name__ == "__main__":
    main()
