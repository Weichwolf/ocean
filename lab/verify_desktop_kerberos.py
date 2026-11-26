#!/usr/bin/env python3
"""Verify service-only Kerberos delegation in the disposable workplace lab."""

import argparse
import json
import secrets
import shlex
from datetime import datetime
from pathlib import Path

from region import ssh


DOMAIN = "ad.ocean.test"
REALM = DOMAIN.upper()
CONTROLLER = "farm-1-node-01"
CLIENT = "farm-1-node-02"
FILE_SERVER = "farm-1-node-04"
USER = "smbwriter"
CIFS = "cifs/files04." + DOMAIN + "@" + REALM
DISALLOWED = "ldap/dc01." + DOMAIN + "@" + REALM
SHARE = "//files04." + DOMAIN + "/company-files"
TICKET_SECONDS = 300


def issue_fixture_ticket(state, account):
    principal = account + "@" + REALM
    program = f"""set -eu
umask 077
private=$(mktemp -d /run/ocean-s4u.XXXXXX)
trap 'find "$private" -mindepth 1 -delete; rmdir "$private"' EXIT
cat >"$private/krb5.conf" <<'CONF'
[libdefaults]
default_realm = {REALM}
dns_lookup_kdc = false
dns_uri_lookup = false
[realms]
{REALM} = {{
    kdc = 10.232.1.11
}}
CONF
export KRB5_CONFIG="$private/krb5.conf" SSSD_KRB5_LOCATOR_DISABLE=1
samba-tool domain exportkeytab "$private/broker.keytab" --principal '{principal}' --only-current-keys >&2
kinit -f -l {TICKET_SECONDS}s -k -t "$private/broker.keytab" -c FILE:"$private/broker" '{principal}'
kvno -q -c FILE:"$private/broker" --no-store --out-cache FILE:"$private/cifs" -I '{USER}@{REALM}' -P '{CIFS}'
kvno -q -c FILE:"$private/broker" --no-store '{DISALLOWED}'
if kvno -q -c FILE:"$private/broker" --no-store --out-cache FILE:"$private/denied" -I '{USER}@{REALM}' -P '{DISALLOWED}' >"$private/deny.log" 2>&1; then
    echo 'Delegation outside the configured CIFS service unexpectedly succeeded' >&2
    exit 1
fi
if klist -c FILE:"$private/denied" 2>/dev/null | grep -Fq '{DISALLOWED}'; then
    echo 'A ticket for the denied service was exported' >&2
    exit 1
fi
cat "$private/cifs"
"""
    return ssh(state, CONTROLLER, "sudo sh -se", program.encode(), timeout=40)


def check_personal_share(state, ticket, checkpoint):
    program = f"""set -eu
cd /tmp
umask 077
private=$(mktemp -d)
trap 'find "$private" -mindepth 1 -delete; rmdir "$private"' EXIT
cat >"$private/cifs"
export LC_ALL=C
id -un
klist -c FILE:"$private/cifs"
printf '%s' '{checkpoint}' >"$private/source"
smbclient '{SHARE}' -I 10.232.1.14 --use-kerberos=required --use-krb5-ccache=FILE:"$private/cifs" \
    --client-protection=encrypt -c "put $private/source {checkpoint}; get {checkpoint} $private/restored; del {checkpoint}" >&2
cmp "$private/source" "$private/restored"
"""
    # Keep the delegated cache owned by the mapped AD user while the broker
    # keytab and broker cache remain on the controller.
    user_program = shlex.join(["sudo", "-u", USER + "@" + DOMAIN, "sh", "-c", program])
    report = ssh(state, CLIENT, user_program, ticket, timeout=40).decode().splitlines()
    tickets = [line.split() for line in report if line and line[0].isdigit()]
    if not report or report[0] != USER + "@" + DOMAIN or f"Default principal: {USER}@{REALM}" not in report:
        raise RuntimeError("The delegated cache did not match the mapped AD user")
    if len(tickets) != 1 or len(tickets[0]) != 5 or tickets[0][-1] != CIFS:
        raise RuntimeError("The exported cache did not contain exactly the CIFS service ticket")
    issued, expires = (
        datetime.strptime(" ".join(tickets[0][index:index + 2]), "%m/%d/%y %H:%M:%S")
        for index in (0, 2)
    )
    duration = int((expires - issued).total_seconds())
    if not 0 < duration <= TICKET_SECONDS:
        raise RuntimeError("The service ticket exceeded the requested lifetime")
    audit = ssh(state, FILE_SERVER, "sudo journalctl -t smbd_audit --since '-2 minutes' --no-pager -o cat").decode()
    if not any("|" + USER + "|10.232.1.12|company-files|create_file|ok|" in line and checkpoint in line
               for line in audit.splitlines()):
        raise RuntimeError("The file service did not audit access by the personal AD user")
    return duration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    account = "smbdesk" + secrets.token_hex(5)
    checkpoint = "ocean-desktop-" + secrets.token_hex(12)
    ssh(args.state, CONTROLLER, f"sudo samba-tool user create {account} --random-password")
    try:
        ssh(args.state, CONTROLLER, f"sudo samba-tool spn add HTTP/{account}.{DOMAIN} {account}")
        ssh(args.state, CONTROLLER, f"sudo samba-tool delegation for-any-protocol {account} on")
        ssh(args.state, CONTROLLER, f"sudo samba-tool delegation add-service {account} {CIFS.split('@')[0]}")
        ticket = issue_fixture_ticket(args.state, account)
        duration = check_personal_share(args.state, ticket, checkpoint)
    finally:
        ssh(args.state, CONTROLLER, f"sudo samba-tool user delete {account}")
    report = json.dumps({"user": USER + "@" + DOMAIN, "service": CIFS, "ticketSeconds": duration,
                         "delegationOutsideService": "denied", "encryptedShareReadback": "passed",
                         "personalFileServerAudit": "passed"}) + "\n"
    evidence = args.state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "desktop-kerberos-delegation.json").write_text(report)
    print(report, end="")


if __name__ == "__main__":
    main()
