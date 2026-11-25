#!/usr/bin/env python3
"""Prepare Samba AD and verify a Debian client in a disposable ocean-lab state."""

import argparse
from datetime import datetime
import json
import re
import secrets
import shlex
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import ROOT, eventually, run, ssh

PROFILE = ROOT / "lab/profiles/domain-join.yaml"
DC = "farm-1-node-01"
CLIENT = "farm-1-node-02"
FOREIGN = "farm-2-node-02"
DOMAIN = "ad.ocean.test"
REALM = DOMAIN.upper()
DC_IP = "10.232.1.11"
DC_NAME = f"dc01.{DOMAIN}"
USER = f"employee@{DOMAIN}"
GROUP = "FileUsers"
DNS_RECORD = f"_ldap._tcp.dc._msdcs.{DOMAIN}"
WINDOWS_PROFILES = {"server-core": "ServerCore", "windows-11": "Windows11"}

DC_SETUP = r"""
ip -4 addr show dev work0 | grep -q '10.232.1.11/24'
install -d -m 0700 /var/lib/ocean-domain-join

if ! test -f /var/lib/samba/private/sam.ldb; then
    hostnamectl set-hostname dc01.ad.ocean.test
    if ! grep -Fq '10.232.1.11 dc01.ad.ocean.test dc01' /etc/hosts; then
        printf '10.232.1.11 dc01.ad.ocean.test dc01\n' >> /etc/hosts
    fi
    systemctl disable --now smbd.service nmbd.service winbind.service
    if test -e /etc/samba/smb.conf; then
        mv /etc/samba/smb.conf /var/lib/ocean-domain-join/initial-smb.conf
    fi
    samba-tool domain provision --realm=AD.OCEAN.TEST --domain=OCEANLAB \
        --server-role=dc --dns-backend=SAMBA_INTERNAL --host-name=dc01 \
        --host-ip=10.232.1.11 --adminpass="$administrator" > /var/lib/ocean-domain-join/provision.log 2>&1 ||
        { echo 'Samba provisioning failed. Inspect the private controller provision log.' >&2; exit 1; }
    sed -i '/^\[global\]/a\	bind interfaces only = yes\n\tinterfaces = lo work0' /etc/samba/smb.conf
    install -m 0644 /var/lib/samba/private/krb5.conf /etc/krb5.conf
fi
if ! samba-tool user show employee >/dev/null 2>&1; then
    samba-tool user create employee "$employee" >/dev/null
fi
if ! samba-tool group show FileUsers >/dev/null 2>&1; then
    samba-tool group add FileUsers >/dev/null
fi
if ! samba-tool group listmembers FileUsers | grep -Fixq employee; then
    samba-tool group addmembers FileUsers employee >/dev/null
fi

printf '%s\n' 'local stratum 10' 'bindaddress 10.232.1.11' 'allow 10.232.1.0/24' > /etc/chrony/chrony.conf
systemctl enable --now samba-ad-dc.service
systemctl restart chrony.service
samba --version
"""

CLIENT_SETUP = r"""
set -euo pipefail
ip -4 addr show dev work0 | grep -q '10.232.1.12/24'
network_file=$(networkctl status work0 --no-pager | sed -n 's/^[[:space:]]*Network File: //p')
test -n "$network_file"
dropin="/etc/systemd/network/$(basename "$network_file").d"
install -d "$dropin"
printf '%s\n' '[Network]' 'DNS=10.232.1.11' 'Domains=~ad.ocean.test' > "$dropin/90-ocean-ad.conf"
networkctl reload
networkctl reconfigure work0
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = AD.OCEAN.TEST
    dns_lookup_kdc = true
    rdns = false
EOF
printf '%s\n' 'server 10.232.1.11 iburst' 'makestep 0.1 3' > /etc/chrony/chrony.conf
systemctl restart chrony.service
"""

FOREIGN_CHECK = r"""
ip -4 addr show dev work0 | grep -q '10.232.2.12/24'
if dig +time=1 +tries=1 +short @10.232.1.11 _ldap._tcp.dc._msdcs.ad.ocean.test SRV | grep -q dc01; then
    echo 'The foreign network discovered the directory' >&2
    exit 1
fi
for port in 88 389; do
    if timeout 2 bash -c "exec 3<>/dev/tcp/10.232.1.11/$port"; then
        echo "The foreign network reached directory port $port" >&2
        exit 1
    fi
done
cache=$(mktemp -d)
trap 'unlink "$cache/krb5.conf"; rmdir "$cache"' EXIT
cat > "$cache/krb5.conf" <<'EOF'
[libdefaults]
    default_realm = AD.OCEAN.TEST
    dns_lookup_kdc = false
[realms]
    AD.OCEAN.TEST = {
        kdc = 10.232.1.11
    }
EOF
if printf '%s\n' "$employee" | timeout 5 env KRB5_CONFIG="$cache/krb5.conf" \
        KRB5CCNAME="FILE:$cache/ticket" kinit employee@AD.OCEAN.TEST >/dev/null 2>&1; then
    unlink "$cache/ticket"
    echo 'The foreign network obtained a ticket for the test employee' >&2
    exit 1
fi
"""

def shell(state, guest, script, *, timeout=180):
    return ssh(state, guest, "sudo bash -s", (script.strip() + "\n").encode(), timeout=timeout).decode().strip()


def command(state, guest, text, payload=None, *, timeout=180):
    return ssh(state, guest, text, payload, timeout=timeout).decode().strip()


def credentials(state):
    directory = state / "identity"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / "domain-join.secret"
    if not path.exists():
        record = {key: "Ad9-" + secrets.token_urlsafe(24) for key in ("administrator", "employee")}
        with path.open("x") as output:
            path.chmod(0o600)
            json.dump(record, output)
    return json.loads(path.read_text())


def boot(state, image):
    run([ROOT / "bin/ocean-lab", "up", "-state", state, "-profile", PROFILE,
         "-image", image, "-only", DC, "-only", CLIENT, "-only", FOREIGN], timeout=120)
    for machine in (DC, CLIENT, FOREIGN):
        eventually(lambda: command(state, machine, "cloud-init status --wait", timeout=20), 90)


def install(state):
    dc_packages = "samba-ad-dc samba-ad-provision dnsutils chrony"
    client_packages = "realmd adcli sssd sssd-tools libnss-sss libpam-sss packagekit krb5-user dnsutils chrony pamtester"
    for machine, packages in ((DC, dc_packages), (CLIENT, client_packages), (FOREIGN, "dnsutils krb5-user")):
        command(state, machine, "sudo apt-get update -qq && "
                "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends " + packages,
                timeout=540)


def prepare(state, image):
    boot(state, image)
    install(state)
    passwords = credentials(state)
    # Store the provision transcript only on the disposable controller. It can contain secrets.
    provision = ("set -euo pipefail\nadministrator=" + shlex.quote(passwords["administrator"]) +
                 "\nemployee=" + shlex.quote(passwords["employee"]) + "\n" + DC_SETUP)
    version = shell(state, DC, provision)
    shell(state, CLIENT, CLIENT_SETUP)
    return version


def assert_dns_and_time(state):
    answer = eventually(lambda: lookup_dc(state), 30)
    command(state, CLIENT, "chronyc waitsync 20 1.0 0.0 1 && chronyc -n sources | grep -F '^* 10.232.1.11'",
            timeout=30)
    return answer


def lookup_dc(state):
    answer = command(state, CLIENT, f"dig +short +time=2 +tries=1 SRV {DNS_RECORD}")
    if f"389 {DC_NAME}." not in answer:
        raise RuntimeError("the directory DNS record did not resolve to the expected controller")
    return answer


def join_debian(state, administrator):
    denial_record = state / "identity/debian-invalid-join"
    current = command(state, CLIENT, "sudo realm list --name-only")
    if current.lower() == DOMAIN:
        if not denial_record.is_file():
            raise RuntimeError("use a fresh Debian fixture to verify the invalid join before enrollment")
        return
    if current:
        raise RuntimeError("the Debian fixture is already joined to another realm")
    try:
        command(state, CLIENT, f"sudo realm join --verbose --user=Administrator {DOMAIN}", b"wrong-password\n")
    except RuntimeError as error:
        if "preauthentication failed" not in str(error).lower():
            raise
    else:
        raise RuntimeError("the directory accepted incorrect join credentials")
    denial_record.write_text("Kerberos preauthentication rejected invalid credentials.\n")
    command(state, CLIENT, f"sudo realm join --verbose --user=Administrator {DOMAIN}", (administrator + "\n").encode())


def reboot_debian(state):
    previous_id = command(state, CLIENT, "cat /proc/sys/kernel/random/boot_id")
    command(state, CLIENT, "sudo systemd-run --on-active=2s systemctl reboot")

    def new_boot():
        current_id = command(state, CLIENT, "cat /proc/sys/kernel/random/boot_id", timeout=10)
        if previous_id == current_id:
            raise RuntimeError("the Debian fixture has not rebooted")

    eventually(new_boot, 90)


def verify_debian(state, employee):
    command(state, CLIENT, f"sudo realm list --name-only | grep -Fx {DOMAIN} && sudo adcli testjoin --domain={DOMAIN}")
    identity = command(state, CLIENT, f"id {USER}")
    if f"{GROUP.lower()}@{DOMAIN}" not in identity.lower():
        raise RuntimeError("the SSSD identity did not include the expected domain group")
    command(state, CLIENT, f"sudo pamtester login {USER} authenticate acct_mgmt",
            (employee + "\n").encode())
    ticket = command(state, CLIENT, f"""set -eu
cache=$(mktemp -d)
trap 'unlink "$cache/ticket"; rmdir "$cache"' EXIT
export KRB5CCNAME="FILE:$cache/ticket"
kinit employee@{REALM}
klist
""", (employee + "\n").encode())
    if f"krbtgt/{REALM}@{REALM}" not in ticket:
        raise RuntimeError("the client did not receive a ticket-granting ticket")
    return identity


def write_evidence(state, name, result):
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    destination = evidence / name
    destination.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Evidence at {destination}")


def windows_evidence(state, profile):
    fixture = state / profile
    media = json.loads((fixture / "media.json").read_text())
    checks = ("join", "machine", "identity")
    files = [fixture / f"{name}.json" for name in checks]
    captured = not all(path.is_file() for path in files)
    if captured:
        records = {}
        for line in (fixture / "guest-serial.log").read_text(errors="replace").splitlines():
            if line.startswith("OCEAN-DOMAIN "):
                record = json.loads(line.removeprefix("OCEAN-DOMAIN "))
                records[record["check"]] = record
        if not all(name in records for name in checks):
            raise RuntimeError(f"the {profile} serial capture lacks a join, machine or identity record")
        join, machine, identity = [records[name] for name in checks]
    else:
        join, machine, identity = [
            json.loads(path.read_text(encoding="utf-8-sig")) for path in files
        ]
    expected = WINDOWS_PROFILES[profile]
    edition = machine["edition"]
    correct_edition = edition in {"Professional", "EnterpriseEval"} if expected == "Windows11" else edition in {
        "ServerStandard", "ServerStandardEval", "ServerDatacenter", "ServerDatacenterEval",
    }
    if not (
        media["profile"] == profile and re.fullmatch("[0-9a-f]{64}", media["installationMediaSHA256"])
        and join["check"] == "join" and machine["check"] == "machine" and identity["check"] == "identity"
        and join["requestedDomain"] == machine["domain"].lower() == DOMAIN
        and join["wrongDomainRejected"] is True and machine["secureChannel"] is True
        and len(join["clockOffsetsSeconds"]) == 3 and all(abs(offset) <= 5 for offset in join["clockOffsetsSeconds"])
        and join["guest"].lower() == machine["guest"].lower() == identity["guest"].lower()
        and join["edition"] == edition and correct_edition and join["build"] == machine["build"]
        and datetime.fromisoformat(machine["lastBoot"]) > datetime.fromisoformat(join["joinedAt"])
        and machine["profile"] == identity["profile"] == expected
        and identity["principal"].lower() == USER and identity["group"].lower() == r"oceanlab\fileusers"
        and identity["kerberosTicketGranted"] is True
    ):
        raise RuntimeError(f"the {profile} records do not prove join, reboot, machine trust and domain sign-in")
    if captured:
        for path, record in zip(files, (join, machine, identity), strict=True):
            path.write_text(json.dumps(record, indent=2) + "\n")
    write_evidence(state, f"{profile}-domain-join.json", {
        "media": media, "join": join, "machine": machine, "identity": identity,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    fixture = parser.add_mutually_exclusive_group(required=True)
    fixture.add_argument("--debian-image", type=Path)
    fixture.add_argument("--windows-profile", choices=WINDOWS_PROFILES)
    args = parser.parse_args()
    state = args.state.resolve()
    if not state.is_dir() or state.stat().st_mode & 0o077:
        parser.error("--state must be an owner-only directory created for this fixture")
    if args.windows_profile:
        windows_evidence(state, args.windows_profile)
        return

    samba_version = prepare(state, args.debian_image.resolve())
    passwords = credentials(state)
    dns_answer = assert_dns_and_time(state)
    join_debian(state, passwords["administrator"])
    reboot_debian(state)
    assert_dns_and_time(state)
    identity = verify_debian(state, passwords["employee"])
    foreign_probe = "set -euo pipefail\nemployee=" + shlex.quote(passwords["employee"]) + "\n" + FOREIGN_CHECK
    shell(state, FOREIGN, foreign_probe)
    versions = command(state, CLIENT, "dpkg-query -W realmd adcli sssd-ad krb5-user").splitlines()
    result = {
        "domain": DOMAIN,
        "controller": DC_NAME,
        "sambaVersion": samba_version,
        "debianPackages": versions,
        "dnsServiceRecord": dns_answer,
        "commonTimeSource": DC_IP,
        "debianInvalidJoinRejected": True,
        "debianMembershipAfterReboot": True,
        "debianPAMAuthentication": True,
        "debianKerberosTicketGranted": True,
        "debianIdentityAndGroups": identity,
        "foreignTenantDirectoryReachable": False,
        "foreignTenantKerberosTicketGranted": False,
    }
    print("Verified Debian domain login, Kerberos, and private network isolation.")
    write_evidence(state, "debian-domain-join.json", result)


if __name__ == "__main__":
    main()
