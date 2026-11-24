#!/usr/bin/env python3
"""Deploy host enrollment authority and one approved lab host."""

import argparse
import datetime
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import DEST, NODES, ROOT, ca, ssh, upload
from verify_operations import wait_api


def approval(state, node, *, mac=None, address=None, profile="identity-support", roles=None):
    directory = state / "enrollment-pki"
    directory.mkdir(mode=0o700, exist_ok=True)
    credential = directory / f"{node}.secret"
    if not credential.exists():
        fd = os.open(credential, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32))
    inventory = directory / f"{node}-inventory.json"
    if not inventory.exists():
        if mac is None:
            mac = ssh(state, node, "cat /sys/class/net/mgmt0/address").decode().strip()
        address = address or NODES[node]
        now = datetime.datetime.now(datetime.timezone.utc)
        data = {"hosts": [{"hostId": node, "mac": mac, "address": address, "profile": profile,
                           "cell": "cell-1", "pool": "lab-default", "roles": roles or ["compute"], "minimumCPU": 1,
                           "minimumMemoryMiB": 768, "requireKVM": False,
                           "tokenSHA256": hashlib.sha256(credential.read_bytes()).hexdigest(),
                           "expiresAt": (now + datetime.timedelta(minutes=30)).isoformat()}]}
        inventory.write_text(json.dumps(data) + "\n")
    elif roles is not None and json.loads(inventory.read_text())["hosts"][0]["roles"] != roles:
        raise RuntimeError(f"{node} already has a different approved role profile")
    return directory, credential, inventory


def deploy(state, node, public_ips=None):
    approval(state, node)
    publish(state, public_ips)


def publish(state, public_ips=None, gateway_slots=None, gateway_key=None, wireguard=None):
    directory = state / "enrollment-pki"
    hosts = [host for path in sorted(directory.glob("*-inventory.json")) for host in json.loads(path.read_text())["hosts"]]
    inventory = json.dumps({"hosts": hosts}).encode()
    cert, key = ca(directory, "host-enrollment")
    for member in NODES:
        config = json.loads(ssh(state, member, f"cat {DEST}/api.json"))
        extra = {}
        if gateway_slots is not None:
            config["region"]["applicationGateways"] = {
                "certificateKeyFile": f"{DEST}/pki/application-gateway.key", "slots": gateway_slots,
            }
            extra["pki/application-gateway.key"] = gateway_key.read_bytes()
        if wireguard is not None:
            config["region"]["wireGuard"] = wireguard
        if public_ips is not None:
            config["region"]["publicIPv4Addresses"] = public_ips
        config["tls"]["clientCAFile"] = f"{DEST}/pki/host-enrollment.pem"
        config["tls"]["optionalClientCA"] = True
        config["hostEnrollment"] = {"certificateFile": f"{DEST}/pki/host-enrollment.pem",
                                    "keyFile": f"{DEST}/pki/host-enrollment.key",
                                    "inventoryFile": f"{DEST}/host-inventory.json"}
        upload(state, member, {"pki/host-enrollment.pem": cert.read_bytes(), "pki/host-enrollment.key": key.read_bytes(),
                               "host-inventory.json": inventory, "api.json": json.dumps(config).encode(),
                               "bin/ocean-control-plane.next": (ROOT / "bin/ocean-control-plane").read_bytes(), **extra})
        ssh(state, member, f"sudo mv {DEST}/bin/ocean-control-plane.next {DEST}/bin/ocean-control-plane && "
            "sudo systemctl restart ocean-api.service")
        wait_api(state, member)
    print("Host certificate enrollment is ready on all three regional API replicas.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--node", choices=NODES, required=True)
    parser.add_argument("--public-ipv4", action="append", help="approved regional public IP address; repeat for each pool entry")
    args = parser.parse_args()
    deploy(args.state.resolve(), args.node, args.public_ipv4)


if __name__ == "__main__":
    main()
