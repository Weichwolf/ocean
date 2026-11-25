#!/usr/bin/env python3
"""Enroll two gateway guests and prepare their HTTPS slots in the regional lab."""

import argparse
import json
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import approval, publish
from region import ARM, DEST, ROOT, ssh, upload
from verify_agent_package import INSTALL
from verify_enrollment import agent_command, wait_ready
from verify_https_hosts import external_mac, public
from verify_wireguard_hosts import macvlan

GATEWAYS = ("farm-1-node-01", "farm-1-node-02")
SLOT = "ingress-lab"
NAMESPACE = "ocean-https-slt"


def prepare_slot(state, node, index, package, token):
    ssh(state, node, "sudo apt-get clean && sudo env DEBIAN_FRONTEND=noninteractive apt-get -yqq --no-install-recommends "
        "install haproxy dnsmasq-base keepalived curl && sudo apt-get clean")
    ssh(state, node, INSTALL, package)
    ssh(state, node, "sudo apt-get clean")
    agent = json.loads(ssh(state, node, "cat /etc/ocean-agent/config.json"))
    agent.setdefault("enrollment", {}).update({
        "origin": f"https://{ARM}", "hostId": node, "managementInterface": "mgmt0",
        "caFile": f"{DEST}/pki/ingress-ca.pem", "tokenFile": "/etc/ocean-agent/enrollment.secret",
        "stateDirectory": "/var/lib/ocean-agent/host-enrollment"})
    slot = {"namespace": NAMESPACE, "publicInterface": "public0", "backendInterface": "backend0",
            "publicLink": public(index) + "/24", "peerAddress": public(1 - index),
            "peerMac": external_mac(1 - index), "priority": 150 if index == 0 else 100, "vrrpId": 99}
    upload(state, node, {"config.json": json.dumps(agent).encode(), "enrollment.secret": token.read_bytes(),
                         "https.json": json.dumps({"slots": {SLOT: slot}}).encode()}, "/etc/ocean-agent", "ocean-agent")
    agent_command(state, node, "systemctl", "--user", "restart", "ocean-agent.service")
    wait_ready(state, node)
    configure_slot_links(state, node, index)


def configure_slot_links(state, node, index):
    directory = "/opt/ocean-lab-https"
    script = f"""#!/bin/sh
set -eu
if sudo ip -n {NAMESPACE} link show public0 >/dev/null 2>&1 &&
   sudo ip -n {NAMESPACE} link show backend0 >/dev/null 2>&1; then
    exit 0
fi
if sudo test -e /run/netns/{NAMESPACE}; then
    sudo ip netns delete {NAMESPACE}
fi
sudo ip netns add {NAMESPACE}
sudo ip -n {NAMESPACE} link set lo up
{macvlan(NAMESPACE, "customer0", "public0", public(index) + "/24", external_mac(index))}
{macvlan(NAMESPACE, "work0", "backend0", f"10.89.1.{index + 1}/24")}
"""
    unit = f"""[Unit]
Wants=network-online.target
After=network-online.target
Before=ocean-https-agent.service

[Service]
Type=oneshot
ExecStart={directory}/bin/prepare-slot
RemainAfterExit=yes
"""
    drop_in = "[Unit]\nRequires=ocean-lab-https-slot.service\nAfter=ocean-lab-https-slot.service\n"
    upload(state, node, {"bin/prepare-slot": script.encode(), "ocean-lab-https-slot.service": unit.encode(),
                         "lab-slot.conf": drop_in.encode()}, directory, "root")
    ssh(state, node, f"""set -eu
sudo install -m 0644 {directory}/ocean-lab-https-slot.service /etc/systemd/system/
sudo install -D -m 0644 {directory}/lab-slot.conf /etc/systemd/system/ocean-https-agent.service.d/lab-slot.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed ocean-https-agent.service 2>/dev/null || true
sudo systemctl enable ocean-https-agent.service
sudo systemctl restart ocean-lab-https-slot.service ocean-https-agent.service
sudo systemctl is-active --quiet ocean-https-agent.service
""")


def prepare(state, package):
    key = state / "enrollment-pki/application-gateway.key"
    directory = key.parent
    directory.mkdir(mode=0o700, exist_ok=True)
    if not key.exists():
        fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    tokens = [approval(state, node, profile="gateway-lab", roles=["compute", "gateway"])[1] for node in GATEWAYS]
    publish(state, gateway_slots=[{"name": SLOT, "hosts": list(GATEWAYS)}], gateway_key=key)
    package_data = package.read_bytes()
    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = [executor.submit(prepare_slot, state, node, index, package_data, tokens[index])
                for index, node in enumerate(GATEWAYS)]
        for job in jobs:
            job.result()
    print("Both enrolled gateway hosts are ready to receive HTTPS assignments.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.state.resolve(), args.package.resolve())


if __name__ == "__main__":
    main()
