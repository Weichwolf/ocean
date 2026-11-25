#!/usr/bin/env python3
"""Prepare the three management voters and isolated clients for scale acceptance."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from enrollment import approval, publish
from keycloak import deploy as deploy_identity
from postgres import deploy as deploy_database
from prepare_functions import ensure_boot_capacity
from region import ARM, DEST, NODES, ROOT, deploy as deploy_region, run, ssh, upload
from verify_agent_package import INSTALL
from verify_enrollment import agent_command, wait_ready
from verify_identity import prepare_client

BASE = (*NODES, "farm-1-operator", "farm-1-customer")
CONFIG = "/etc/ocean-agent"


def prepare(state, image, etcd, keycloak, cli, package):
    args = [ROOT / "bin/ocean-lab", "up", "-state", state, "-profile", ROOT / "lab/profiles/scale-16.yaml",
            "-image", image]
    for node in BASE:
        args.extend(("-only", node))
    run(args)
    deploy_region(state, etcd)

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda node: ensure_boot_capacity(state, node), NODES))
    deploy_database(state)
    deploy_identity(state, keycloak, heap_mib=384)
    prepare_client(state, cli)
    enroll_base(state, package)


def enroll_base(state, package):
    tokens = {}
    for index, node in enumerate(NODES):
        gateway = index < 2
        _, token, _ = approval(state, node, profile="gateway-lab" if gateway else "lab-kvm",
                               roles=["compute", "gateway"] if gateway else ["compute"])
        tokens[node] = token
    publish(state, public_ips=["198.51.100.20", "198.51.100.21"])

    def enroll(node):
        if ssh(state, node, "dpkg-query -W -f='${db:Status-Status}' ocean-agent 2>/dev/null || true").strip() != b"installed":
            ssh(state, node, INSTALL, package.read_bytes(), timeout=600)
        config = {"listenAddress": "127.0.0.1:8081", "enrollment": {
            "origin": f"https://{ARM}", "hostId": node, "managementInterface": "mgmt0",
            "caFile": f"{DEST}/pki/ingress-ca.pem", "tokenFile": f"{CONFIG}/enrollment.secret",
            "stateDirectory": "/var/lib/ocean-agent/host-enrollment"}}
        upload(state, node, {"enrollment.secret": tokens[node].read_bytes(), "config.json": json.dumps(config).encode()},
               CONFIG, "ocean-agent")
        agent_command(state, node, "systemctl", "--user", "restart", "ocean-agent.service")
        wait_ready(state, node)

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(enroll, NODES))
    print("The three 1 GiB management voters and isolated test clients are ready for scale acceptance.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state", "image", "etcd", "keycloak", "azure-cli", "package"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    prepare(args.state.resolve(), args.image.resolve(strict=True), args.etcd.resolve(strict=True),
            args.keycloak.resolve(strict=True), args.azure_cli.resolve(strict=True), args.package.resolve(strict=True))


if __name__ == "__main__":
    main()
