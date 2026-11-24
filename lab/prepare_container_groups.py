#!/usr/bin/env python3
"""Enable container scheduling and separate network agents in an enrolled KVM lab."""

import argparse
import json
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import publish
from region import ssh, upload
from verify_agent_package import INSTALL
from verify_enrollment import wait_ready

SERVICE = "ocean-container-network.service"
NETWORK = {"privateFabric": "work0", "publicFabric": "work0", "publicPrefixes": ["198.51.100.0/24"],
           "protectedPrefixes": ["10.231.0.0/16", "10.232.0.0/16", "10.233.0.0/16", "169.254.0.0/16"],
           "internetPrefixes": ["198.51.100.0/24"]}


def prepare(state, package, selected=()):
    key = state / "enrollment-pki/workload-secrets.key"
    if not key.exists():
        fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    nodes = []
    for path in sorted(key.parent.glob("*-inventory.json")):
        for host in json.loads(path.read_bytes())["hosts"]:
            if "compute" in host["roles"]:
                nodes.append(host["hostId"])
    if selected:
        if set(selected) - set(nodes):
            raise RuntimeError("all selected nodes must be enrolled compute nodes")
        nodes = list(selected)
    if not nodes:
        raise RuntimeError("the lab has no enrolled compute nodes")
    publish(state, workloads={"defaultPlacement": {"pools": ["lab-default"], "quota": {"cpuMillis": 1000, "memoryMiB": 416}}},
            workload_key=key)
    payload = package.read_bytes()

    def provision(host):
        ssh(state, host, "sudo apt-get clean")
        ssh(state, host, INSTALL, payload)
        wait_ready(state, host)
        upload(state, host, {"workload-network.json": json.dumps(NETWORK).encode()}, "/etc/ocean-agent")
        ssh(state, host, f"sudo systemctl enable --now {SERVICE}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(provision, nodes))
    print(f"Container scheduling and leased network policies are configured on {len(nodes)} enrolled compute nodes.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--node", action="append", help="enrolled compute node to configure; defaults to all enrolled compute nodes")
    args = parser.parse_args()
    prepare(args.state.resolve(), args.package.resolve(), args.node)


if __name__ == "__main__":
    main()
