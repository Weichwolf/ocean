#!/usr/bin/env python3
"""Connect the enrolled regional storage workers to the replicated lab pool."""

import argparse
import json
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import publish
from fencing import create_authority
from region import ssh, upload
from storage import FILES, POOL, command, private_file
from verify_agent_package import INSTALL
from verify_enrollment import wait_ready

WORKERS = ("farm-1-node-05", "farm-1-node-06")
SERVICE = "ocean-storage-agent.service"
CLIENT = "ocean-storage-worker"
DEST = "/etc/ocean-agent"
TOOLS = ("sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install "
         "-y -qq --no-install-recommends ceph-common cryptsetup-bin e2fsprogs && sudo apt-get clean")


def prepare(state, package):
    directory = state / "storage-pki"
    if not (directory / "cluster-id").exists():
        raise RuntimeError("the three-host Ceph cluster must be initialized first")
    key = directory / "storage-envelope.key"
    if not key.exists():
        private_file(key, secrets.token_bytes(32))
    config = {"pool": POOL, "client": CLIENT, "cephConfig": f"{DEST}/ceph.conf", "keyring": f"{DEST}/ceph.key",
              "mountRoot": "/run/ocean-storage/mounts"}
    keyring = command(state, ["ceph", "auth", "get-or-create", f"client.{CLIENT}", "mon", "profile rbd", "osd",
                              f"profile rbd pool={POOL}", "mgr", f"profile rbd pool={POOL}"])
    ceph = command(state, ["cat", f"{FILES}/ceph.conf"])
    publish(state, storage={"workers": list(WORKERS)}, storage_key=key, fence_public=create_authority(state))
    payload = package.read_bytes()

    def provision(node):
        ssh(state, node, TOOLS)
        ssh(state, node, INSTALL, payload)
        wait_ready(state, node)
        upload(state, node, {"storage.json": json.dumps(config).encode(), "ceph.conf": ceph, "ceph.key": keyring}, DEST, owner="root")
        ssh(state, node, f"sudo systemctl enable --now {SERVICE}")

    with ThreadPoolExecutor(max_workers=len(WORKERS)) as pool:
        list(pool.map(provision, WORKERS))
    print("Two enrolled Debian workers can reconcile Azure Files shares in the replicated storage pool.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.state.resolve(), args.package.resolve())


if __name__ == "__main__":
    main()
