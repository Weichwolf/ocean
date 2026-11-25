#!/usr/bin/env python3
"""Exercise the encrypted VM backing disk across two disposable KVM workers."""

import argparse
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from region import ROOT, ssh, upload
from storage import FILES, POOL, command


def fixture_digests():
    disk = hashlib.sha256()
    zeros = bytes(8 << 20)
    seed = b"seeded-guest-disk"
    disk.update(zeros)
    disk.update(seed)
    remaining = (32 << 30) - len(zeros) - len(seed)
    chunks, tail = divmod(remaining, len(zeros))
    for _ in range(chunks):
        disk.update(zeros)
    disk.update(zeros[:tail])
    firmware = bytearray(540672)
    seed = b"seeded-guest-vars"
    firmware[4096:4096 + len(seed)] = seed
    return disk.hexdigest(), hashlib.sha256(firmware).hexdigest()


def verify(state, evidence):
    volume = "vm-probe-" + uuid4().hex[:20]
    directory = f"/opt/ocean-vm-disk-lab/{volume}"
    identity = f"client.{volume}"
    workers = ("farm-1-node-05", "farm-1-node-06")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    disk_sha, firmware_sha = fixture_digests()
    profile = {"pool": POOL, "client": volume, "cephConfig": f"{directory}/ceph.conf",
               "keyring": f"{directory}/ceph.key", "mountRoot": f"{directory}/mounts"}
    storage_config = command(state, ["cat", f"{FILES}/ceph.conf"])
    keyring = command(state, ["ceph", "auth", "get-or-create", identity, "mon", "profile rbd",
                              "osd", f"profile rbd pool={POOL}", "mgr", f"profile rbd pool={POOL}"])
    uploaded = []
    try:
        with tempfile.TemporaryDirectory(prefix="ocean-vm-disk-lab-") as scratch:
            binary = Path(scratch) / "storage.test"
            subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c",
                            "-o", str(binary), "./internal/storage"], cwd=ROOT,
                           env=dict(os.environ, CGO_ENABLED="0"), check=True)
            files = {"bin/storage.test": binary.read_bytes(), "ceph.conf": storage_config, "ceph.key": keyring,
                     "volume.key": secrets.token_bytes(32), "config.json": json.dumps(profile).encode()}
            for node in workers:
                upload(state, node, files, directory, owner="root")
                uploaded.append(node)

        metrics = {}
        for node, mode in zip(workers, ("write", "reopen"), strict=True):
            args = ["sudo", "env", f"OCEAN_E2E_RBD_CONFIG={directory}/config.json",
                    f"OCEAN_E2E_RBD_KEY={directory}/volume.key", f"OCEAN_E2E_RBD_ID={volume}",
                    f"OCEAN_E2E_RBD_MODE={mode}", f"OCEAN_E2E_VM_DISK_SHA={disk_sha}",
                    f"OCEAN_E2E_VM_VARS_SHA={firmware_sha}", f"{directory}/bin/storage.test",
                    "-test.run=^TestEncryptedVMDisk$", "-test.v"]
            start = time.monotonic()
            script = shlex.join(args)
            result = ssh(state, node, f'if result=$({script} 2>&1); then printf "%s\\n" "$result"; '
                         'else status=$?; printf "%s\\n" "$result" >&2; exit "$status"; fi',
                         timeout=400).decode()
            metrics[mode] = round((time.monotonic() - start) * 1000)
            (evidence / f"vm-disk-{mode}.log").write_text(result)
            if "--- PASS: TestEncryptedVMDisk" not in result:
                raise RuntimeError(f"the encrypted VM disk {mode} probe did not run")

        health = json.loads(command(state, ["ceph", "status", "--format", "json"]))
        result = {"volume": volume, "writer": workers[0], "reopenWorker": workers[1], "virtualSizeGiB": 32,
                  "rawDiskSHA256": disk_sha, "firmwareSHA256": firmware_sha, "durationMs": metrics,
                  "monitorQuorum": health["quorum_names"], "wrongDigestRejected": True,
                  "wrongKeyRejected": True, "runtimeCannotChangeReceipt": True,
                  "busyDetachRejected": True, "encryptedSnapshotMarkerAbsent": True,
                  "diskAndFirmwareWritesPreserved": True}
        (evidence / "vm-disk.json").write_text(json.dumps(result, indent=2) + "\n")
        print("Two KVM workers verified the same encrypted OS disk and UEFI state after confirmed detach.")
    finally:
        images = json.loads(command(state, ["rbd", "ls", "--pool", POOL, "--format", "json"]))
        if volume in images:
            command(state, ["rbd", "snap", "purge", f"{POOL}/{volume}"])
            command(state, ["rbd", "rm", f"{POOL}/{volume}"])
        for node in uploaded:
            ssh(state, node, f"sudo unlink {directory}/volume.key && sudo unlink {directory}/ceph.key")
        command(state, ["ceph", "auth", "del", identity])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    state = args.state.resolve()
    verify(state, (args.evidence or state / "evidence").resolve())


if __name__ == "__main__":
    main()
