#!/usr/bin/env python3
"""Exercise encrypted Ceph snapshots and independent backup restore on two KVM workers."""

import argparse
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from region import ROOT, ssh, upload
from storage import FILES, POOL, command, private_file

WRITER = "farm-1-node-05"
RECOVERY = "farm-1-node-06"
CLIENT = "ocean-rbd-lab"


def verify(state):
    run_id = "backup-" + uuid4().hex[:20]
    directory = f"/opt/ocean-rbd-test/{run_id}"
    key_path = state / "storage-pki" / f"{run_id}.key"
    private_file(key_path, secrets.token_bytes(32))
    config = {"pool": POOL, "client": CLIENT, "cephConfig": f"{directory}/ceph.conf", "keyring": f"{directory}/ceph.key",
              "mountRoot": f"{directory}/mounts"}
    keyring = command(state, ["ceph", "auth", "get-or-create", f"client.{CLIENT}", "mon", "profile rbd",
                              "osd", f"profile rbd pool={POOL}", "mgr", f"profile rbd pool={POOL}"])
    storage_config = command(state, ["cat", f"{FILES}/ceph.conf"])
    with tempfile.TemporaryDirectory(prefix="ocean-rbd-test-") as tmp:
        binary = Path(tmp) / "storage.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary), "./internal/storage"],
                       cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        files = {"bin/storage.test": binary.read_bytes(), "ceph.conf": storage_config, "ceph.key": keyring,
                 "volume.key": key_path.read_bytes(), "config.json": json.dumps(config).encode()}
        for node in (WRITER, RECOVERY):
            upload(state, node, files, directory, owner="root")

    backup = f"{directory}/checkpoint.rbd"

    def invoke(node, mode):
        args = ["sudo", "env", f"OCEAN_E2E_RBD_CONFIG={directory}/config.json", f"OCEAN_E2E_RBD_KEY={directory}/volume.key",
                f"OCEAN_E2E_RBD_ID={run_id}", f"OCEAN_E2E_RBD_BACKUP={backup}", f"OCEAN_E2E_RBD_MODE={mode}",
                f"{directory}/bin/storage.test", "-test.run=^TestEncryptedRBDDataPath$", "-test.v"]
        shell_arg = shlex.join(args)
        reply = ssh(state, node, f'if result=$({shell_arg} 2>&1); then printf "%s\\n" "$result"; '
                                'else status=$?; printf "%s\\n" "$result" >&2; exit "$status"; fi').decode()
        if "--- PASS: TestEncryptedRBDDataPath" not in reply:
            raise RuntimeError("the encrypted storage fixture did not run")
        return reply

    writer = invoke(WRITER, "write")
    encrypted = ssh(state, WRITER, f"sudo cat {backup}")
    if not encrypted:
        raise RuntimeError("the independent encrypted backup is empty")
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    artifact = state / f"{run_id}.rbd"
    private_file(artifact, encrypted)
    upload(state, RECOVERY, {"checkpoint.rbd": encrypted}, directory, owner="root")
    recovery = invoke(RECOVERY, "restore")
    (evidence / "rbd-encryption.log").write_text(f"Writer VM {WRITER}\n{writer}\nRecovery VM {RECOVERY}\n{recovery}")
    (evidence / "rbd-encryption.json").write_text(json.dumps({"writer": WRITER, "recovery": RECOVERY, "volume": run_id,
                                                            "backupSHA256": hashlib.sha256(encrypted).hexdigest(), "backupBytes": len(encrypted),
                                                            "snapshotPlaintextMarkerAbsent": True, "authorizedRestore": True,
                                                            "invalidMountKeyRejected": True}, indent=2) + "\n")
    for volume in (run_id, "restored-" + run_id):
        command(state, ["rbd", "snap", "purge", f"{POOL}/{volume}"])
        command(state, ["rbd", "rm", f"{POOL}/{volume}"])
    for node in (WRITER, RECOVERY):
        ssh(state, node, f"sudo unlink {directory}/volume.key && sudo unlink {directory}/ceph.key")
    print("Two KVM workers verified LUKS2, wrong-key rejection, a raw encrypted snapshot, and independent RBD restore.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    verify(args.state.resolve())


if __name__ == "__main__":
    main()
