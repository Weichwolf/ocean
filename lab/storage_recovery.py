"""Restore one Azure Files checkpoint and metadata snapshot in an isolated lab guest."""

import hashlib
import io
import json
import os
import shlex
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from region import ARM, DEST, ETCD_ROOT, ETCD_SHA, GRAPH, IDENTITY, NODES, OAUTH, OPERATOR, ROOT, VIP, etcdctl, eventually, leaf, ssh, upload
from storage import FILES, POOL, command, private_file

RECOVERY = "farm-1-node-04"
IP = "10.231.1.14"
CLIENT = "ocean-storage-worker"
RECOVERY_DEADLINE_MS = 180_000


def redirect_paths(value, namespace, references):
    if isinstance(value, dict):
        return {name: redirect_paths(item, namespace, references) for name, item in value.items()}
    if isinstance(value, list):
        return [redirect_paths(item, namespace, references) for item in value]
    if isinstance(value, str) and value.startswith(DEST + "/"):
        suffix = value.removeprefix(DEST + "/")
        references.add(suffix)
        return f"{namespace}/{suffix}"
    return value


def source_files(state, node, names):
    archive = ssh(state, node, shlex.join(["sudo", "tar", "-czf", "-", "-C", DEST, "--", *sorted(names)]))
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return {entry.name: tar.extractfile(entry).read() for entry in tar.getmembers() if entry.isfile()}


def etcd_tools(archive):
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != ETCD_SHA:
            raise RuntimeError("the recovery etcd archive differs from the pinned release")
    with tarfile.open(archive) as bundle:
        return {f"bin/{name}": bundle.extractfile(f"{ETCD_ROOT}/{name}").read() for name in ("etcd", "etcdutl")}


def restore_region(state, namespace, capsule, archive):
    node = next(iter(NODES))
    source = json.loads(ssh(state, node, f"cat {DEST}/api.json"))
    source["identity"].pop("onboarding", None)
    source["region"].pop("telemetry", None)
    source["tls"].pop("certificateFile", None)
    source["tls"].pop("keyFile", None)
    paths = set()
    config = redirect_paths(source, namespace, paths)
    pki = state / "region-pki"
    suffix = namespace.rsplit("-", 1)[1]
    storage_name, api_name = f"restore-storage-{suffix}", f"restore-api-{suffix}"
    certificates = leaf(pki, storage_name, (pki / "storage-ca.pem", pki / "storage-ca.key"), "serverAuth", f"IP:{IP}")
    certificates.update(leaf(pki, api_name, (pki / "ingress-ca.pem", pki / "ingress-ca.key"), "serverAuth", f"DNS:{ARM},IP:{IP}"))
    config["listenAddress"] = f"{IP}:443"
    config["tls"].update({"certificateFile": f"{namespace}/pki/{api_name}.pem", "keyFile": f"{namespace}/pki/{api_name}.key"})
    config["region"]["etcd"]["endpoints"] = [f"https://{IP}:32379"]
    config["region"]["operationController"] = False
    paths.remove("pki/storage-envelope.key")
    files = source_files(state, node, paths)
    files.update(certificates)
    files.update(etcd_tools(archive))
    files.update({"bin/ocean-control-plane": (ROOT / "bin/ocean-control-plane").read_bytes(),
                  "bin/ocean-recover": (ROOT / "bin/ocean-recover").read_bytes(), "api.json": json.dumps(config).encode(),
                  "region.snapshot.secret": capsule})
    recovery_hosts = f"{IP} {ARM}\n{VIP} {IDENTITY} {GRAPH} {OAUTH}\n127.0.0.1 localhost\n".encode()
    files["resolver.hosts"] = recovery_hosts
    upload(state, RECOVERY, files, namespace, owner="root")
    ssh(state, RECOVERY, f"sudo chmod 0700 {namespace}/exchange")
    peer = "http://127.0.0.1:32380"
    restore = [f"{namespace}/bin/etcdutl", "snapshot", "restore", f"{namespace}/region.snapshot.secret", "--name=recovery",
               f"--initial-cluster=recovery={peer}", f"--initial-advertise-peer-urls={peer}", f"--initial-cluster-token={suffix}",
               f"--data-dir={namespace}/etcd-data"]
    names = (f"ocean-recovery-etcd-{suffix}", f"ocean-recovery-api-{suffix}")
    etcd = [f"{namespace}/bin/etcd", "--name=recovery", f"--data-dir={namespace}/etcd-data", f"--listen-peer-urls={peer}",
            f"--initial-advertise-peer-urls={peer}", f"--initial-cluster=recovery={peer}", f"--initial-cluster-token={suffix}",
            f"--listen-client-urls=https://{IP}:32379", f"--advertise-client-urls=https://{IP}:32379", "--client-cert-auth",
            f"--cert-file={namespace}/pki/{storage_name}.pem", f"--key-file={namespace}/pki/{storage_name}.key",
            f"--trusted-ca-file={namespace}/pki/storage-ca.pem"]
    ssh(state, RECOVERY, shlex.join(["sudo", *restore]))
    ssh(state, RECOVERY, shlex.join(["sudo", "systemd-run", "--quiet", "--unit", names[0], *etcd]))
    return names, recovery_hosts


def recovery_backup(state, directory, volume):
    snapshot_location = f"/tmp/ocean-region-backup-{directory.name}.snapshot"
    try:
        primary = next(iter(NODES.values()))
        ssh(state, OPERATOR, etcdctl(f"snapshot save {snapshot_location}", (primary,)).replace("--command-timeout=2s", "--command-timeout=25s"))
        capsule = ssh(state, OPERATOR, f"cat {snapshot_location}")
        private_file(directory / "region.snapshot", capsule)
    finally:
        ssh(state, OPERATOR, f"if test -e {snapshot_location}; then unlink {snapshot_location}; fi")
    checkpoint = f"{POOL}/{volume}@{directory.name}"
    command(state, ["rbd", "snap", "create", checkpoint])
    try:
        encrypted = command(state, ["rbd", "export", "--export-format", "2", "--no-progress", checkpoint, "-"])
    finally:
        command(state, ["rbd", "snap", "rm", checkpoint])
    private_file(directory / "volume.rbd", encrypted)
    return capsule, encrypted


def verify_recovery(state, share, volume, invoke, archive):
    run_id = uuid4().hex[:10]
    directory = state / "recovery-backups" / f"copy-{run_id}"
    directory.mkdir(mode=0o700, parents=True)
    namespace = f"/opt/ocean-recovery-{run_id}"
    metadata, encrypted = recovery_backup(state, directory, volume)
    if share["checksum"].encode() in encrypted:
        raise RuntimeError("the independently saved RBD image contained plaintext")
    mounted_copy = f"recovered-{run_id}"
    unit_names = ()
    started = time.monotonic()
    try:
        unit_names, hosts = restore_region(state, namespace, metadata, archive)
        output = f"{namespace}/recovered-volume.key"
        lookup = [f"{namespace}/bin/ocean-recover", "-config", f"{namespace}/api.json", "-tenant", share["tenant"],
                  "-subscription", share["subscription"], "-share", share["shareId"], "-output", output]
        # Attempt the recovery with the complete metadata and a different
        # wrapping key, then install the separately protected original key.
        key_file = "pki/storage-envelope.key"
        upload(state, RECOVERY, {key_file: os.urandom(32)}, namespace, owner="root")
        def denied_key():
            attempt = shlex.join(["sudo", *lookup])
            diagnostic = ssh(state, RECOVERY, f'if result=$({attempt} 2>&1); then exit 9; fi; printf "%s\\n" "$result"')
            if b"invalid storage encryption key envelope" not in diagnostic:
                raise RuntimeError("the restored metadata has not reached the authorized key check")
            ssh(state, RECOVERY, f"sudo test ! -e {output}")

        eventually(denied_key, 30)
        key = state / "storage-pki/storage-envelope.key"
        upload(state, RECOVERY, {key_file: key.read_bytes()}, namespace, owner="root")
        eventually(lambda: ssh(state, RECOVERY, shlex.join(["sudo", *lookup])), 30)
        resolver = f"{namespace}/resolver.hosts"
        script = f"mount --bind {resolver} /etc/hosts; exec {namespace}/bin/ocean-control-plane -config {namespace}/api.json"
        ssh(state, RECOVERY, shlex.join(["sudo", "systemd-run", "--quiet", "--unit", unit_names[1], "unshare", "--mount", "--propagation",
                                         "private", "/bin/sh", "-ec", script]))
        eventually(lambda: ssh(state, OPERATOR, f"curl --noproxy '*' -fsS --max-time 3 --resolve {ARM}:443:{IP} "
                                f"--cacert {DEST}/pki/ingress-ca.pem https://{ARM}/readyz"), 30)
        op_path = f"/opt/ocean-recovery-client-{run_id}"
        upload(state, OPERATOR, {"resolver.hosts": hosts}, op_path)
        checked = invoke("metadata-check", f"{op_path}/resolver.hosts")
        ssh(state, RECOVERY, "sudo env OCEAN_AGENT_DEFER_START=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
            "ceph-common cryptsetup-bin e2fsprogs && sudo apt-get clean")
        backend = {"pool": POOL, "client": CLIENT, "cephConfig": f"{namespace}/ceph.conf", "keyring": f"{namespace}/ceph.key", "mountRoot": f"{namespace}/mounts"}
        credentials = command(state, ["ceph", "auth", "get", f"client.{CLIENT}"])
        with tempfile.TemporaryDirectory(prefix="ocean-restore-test-") as tmp:
            binary = Path(tmp) / "storage.test"
            subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary), "./internal/storage"],
                           cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
            upload(state, RECOVERY, {"ceph.conf": command(state, ["cat", f"{FILES}/ceph.conf"]), "ceph.key": credentials,
                                     "volume.rbd": encrypted, "rbd.json": json.dumps(backend).encode(),
                                     "bin/storage.test": binary.read_bytes()}, namespace, owner="root")
        args = ["sudo", "env", f"OCEAN_E2E_RBD_CONFIG={namespace}/rbd.json", f"OCEAN_E2E_RBD_KEY={output}",
                f"OCEAN_E2E_RBD_ID={mounted_copy}", f"OCEAN_E2E_RBD_BACKUP={namespace}/volume.rbd", "OCEAN_E2E_RBD_MODE=recovery-copy",
                f"OCEAN_E2E_RBD_CHECKSUM={share['checksum']}", f"{namespace}/bin/storage.test", "-test.run=^TestEncryptedRBDDataPath$", "-test.v"]
        shell_arg = shlex.join(args)
        logs = ssh(state, RECOVERY, f'if result=$({shell_arg} 2>&1); then printf "%s\\n" "$result"; '
                                    'else status=$?; printf "%s\\n" "$result" >&2; exit "$status"; fi').decode()
        if "--- PASS: TestEncryptedRBDDataPath" not in logs:
            raise RuntimeError("the restored data verification did not run")
        elapsed = round((time.monotonic() - started) * 1000)
        if elapsed > RECOVERY_DEADLINE_MS:
            raise RuntimeError("the isolated recovery exceeded the declared deadline")
        (state / "evidence/storage-recovery-data.log").write_text(logs)
        return {"recoveryHost": RECOVERY, "recoveryMs": elapsed, "deadlineMs": RECOVERY_DEADLINE_MS, "metadataSnapshotSHA256": hashlib.sha256(metadata).hexdigest(),
                "encryptedBackupSHA256": hashlib.sha256(encrypted).hexdigest(), "separateWrappingKeyRequired": True,
                "originalVolumeUnmodified": True, "restoredDataVerified": True, **checked}
    finally:
        for name in reversed(unit_names):
            ssh(state, RECOVERY, f"sudo systemctl stop {name}.service")
        if unit_names:
            images = json.loads(command(state, ["rbd", "ls", POOL, "--format", "json"]))
            if mounted_copy in images:
                command(state, ["rbd", "snap", "purge", f"{POOL}/{mounted_copy}"])
                command(state, ["rbd", "rm", f"{POOL}/{mounted_copy}"])
            ssh(state, RECOVERY, f"sudo find {namespace} -xdev -type f \\( -name '*.key' -o -name '*.secret' \\) -delete")
