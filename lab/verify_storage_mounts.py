#!/usr/bin/env python3
"""Verify persistent container mounts and out-of-band writer fencing in the KVM lab."""

import argparse
import base64
import hashlib
import json
import shlex
import sys
import time
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from fencing import sign_terminal_state
from storage_recovery import verify_recovery
from region import ARM, DEST, OPERATOR, ROOT, etcdctl, eventually, run, ssh, upload
from verify_container_groups import assignment, pinned_image, resources
from verify_egress_hosts import require, worker_command
from verify_enrollment import wait_ready
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_wireguard_hosts import macvlan

PROBE = "ocean-storage-probe"
PROFILE = ROOT / "lab/profiles/storage-ha.yaml"
PARTITION = "ocean_storage_management_partition"


def partition(state, host):
    rules = f"""destroy table inet {PARTITION}
add table inet {PARTITION}
add chain inet {PARTITION} output {{ type filter hook output priority filter; policy accept; }}
add rule inet {PARTITION} output ip daddr {{ 10.231.1.10, 10.231.1.11, 10.231.1.12, 10.231.1.13 }} tcp dport {{ 443, 8080, 8443 }} counter drop
"""
    ssh(state, host, "sudo nft -f -", rules.encode())


def clear_partition(state, host):
    ssh(state, host, f"if sudo nft list table inet {PARTITION} >/dev/null 2>&1; then sudo nft delete table inet {PARTITION}; fi")


def send_fence(state, message):
    name = f"fence-{uuid4().hex}.json"
    upload(state, OPERATOR, {name: json.dumps(message).encode()}, CLIENT)
    try:
        status = ssh(state, OPERATOR, f"curl --silent --show-error --max-time 8 --cacert {DEST}/pki/ingress-ca.pem "
                     f"-o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json' --data-binary @{CLIENT}/{name} "
                     f"https://{ARM}/ocean/storage/fences")
        return int(status)
    finally:
        ssh(state, OPERATOR, f"sudo unlink {CLIENT}/{name}")


def workload_record(state, result):
    key = resources(result) + "/containers/" + result["id"].lower().split("/resourcegroups/", 1)[1].replace("/providers/", "/", 1)
    return json.loads(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only")))


def request(state, observer, address, name):
    result = ssh(state, observer, f"sudo ip netns exec {PROBE} curl --noproxy '*' -fsS --max-time 2 http://{address}:8080/{name}")
    return result.decode().strip()


def boot(state, host):
    run([ROOT / "bin/ocean-lab", "up", "-state", state, "-profile", PROFILE])
    wait_ready(state, host)


def verify(state, observer, fence, archive=None):
    prepare_operator_client(state, ("arm_cli.py", "storage_cli.py", "testdata/arm-contract.tsv"))
    fixture_script = ROOT / "tests/e2e/testdata/workloads/stateful-http/checkpoint.sh"
    upload(state, OPERATOR, {"checkpoint.sh": fixture_script.read_bytes()}, CLIENT)
    fixture = f"/tmp/ocean-files-{uuid4().hex}.secret"
    image = pinned_image("busybox")

    def invoke(phase, resolver=None):
        arguments = ["python3", f"{CLIENT}/storage_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix", f"{CLIENT}/arm-contract.tsv",
                     "--fixture", fixture, "--program", f"{CLIENT}/checkpoint.sh", "--phase", phase, "--image", image]
        command = shlex.join(arguments)
        if resolver is not None:
            script = "mount --bind " + shlex.quote(resolver) + " /etc/hosts; exec runuser -u ocean -- " + command
            command = shlex.join(["sudo", "unshare", "--mount", "--propagation", "private", "/bin/sh", "-ec", script])
        return json.loads(ssh(state, OPERATOR, command))

    stopped_host = None
    isolated_host = None
    try:
        ssh(state, observer, f"sudo test ! -e /run/netns/{PROBE} && sudo ip netns add {PROBE}\n" +
            macvlan(PROBE, "work0", "external0", "198.51.100.34/24"))
        share = invoke("setup")
        writer = invoke("write")
        host, runtime = assignment(state, writer)
        require(host != observer, "the storage worker and probe need separate guests")
        value = eventually(lambda: request(state, observer, writer["address"], "checkpoint"), 12)
        require(value == share["checksum"], "the running workload returned the wrong durable checksum")
        fault = {}
        if fence:
            record = workload_record(state, writer)
            reservation = record["reservation"]
            attestation = {"tenantId": writer["tenant"], "subscriptionId": writer["subscription"],
                           "hostId": host, "placementId": reservation["id"], "generation": reservation["generation"],
                           "volumeId": record["volume"]["id"]}
            bad_signature = {"attestation": base64.b64encode(json.dumps(attestation).encode()).decode(),
                             "signature": base64.b64encode(bytes(64)).decode()}
            require(send_fence(state, bad_signature) == 403, "the API accepted a forged fence")
            partition(state, host)
            isolated_host = host

            def expired():
                key = f"/ocean/v1/regions/farm-1/hosts/live/{host}"
                heartbeat = json.loads(ssh(state, OPERATOR, etcdctl(f"get {key} -w json")))
                require(heartbeat.get("count", 0) == 0, "the old host still has a live placement lease")

            eventually(expired, 24)
            refused = invoke("deny-second")
            partition_marker = hashlib.sha256((share["checksum"] + "partition").encode()).hexdigest()
            action = shlex.join(["sh", "-ec", f"printf '%s\\n' {partition_marker} > /data/partition-proof; sync -f /data/partition-proof"])
            worker_command(state, f"pod exec {runtime} {action}", host)
            started = time.monotonic()
            signed = sign_terminal_state(state, attestation)
            stopped_host = host
            require(send_fence(state, signed) == 204 and send_fence(state, signed) == 204, "a valid writer fence was not repeatable")
            recovery = invoke("recover")
            replacement, _ = assignment(state, recovery)
            require(replacement != host, "the fenced writer was replaced on its old host")
            restored = eventually(lambda: request(state, observer, recovery["address"], "partition-proof"), 15)
            require(restored == partition_marker, "the replacement did not retain the old writer's last persisted data")
            recovery_ms = round((time.monotonic() - started) * 1000)
            boot(state, host)
            stopped_host = None
            devices = json.loads(ssh(state, host, "sudo rbd device list --format json"))
            require(all(device["name"] != record["volume"]["id"] for device in devices), "the old VM regained its writable map")
            clear_partition(state, host)
            isolated_host = None
            fault = {"oldHost": host, "survivingHost": replacement, "writerLeaseExpired": True, "storageWriteDuringPartition": True,
                     "invalidFenceDenied": True, "powerOffConfirmed": True, "recoveryMsIncludingAzureCLI": recovery_ms,
                     "fenceReplayedSafely": True, "oldVolumeMapAbsentAfterReboot": True, **refused}
        else:
            fault.update(invoke("deny-second"))
            volume = workload_record(state, writer)["volume"]["id"]
            fault.update(invoke("stop-writer"))
            if archive is not None:
                fault.update(verify_recovery(state, share, volume, invoke, archive))
            recovery = invoke("recover")
        restored = eventually(lambda: request(state, observer, recovery["address"], "checkpoint"), 15)
        require(restored == share["checksum"], "the replacement returned different persistent data")
        denied = invoke("deny-foreign")
        return {"azureCLI": share["azureCLI"], "shareId": share["shareId"], "checkPointSHA256": share["checksum"],
                "image": image, "persistentDataMatched": True, **denied, **fault}
    finally:
        try:
            if stopped_host:
                boot(state, stopped_host)
            if isolated_host:
                clear_partition(state, isolated_host)
            invoke("cleanup")
        finally:
            ssh(state, observer, f"if sudo test -e /run/netns/{PROBE}; then sudo ip netns delete {PROBE}; fi")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--observer", default="farm-1-node-04")
    parser.add_argument("--fence", action="store_true", help="turn off the isolated writer before granting its volume to a different host")
    parser.add_argument("--restore-from-backups", type=Path, metavar="ETCD_ARCHIVE", help="restore the checkpoint in an isolated recovery VM")
    args = parser.parse_args()
    if args.fence and args.restore_from_backups:
        parser.error("select one fault profile per run")
    state = args.state.resolve()
    evidence = verify(state, args.observer, args.fence, args.restore_from_backups)
    output = state / "evidence"
    output.mkdir(mode=0o700, exist_ok=True)
    name = "storage-fencing.json" if args.fence else "storage-mounts.json"
    if args.restore_from_backups is not None:
        name = "storage-recovery.json"
    (output / name).write_text(json.dumps(evidence, indent=2) + "\n")
    print("Azure CLI mounted the encrypted share and a replacement returned the same stored checkpoint.")


if __name__ == "__main__":
    main()
