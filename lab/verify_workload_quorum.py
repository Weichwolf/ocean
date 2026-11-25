#!/usr/bin/env python3
"""Fault the management and storage quorums separately against a live mounted workload."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import sys
import time
from uuid import uuid4

sys.dont_write_bytecode = True
from keycloak import REPLICAS, provider_health
from region import NODES, OPERATOR, etcdctl, eventually, ssh
from storage import NODES as STORAGE, command as ceph, pool_ready
from verify_container_groups import pinned_image
from verify_egress_hosts import require, worker_command
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_region import expect_failure, ready
from verify_storage_mounts import verify as verify_storage, workload_record


def service(state, targets, action):
    def change(item):
        node, unit = item
        ssh(state, node, f"sudo systemctl {action} {unit}")
    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        list(pool.map(change, targets))


def cli(state, fixture, phase):
    args = ["python3", f"{CLIENT}/quorum_cli.py", "--matrix", f"{CLIENT}/arm-contract.tsv", "--fixture", fixture,
            "--image", pinned_image("busybox"), "--phase", phase]
    return json.loads(ssh(state, OPERATOR, shlex.join(args)))


def management_fault(state, host, runtime, fixture):
    stopped = [(node, "ocean-etcd.service") for node in list(NODES)[:2]]
    survivor = [list(NODES.values())[-1]]
    marker = uuid4().hex
    started = time.monotonic()
    try:
        service(state, stopped, "stop")
        ssh(state, OPERATOR, etcdctl("endpoint status", survivor))
        expect_failure(lambda: ready(state), "regional API readiness without management quorum")
        print("Testing a pinned CLI mutation and live storage I/O without management quorum.", flush=True)
        refused = cli(state, fixture, "outage")
        program = f"printf '%s\\n' {marker} > /data/quorum-proof && sync -f /data/quorum-proof && cat /data/quorum-proof"
        data = worker_command(state, f"pod exec {runtime} " + shlex.join(["sh", "-ec", program]), host)
        require(data == marker, "the running workload lost its healthy mounted data path")
    finally:
        service(state, stopped, "start")
        eventually(lambda: ssh(state, OPERATOR, etcdctl("endpoint health --cluster")), 45)
        eventually(lambda: ready(state), 20)
        for node in REPLICAS:
            eventually(lambda node=node: provider_health(state, node), 75)
    replay = cli(state, fixture, "recover")
    return {**refused, **replay, "lawfulExistingWrite": True, "membersStopped": len(stopped),
            "faultAndRecoveryMs": round((time.monotonic()-started)*1000)}


def osd_targets(state):
    tree = json.loads(ceph(state, ["ceph", "osd", "tree", "-f", "json"]))["nodes"]
    hosts = [row for row in tree if row["type"] == "host" and row["name"] in STORAGE]
    require(len(hosts) == 3 and all(len(row["children"]) == 1 for row in hosts), "expected one dedicated storage OSD per host")
    return [(row["name"], row["children"][0]) for row in sorted(hosts, key=lambda row: row["name"])[:2]]


def storage_fault(state, host, runtime, volume):
    targets = osd_targets(state)
    stopped = [(node, f"ceph-osd@{osd}.service") for node, osd in targets]
    started = time.monotonic()
    fault_write = f"printf '%s\\n' unacknowledged > /data/quorum-unconfirmed && sync -f /data/quorum-unconfirmed"
    try:
        service(state, stopped, "stop")
        ceph(state, ["ceph", "osd", "down", *[str(osd) for _, osd in targets]])
        def no_replica_quorum():
            rows = json.loads(ceph(state, ["ceph", "osd", "dump", "-f", "json"]))["osds"]
            require(sum(row["up"] for row in rows) == 1, "storage still has more than one available OSD")
        eventually(no_replica_quorum, 30)
        ready(state)
        print("Testing synchronous volume writes below the two-replica I/O minimum.", flush=True)
        args = shlex.join(["timeout", "--signal=KILL", "5s", "nice", "-n", "10", "podman", "exec", runtime, "sh", "-ec", fault_write])
        attempted = worker_command(state,
            f'status=0; sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" {args} >/dev/null 2>&1 '
            '|| status=$?; printf "%s" "$status"', host)
        require(attempted in ("124", "137"), f"storage returned an unexpected status during lost replication: {attempted}")
    finally:
        service(state, stopped, "start")
    eventually(lambda: pool_ready(state), 140)
    writes = worker_command(state, f"pod exec {runtime} " +
                            shlex.join(["sh", "-ec", "printf '%s\\n' after-recovery > /data/quorum-after && sync -f /data/quorum-after && cat /data/quorum-after"]), host)
    require(writes == "after-recovery", "the same mounted writer did not recover")
    maps = json.loads(ssh(state, host, "sudo rbd device list --format json"))
    require(sum(record["name"] == volume for record in maps) == 1, "storage recovery left duplicate writable mappings")
    return {"osdsStopped": len(stopped), "minimumOSDsForIO": 2, "writeWasUnacknowledged": True,
            "writeExitCode": int(attempted), "sameWriterRecovered": True,
            "faultAndRecoveryMs": round((time.monotonic()-started)*1000)}


def fault_probe(state, host, runtime, writer, invoke, fixture):
    prepare_operator_client(state, ("quorum_cli.py",))
    invoke("cache-arm-token")
    volume = workload_record(state, writer)["volume"]["id"]
    return {"managementQuorum": management_fault(state, host, runtime, fixture),
            "storageReplicaQuorum": storage_fault(state, host, runtime, volume)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--observer", default="farm-1-node-04")
    args = parser.parse_args()
    state = args.state.resolve()
    proof = verify_storage(state, args.observer, False, fault_probe=fault_probe)
    folder = state/"evidence"
    folder.mkdir(mode=0o700, exist_ok=True)
    (folder/"workload-quorum.json").write_text(json.dumps(proof, indent=2)+"\n")
    print("Management and storage faults independently preserved workload data and reservation consistency.")


if __name__ == "__main__":
    main()
