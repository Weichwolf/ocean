#!/usr/bin/env python3
"""Fault the telemetry quorum while proving scoped measurements and real volume fencing."""

import argparse
import json
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from prepare_telemetry import SERVICE
from region import NODES, OPERATOR, eventually, ssh
from verify_container_groups import assignment, pinned_image
from verify_egress_hosts import require, worker_command
from verify_enrollment import CONFIG_DIR, HOST_STATE, agent_command, wait_ready
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_storage_mounts import verify as verify_storage_fencing

REPORTING_DEADLINE = 45
CPU_TOLERANCE = 100
MEMORY_TOLERANCE = 4 << 20
OUTAGE_MINIMUM_DROP = 1
PROFILE_MAXIMUM_DROP = 160


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def store_action(state, action):
    def run(node):
        ssh(state, node, f"sudo systemctl {action} {SERVICE}")
    with ThreadPoolExecutor(max_workers=len(NODES)) as pool:
        list(pool.map(run, NODES))


def outbox(state, worker):
    command = f"cd / && sudo cat {HOST_STATE}/telemetry-outbox.json"
    data = ssh(state, worker, command)
    queue = json.loads(data)
    return {"bytes": len(data), "pending": len(queue.get("pending") or []), "dropped": queue["dropped"],
            "reported": sum(item["sample"]["gap"]["dropped"] for item in queue.get("losses") or []),
            "losses": queue.get("losses") or [], "oversized": queue.get("oversized", 0)}


def control_measurement(state, worker, name):
    program = f"""set -eu
pid=$(pod inspect --format '{{{{.State.Pid}}}}' {shlex.quote(name)})
group=$(sed -n 's,^0::/,,p' /proc/"$pid"/cgroup)
test -n "$group"
path="/sys/fs/cgroup/$group"
before=$(date +%s%N)
prior=$(awk '$1 == "usage_usec" {{print $2}}' "$path/cpu.stat")
sleep 5
now=$(date +%s%N)
current=$(awk '$1 == "usage_usec" {{print $2}}' "$path/cpu.stat")
printf '%s %s %s\n' "$((current - prior))" "$((now - before))" "$(cat "$path/memory.current")"
"""
    spent, elapsed, memory = map(int, worker_command(state, program, worker).split())
    return {"cpuMillis": spent * 1_000_000 / elapsed, "memoryBytes": memory}


def verify(state, observer):
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "functions_cli.py", "application_gateway_cli.py",
                                    "insights_cli.py", "telemetry_load_cli.py", "testdata/arm-contract.tsv"))
    fixture = f"/tmp/ocean-telemetry-load-{uuid4().hex[:12]}.secret"
    image = pinned_image("busybox")

    def run(phase, start=None, end=None):
        args = ["python3", f"{CLIENT}/telemetry_load_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix",
                f"{CLIENT}/arm-contract.tsv", "--fixture", fixture, "--phase", phase, "--image", image]
        if start is not None:
            args += ["--start", stamp(start), "--end", stamp(end)]
        return json.loads(ssh(state, OPERATOR, shlex.join(args)))

    faulted = False
    try:
        load = run("setup")
        worker, container = assignment(state, load)
        configuration = json.loads(ssh(state, worker, f"sudo cat {CONFIG_DIR}/config.json"))
        budget = configuration["enrollment"]["telemetryBufferBytes"]
        require(budget == 4096, "the fault profile requires a 4096-byte buffer")
        before = datetime.now(timezone.utc)
        cpu_start = datetime.now(timezone.utc)
        observed = control_measurement(state, worker, container)
        cpu_end = datetime.now(timezone.utc) + timedelta(seconds=2)
        require(400 < observed["cpuMillis"] < 650 and observed["memoryBytes"] >= 12 << 20,
                f"the load generator did not deliver the declared CPU and memory profile: {observed}")

        def verify_metrics():
            result = run("metrics", cpu_start, cpu_end)
            require(result["CpuUsage"] and result["MemoryUsage"], "load samples have not arrived")
            require(all(abs(value - observed["cpuMillis"]) <= CPU_TOLERANCE for value in result["CpuUsage"]),
                    f"Azure Monitor CPU series differs from measured runtime counters: {result['CpuUsage']}")
            require(all(abs(value - observed["memoryBytes"]) <= MEMORY_TOLERANCE for value in result["MemoryUsage"]),
                    f"Azure Monitor memory series differs from measured runtime counters: {result['MemoryUsage']}")
            return result

        metrics = eventually(verify_metrics, REPORTING_DEADLINE)
        baseline = outbox(state, worker)
        start = datetime.now(timezone.utc)
        faulted = True
        store_action(state, "stop")
        availability = run("unavailable", before, datetime.now(timezone.utc))
        canary = run("provision")
        storage = verify_storage_fencing(state, observer, True)
        require(storage["powerOffConfirmed"] and storage["persistentDataMatched"] and storage["oldVolumeMapAbsentAfterReboot"],
                "verified fencing and single-writer recovery must complete during the telemetry outage")

        def backlog():
            observed = outbox(state, worker)
            require(observed["bytes"] <= budget and observed["oversized"] == baseline["oversized"],
                    "the telemetry queue exceeded the configured budget or overflowed gap reporting")
            require(observed["dropped"] - baseline["dropped"] >= OUTAGE_MINIMUM_DROP and observed["reported"] >= OUTAGE_MINIMUM_DROP,
                    "the fault has not yet filled the durable buffer")
            return observed

        latest = eventually(backlog, 50)
        agent_command(state, worker, "systemctl", "--user", "restart", "ocean-agent.service")
        wait_ready(state, worker)
        restarted = eventually(backlog, 10)
        require(restarted["dropped"] >= latest["dropped"] and restarted["reported"] >= latest["reported"],
                "restarting the worker lost acknowledged pending data or its gap counter")
        require(restarted["dropped"] - baseline["dropped"] <= PROFILE_MAXIMUM_DROP, "the telemetry loss limit was exceeded")

        recovery = time.monotonic()
        store_action(state, "start")
        faulted = False

        def recovered():
            queue = outbox(state, worker)
            require(queue["pending"] <= 2 and not queue["losses"], "the worker still has a backlog after telemetry quorum recovered")
            return queue

        settled = eventually(recovered, REPORTING_DEADLINE)
        recovery_seconds = time.monotonic() - recovery
        stop = datetime.now(timezone.utc)
        args = ["python3", f"{CLIENT}/insights_cli.py", "--fixture", fixture, "--matrix", f"{CLIENT}/arm-contract.tsv",
                "--timespan", f"{start.isoformat()}/{stop.isoformat()}"]
        gap = json.loads(ssh(state, OPERATOR, shlex.join(args)))
        reported = sum(row["Dropped"] for row in gap["gaps"])
        require(reported >= OUTAGE_MINIMUM_DROP and reported <= settled["dropped"] - baseline["dropped"],
                f"scoped gap rows did not match bounded worker loss: {reported}")
        require(recovery_seconds <= REPORTING_DEADLINE, "telemetry exceeded its declared recovery limit")
        recovered_metrics = run("metrics", start, stop)
        require(recovered_metrics["CpuUsage"] and recovered_metrics["MemoryUsage"], "restored telemetry did not expose retained samples")
        return {"cases": ["OBS-02", "OBS-04"], "azureCLI": load["azureCLI"], "meteredImage": image,
                "controlledUsage": observed, "cliMetrics": metrics, "cpuToleranceMillicores": CPU_TOLERANCE,
                "memoryToleranceBytes": MEMORY_TOLERANCE, "telemetryBackendFaultedMembers": len(NODES), "bufferBudgetBytes": budget,
                "observedBufferBytes": max(latest["bytes"], restarted["bytes"]), "persistedAcrossAgentRestart": True,
                "measuredDroppedSamples": settled["dropped"] - baseline["dropped"], "maximumAllowedDroppedSamples": PROFILE_MAXIMUM_DROP,
                "tenantReportedDroppedSamples": reported, "reportedGaps": gap["gaps"], "telemetryQueryUnavailableDuringOutage": availability,
                "provisioningAndLogsDuringOutage": canary["running"] and canary["logsVerified"], "fencingDuringOutage": storage,
                "outageMs": round((stop - start).total_seconds()*1000), "telemetryRecoveryMs": round(recovery_seconds*1000),
                "telemetryRecoveryLimitMs": REPORTING_DEADLINE*1000, "recoveredTelemetry": recovered_metrics}
    finally:
        try:
            if faulted:
                store_action(state, "start")
        finally:
            run("cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--fencing-observer", default="farm-1-node-04")
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    result = verify(state, args.fencing_observer)
    (evidence / "telemetry-outage.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Telemetry recovered its bounded queue after provision and real storage fencing during a three-member outage.")


if __name__ == "__main__":
    main()
