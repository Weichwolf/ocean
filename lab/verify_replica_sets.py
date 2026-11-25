#!/usr/bin/env python3
"""Verify local redundancy and autoscaling with the Azure CLI and a real KVM node fault."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import sys
import time
from uuid import uuid4

sys.dont_write_bytecode = True
from prepare_application_gateway import GATEWAYS
from region import OPERATOR, ROOT, eventually, run, ssh, upload
from verify_container_groups import pinned_image
from verify_egress_hosts import require, status
from verify_functions import CUSTOMER
from verify_https_hosts import DEST, PROBE, cleanup_probe, configure_probe
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_storage_mounts import boot

LOGICAL_DEADLINE_MS = 8000
RETRIES = 4
FAULT_OBSERVATION_SECONDS = 75


def ready_hosts(view):
    return {member["host"] for member in view["members"] if member["state"] == "Ready"}


def summarize(requests):
    return {"requests": len(requests), "attempts": sum(len(item["attempts"]) for item in requests),
            "failedAttempts": sum(attempt["status"] != "200" for item in requests for attempt in item["attempts"]),
            "maximumLogicalMs": max(item["durationMs"] for item in requests),
            "instances": sorted({item["instance"] for item in requests if "instance" in item})}


def assert_requests(requests):
    require(len(requests) >= 3 and all("instance" in row and row["durationMs"] <= LOGICAL_DEADLINE_MS for row in requests),
            f"one or more logical HTTPS requests exceeded the retry policy: {summarize(requests)}")


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "functions_cli.py", "application_gateway_cli.py",
                                    "replicas_cli.py", "testdata/arm-contract.tsv"))
    fixture = f"/tmp/ocean-replicas-{uuid4().hex[:12]}.secret"
    image = pinned_image("busybox")
    traffic_file = ROOT / "tests/e2e/replica_traffic.py"

    def cli(phase, desired=2, excluded_host=""):
        print(f"Replica lab phase {phase} ({desired} target)", file=sys.stderr, flush=True)
        command = shlex.join(["python3", f"{CLIENT}/replicas_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix",
                              f"{CLIENT}/arm-contract.tsv", "--fixture", fixture, "--phase", phase, "--image", image,
                              "--target", str(desired), "--excluded-host", excluded_host])
        return json.loads(ssh(state, OPERATOR, command))

    def restore(node):
        boot(state, node)
        if node in GATEWAYS:
            eventually(lambda: ssh(state, node, "systemctl is-active --quiet ocean-lab-https-slot.service && "
                                               "systemctl is-active --quiet ocean-https-agent.service"), 35)

    failed_host = None
    probe = False
    try:
        setup = cli("setup")
        ingress = cli("publish")
        host, address = ingress["host"], ingress["address"]
        configure_probe(state, ingress["certificate"].encode(), CUSTOMER, "customer0", address)
        probe = True
        upload(state, CUSTOMER, {"replica_traffic.py": traffic_file.read_bytes()}, DEST)

        def traffic(duration, *, cached=False, burn=False):
            args = ["sudo", "ip", "netns", "exec", PROBE, "python3", f"{DEST}/replica_traffic.py", "--host", host,
                    "--ca", f"{DEST}/ca.pem", "--duration", str(duration), "--retries", str(RETRIES)]
            if cached:
                args += ["--address", address]
            if burn:
                args += ["--burn"]
            return json.loads(ssh(state, CUSTOMER, shlex.join(args)))

        def resolve():
            raw = ssh(state, CUSTOMER, shlex.join(["sudo", "ip", "netns", "exec", PROBE, "getent", "ahostsv4", host]))
            require({line.split()[0] for line in raw.decode().splitlines()} == {address}, "replica host DNS resolved to an unexpected address")
        eventually(resolve, 12)
        baseline = traffic(4)
        assert_requests(baseline)
        require(len(summarize(baseline)["instances"]) == 2, "the HTTPS listener did not use both fixed replicas")
        with ThreadPoolExecutor(max_workers=2) as pool:
            load = pool.submit(traffic, 18, burn=True)
            during_fixed = cli("show")
            fixed_requests = load.result()
        assert_requests(fixed_requests)
        before_fault = cli("show")
        require(all(view["desiredReplicas"] == view["readyReplicas"] == 2 and view["policy"]["mode"] == "Fixed"
                    for view in (during_fixed, before_fault)), "varying demand changed the fixed replica count")
        before_hosts = ready_hosts(before_fault)
        failed_host = sorted(before_hosts)[0]
        powered_off = failed_host

        with ThreadPoolExecutor(max_workers=3) as pool:
            fresh = pool.submit(traffic, FAULT_OBSERVATION_SECONDS)
            cached = pool.submit(traffic, FAULT_OBSERVATION_SECONDS, cached=True)
            time.sleep(3)
            fault_start = time.monotonic()
            run([ROOT / "bin/ocean-lab", "stop", "-state", state, failed_host])
            require(status(state).get(failed_host) is False, "the selected compute VM did not power off")
            management_future = pool.submit(eventually, lambda: cli("management"), 55)
            recovered = eventually(lambda: cli("wait", excluded_host=failed_host), 65)
            recovery_ms = round((time.monotonic() - fault_start)*1000)
            after_hosts = ready_hosts(recovered)
            require(len(after_hosts) == 2 and failed_host not in after_hosts and len(after_hosts-before_hosts) == 1,
                    "the fixed controller did not start a different reserved replica after actual KVM host failure")
            management = management_future.result()
            fresh_rows, cached_rows = fresh.result(), cached.result()
        for rows in (fresh_rows, cached_rows):
            assert_requests(rows)
        require(recovery_ms < FAULT_OBSERVATION_SECONDS*1000, "replica replacement exceeded the local lab deadline")
        restore(failed_host)
        failed_host = None

        policy = cli("autoscale")
        require(policy["policy"]["mode"] == "Local", "the local CPU autoscaling policy did not round-trip")
        demand_at = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            demand = pool.submit(traffic, 35, burn=True)
            scaled_out = cli("wait", 3)
            scaled_out_at = time.monotonic()
            demand_rows = demand.result()
        assert_requests(demand_rows)
        quiet_at = time.monotonic()
        scaled_in = cli("wait", 2)
        scale_in_ms = round((time.monotonic() - quiet_at)*1000)
        recovered_requests = traffic(4)
        assert_requests(recovered_requests)
        scale_out_ms = round((scaled_out_at - demand_at)*1000)
        require(scale_out_ms <= 65000 and scale_in_ms <= 65000, "autoscaling exceeded the local profile limits")
        require(len(ready_hosts(scaled_out)) == 3 and len(ready_hosts(scaled_in)) == 2, "the runtime replica count did not follow local CPU demand")
        require(len(summarize(recovered_requests)["instances"]) == 2, "scale-in withdrew a live backend below the local tier minimum")
        return {"setup": setup, "initialBackends": ingress["backends"], "logicalDeadlineMs": LOGICAL_DEADLINE_MS,
                "retryLimit": RETRIES, "fixedCountAfterLoad": before_fault["readyReplicas"],
                "faultHost": powered_off, "gatewayRejoinedAfterBoot": powered_off in GATEWAYS, "beforeHosts": sorted(before_hosts), "afterHosts": sorted(after_hosts),
                "replacementMs": recovery_ms, "replacementLimitMs": FAULT_OBSERVATION_SECONDS*1000,
                "freshDNS": summarize(fresh_rows), "cachedDNS": summarize(cached_rows), "freshDNSAttempts": fresh_rows,
                "cachedDNSAttempts": cached_rows, "managementDuringFault": management, "scaleOutReadyHosts": sorted(ready_hosts(scaled_out)),
                "scaleInReadyHosts": sorted(ready_hosts(scaled_in)), "scaleInAfterDemandMs": scale_in_ms,
                "scaleOutMs": scale_out_ms, "scaleDeadlineMs": 65000, "image": image}
    finally:
        try:
            if failed_host:
                restore(failed_host)
            if probe:
                cleanup_probe(state, CUSTOMER)
        finally:
            cli("cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    result = verify(state)
    (evidence / "replica-sets.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Fixed replicas served through KVM host loss and CPU policy scaled the local pool out and in.")


if __name__ == "__main__":
    main()
