#!/usr/bin/env python3
"""Verify Azure CLI container lifecycle, isolation, limits, and released allocations in KVM."""

import argparse
import hashlib
import json
import shlex
import sys
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from prepare_container_groups import SERVICE
from region import OPERATOR, ROOT, etcdctl, eventually, ssh
from verify_egress_hosts import require, worker_command
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_wireguard_hosts import macvlan

PROBE = "ocean-aci-probe"
PUBLIC_PATH = "/?probe=ocean-public-probe"
REGION = "/ocean/v1/regions/farm-1"


def pinned_image(key):
    # This scalar lock format is intentionally parseable by the standard library.
    lock = (ROOT / "tests/e2e/testdata/images.lock.yaml").read_text()
    lines = lock.splitlines()
    index = lines.index(f"  {key}:")
    fields = dict(line.strip().split(": ", 1) for line in lines[index + 1:index + 4])
    return f"{fields['repository']}@{fields['digest']}"


def resources(result):
    return f"{REGION}/tenants/{result['tenant']}/arm/{result['subscription']}"


def assignment(state, result):
    resource = result["id"].lower()
    group = resource.split("/resourcegroups/", 1)[1].replace("/providers/", "/", 1)
    prefix = resources(result) + "/containers/" + group
    record = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix} --print-value-only")))
    placed = record["reservation"]
    digest = hashlib.sha256(f"{result['tenant']}/{result['subscription']}/{placed['id']}/{placed['generation']}".encode()).hexdigest()
    return placed["hostId"], "ocean-" + digest[:32]


def runtime(state, host, name):
    result = worker_command(state, "\n".join([f"pid=$(pod inspect --format '{{{{.State.Pid}}}}' {name})", "test \"$pid\" -gt 1",
                                            "pod info --format '{{.Host.Security.Rootless}}'", 'ps -o ni= -p "$pid"',
                                            f"pod exec {name} cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max",
                                            f"pod inspect --format '{{{{.State.StartedAt}}}}' {name}"]), host).splitlines()
    require([line.strip() for line in result[:-1]] == ["true", "10", "25000 100000", "67108864"],
            f"unexpected rootless, process priority, or cgroup limits on {host}")
    return result[-1]


def request(state, observer, address, port, route="/"):
    return ssh(state, observer, f"sudo ip netns exec {PROBE} curl --noproxy '*' -sS --connect-timeout 1 --max-time 2 http://{address}:{port}{route}")


def cannot_connect(state, observer, address, port):
    response = ssh(state, observer, f"rc=0; sudo ip netns exec {PROBE} curl --noproxy '*' -s --connect-timeout 1 --max-time 2 "
                   f"-o /dev/null http://{address}:{port}/ || rc=$?; printf '%s' \"$rc\"")
    require(response in {b"7", b"28"}, "a removed or stopped container endpoint was reachable")


def check_quota_released(state, result):
    raw = ssh(state, OPERATOR, etcdctl(f"get {resources(result)}/placement-usage --print-value-only"))
    require(json.loads(raw) == {"cpuMillis": 0, "memoryMiB": 0}, "deletion left quota allocated")


def check_no_secret(state, results, fixture):
    # Keep both sources inside the restricted operator process. Return only
    # a Boolean and a record count, never the environment value or store data.
    command = etcdctl(f"get {resources(results)}/ --prefix --print-value-only")
    script = f"""import json, subprocess
from pathlib import Path
marker=json.loads(Path({fixture!r}).read_bytes())['secret'].encode()
raw=subprocess.run({shlex.split(command)!r}, check=True, stdout=subprocess.PIPE).stdout
assert b'/reconcile' in raw and marker not in raw
"""
    ssh(state, OPERATOR, "python3 -", script.encode())


def verify(state, observer):
    prepare_operator_client(state, ("arm_cli.py", "container_cli.py", "testdata/arm-contract.tsv"))
    fixture = f"/tmp/ocean-container-{uuid4().hex}.secret"

    def invoke(phase, image=None):
        args = ["python3", f"{CLIENT}/container_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix",
                f"{CLIENT}/arm-contract.tsv", "--fixture", fixture, "--phase", phase]
        if image:
            args += ["--image", image]
        return json.loads(ssh(state, OPERATOR, shlex.join(args)))

    ssh(state, observer, f"sudo test ! -e /run/netns/{PROBE}")
    try:
        ssh(state, observer, f"""set -eu
sudo ip netns add {PROBE}
{macvlan(PROBE, 'work0', 'external0', '198.51.100.33/24')}
{macvlan(PROBE, 'work0', 'internal0', '10.91.1.30/24')}
sudo ip -n {PROBE} link set lo up
""")
        invoke("setup")
        nginx, busybox = pinned_image("nginx"), pinned_image("busybox")
        public = invoke("public-create", nginx)
        host, name = assignment(state, public)
        require(host != observer, "the external probe and the container must run on separate KVM guests")
        address = public["address"]
        started = runtime(state, host, name)
        eventually(lambda: request(state, observer, address, 80), 15)
        request(state, observer, address, 80, PUBLIC_PATH)
        invoke("public-logs")
        invoke("stop")
        eventually(lambda: cannot_connect(state, observer, address, 80), 9)
        invoke("start")
        eventually(lambda: request(state, observer, address, 80), 15)
        restarted = runtime(state, host, name)
        require(restarted != started, "start did not start a new process")
        invoke("restart")
        eventually(lambda: request(state, observer, address, 80), 15)
        require(runtime(state, host, name) != restarted, "restart returned without restarting the actual workload")
        ssh(state, host, f"sudo systemctl is-active --quiet {SERVICE}")
        deleted = invoke("public-delete")
        check_quota_released(state, public)
        cannot_connect(state, observer, address, 80)
        replay = invoke("public-create", nginx)
        require(replay["address"] == address, "deletion did not release the public address for reuse")
        invoke("public-delete")
        check_quota_released(state, public)
        private = invoke("private-create", busybox)
        private_host, private_name = assignment(state, private)
        require(private_host != observer, "the private probe and container must run on separate KVM guests")
        runtime(state, private_host, private_name)
        result = eventually(lambda: request(state, observer, private["address"], 8080), 15)
        require(result.strip() == b"configuration-present", "the workload did not receive the expected variables")
        invoke("private-logs")
        check_no_secret(state, private, fixture)
        conflict = invoke("foreign-conflict", busybox)
        invoke("private-delete")
        cannot_connect(state, observer, private["address"], 8080)
        check_quota_released(state, private)
        return {"azureCLI": public["azureCLI"], "apiVersion": "2024-05-01-preview", "publicImage": nginx,
                "privateImage": busybox, "rootless": True, "nice": 10, "cpuQuota": "25000 100000",
                "memoryLimitBytes": 67108864, "publicHTTP": True, "privateHTTP": True, "logEventFound": True,
                "stoppedEndpointClosed": True, "restartChangedProcess": True, "deletedEndpointClosed": True,
                "publicAddressReused": True, "quotaReleased": True, "standardAndSecureVariablesDelivered": True,
                "secureValueAbsentFromInventoryAuditAndExposedLogs": True, **conflict, **deleted}
    finally:
        try:
            invoke("cleanup")
        finally:
            ssh(state, observer, f"if sudo test -e /run/netns/{PROBE}; then sudo ip netns delete {PROBE}; fi")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--observer", default="farm-1-node-06")
    args = parser.parse_args()
    state = args.state.resolve()
    report = verify(state, args.observer)
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "container-groups.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Azure CLI {report['azureCLI']} verified public and private rootless workloads, cgroups, secrets, lifecycle, and address reuse.")


if __name__ == "__main__":
    main()
