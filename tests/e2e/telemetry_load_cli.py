#!/usr/bin/env python3
"""Provision and inspect isolated workloads for the telemetry acceptance cases."""

import argparse
import json
import os
import shlex
import tempfile
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from functions_cli import command
from identity_cli import AzureCLI

LOAD = """set -eu
dd if=/dev/zero of=/dev/shm/ocean-fixture bs=1M count=12 2>/dev/null
printf 'ocean telemetry load ready\n'
(while :; do :; done) &
exec httpd -f -p 8080 -h /dev/shm
"""
CANARY = """set -eu
printf 'ocean telemetry canary ready\n'
exec httpd -f -p 8080
"""


def verify(settings, matrix, fixture, phase, image, start, end):
    if phase == "setup":
        customer, foreign = create_customers(settings)
        record = {"tenant": customer, "foreign": foreign, "group": "usage-" + uuid4().hex[:10],
                  "app": "load", "kind": "Microsoft.ContainerInstance/containerGroups"}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(record, stream)
    elif fixture.exists():
        record = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"removed": True}
    else:
        raise RuntimeError("telemetry load fixture was not set up")
    customer = record["tenant"]
    group = record["group"]
    with tempfile.TemporaryDirectory(prefix="ocean-telemetry-load-") as temporary:
        cli = AzureCLI(customer, temporary)
        cli.login_device()
        contract = GroupContract(cli, load_matrix(matrix))
        rows = load_matrix(matrix, "OBS-02") | load_matrix(matrix, "CONTAINER-01") | load_matrix(matrix, "NETWORK-01")
        base = f"/subscriptions/{customer['subscription']}/resourceGroups/{group}/providers/"
        resource = base + record["kind"] + "/load"
        values = {"origin": contract.origin, "location": customer["location"], "group": group, "vnet": "private",
                  "vnet_prefix": "10.97.1.0/24", "subnet": "load", "subnet_prefix": "10.97.1.0/27", "image": image,
                  "subnet_id": base + "Microsoft.Network/virtualNetworks/private/subnets/load", "id": resource,
                  "start": start, "end": end, "name": "load"}

        def run(label, *, expected=None, **change):
            return command(cli, rows, contract.version, values | change, label, expected=expected)

        def launch(name, program, cpu, memory):
            result = run("telemetry-load-create", name=name, program=shlex.join(["/bin/sh", "-c", program]), cpu=cpu, memory=memory)
            observed = run("container-show", name=name)
            running = observed.get("instanceView", {}).get("state") or observed.get("properties", {}).get("instanceView", {}).get("state")
            raw = cli.run(*command_args(rows["container-logs"], contract.version, **(values | {"name": name})))
            if result["id"] != observed["id"] or running != "Running" or f"ocean telemetry {name} ready" not in raw:
                raise RuntimeError("the telemetry test workload did not reach its actual runtime and log marker")
            return {"id": observed["id"], "tenant": customer["tenant"], "subscription": customer["subscription"],
                    "azureCLI": contract.version["azure-cli"], "port": 8080, "running": True, "logsVerified": True}

        if phase == "setup":
            contract.command("group-create", group)
            run("vnet-create")
            return launch("load", LOAD, "0.6", "0.25")
        if phase == "provision":
            result = launch("canary", CANARY, "0.25", "0.0625")
            run("container-delete", name="canary")
            return result
        if phase == "metrics":
            result = run("container-metrics-list")
            return {series["name"]["value"]: [point["average"] for points in series["timeseries"] for point in points["data"]
                                              if point.get("average") is not None] for series in result["value"]}
        if phase == "unavailable":
            run("container-metrics-list", expected="TelemetryUnavailable")
            return {"telemetryUnavailable": True}
        if phase == "cleanup":
            for name in ("canary", "load"):
                run("container-delete", name=name)
            contract.delete_group(group)
            fixture.unlink()
            return {"removed": True}
    raise RuntimeError("unrecognized telemetry load phase")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=("setup", "provision", "metrics", "unavailable", "cleanup"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--start", default="")
    parser.add_argument("--end", default="")
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix, args.fixture, args.phase, args.image, args.start, args.end)))


if __name__ == "__main__":
    main()
