#!/usr/bin/env python3
"""Verify the tenant health, audit, and reservation contract through Azure CLI."""

import argparse
import concurrent.futures
import json
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI


def verify(settings, matrix_path, image):
    customer, stranger = create_customers(settings)
    common = load_matrix(matrix_path)
    rows = load_matrix(matrix_path, "OBS-01") | load_matrix(matrix_path, "OBS-02") | load_matrix(matrix_path, "OBS-03") | load_matrix(matrix_path, "CONTAINER-01")
    group = "monitor-" + uuid4().hex[:10]
    pair = ("first", "second")
    with tempfile.TemporaryDirectory(prefix="ocean-monitor-") as directory:
        folder = Path(directory)
        admin = AzureCLI(customer, str(folder / "admin"))
        other = AzureCLI(stranger, str(folder / "other"))
        for cli in (admin, other):
            cli.login_device()
            cli.check_subscription()
        primary = GroupContract(admin, common)
        foreign = GroupContract(other, common)
        values = {"origin": customer["arm"], "subscription": customer["subscription"], "location": customer["location"],
                  "group": group, "image": image}

        def command(label, *, client=admin, expected=None, **arguments):
            args = command_args(rows[label], primary.version, **(values | arguments))
            reply = subprocess.run(["az", *args], env=client.env, capture_output=True, text=True, timeout=90)
            detail = next((line for line in reply.stderr.splitlines() if line.startswith(("ERROR:", "Code:"))), "")
            if any(term in detail.lower() for term in ("bearer", "token", "password", "key=")):
                detail = "[redacted]"
            if expected:
                if reply.returncode == 0 or expected not in reply.stderr:
                    raise RuntimeError(f"{label} did not return {expected} ({reply.returncode}) {detail[:230]}")
                return None
            if reply.returncode:
                raise RuntimeError(f"{label} failed ({reply.returncode}) {detail[:230]}")
            return json.loads(reply.stdout) if reply.stdout.strip() else None

        def reserved():
            return {row["name"]["value"]: (row["currentValue"], row["limit"]) for row in command("regional-usage-show")["value"]}

        def race(name):
            args = command_args(rows["quota-container-create"], primary.version, **(values | {"name": name}))
            reply = subprocess.run(["az", *args], env=admin.env, capture_output=True, text=True, timeout=90)
            if reply.returncode == 0:
                return name, json.loads(reply.stdout)["id"]
            if "QuotaExceeded" in reply.stderr:
                return name, None
            raise RuntimeError(f"{name} returned an unexpected quota-race outcome ({reply.returncode})")

        primary.command("group-create", group)
        foreign.command("group-create", group, "foreign")
        try:
            baseline = reserved()
            if baseline["ContainerGroups"][0] != 0 or baseline["ReservedCPUMillis"] != (0, 1000) or baseline["ReservedMemoryMiB"] != (0, 416):
                raise RuntimeError("the new subscription has an unexpected usage or quota")
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(race, pair))
            admitted = [(name, resource) for name, resource in results if resource]
            if len(admitted) != 1:
                raise RuntimeError("exactly one of the two competing requests must reserve capacity")
            name, resource = admitted[0]
            usage = reserved()
            if usage["ContainerGroups"][0] != 1 or usage["ReservedCPUMillis"] != (600, 1000) or usage["ReservedMemoryMiB"] != (256, 416):
                raise RuntimeError("reserved usage did not match the admitted capacity")
            if command("resource-health-show", id=resource)["properties"]["availabilityState"] != "Available":
                raise RuntimeError("Resource Health did not report the running workload")
            command("resource-health-show", client=other, expected="not found.", id=resource)
            command("regional-usage-show", client=other, expected="not found.")
            usage_path = f"/subscriptions/{values['subscription']}/providers/Microsoft.ContainerInstance/locations/{values['location']}/usages"
            health_path = resource + "/providers/Microsoft.ResourceHealth/availabilityStatuses/current"
            for path, version in ((usage_path, "2025-09-01"), (health_path, "2025-05-01")):
                status, reply = foreign.request("GET", foreign.origin + path, query=f"api-version={version}")
                if status != 404 or reply["error"]["code"] != "SubscriptionNotFound":
                    raise RuntimeError("the server accepted a foreign token for another subscription's observability data")
            start = (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            end = (datetime.now(timezone.utc) + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
            cutoff = time.monotonic() + 20
            while True:
                metrics = command("container-metrics-list", id=resource, start=start, end=end)
                measured = {series["name"]["value"]: [point["average"] for points in series["timeseries"]
                            for point in points["data"] if point.get("average") is not None] for series in metrics["value"]}
                if measured.get("CpuUsage") and measured.get("MemoryUsage"):
                    break
                if time.monotonic() >= cutoff:
                    raise RuntimeError("the monitored container did not publish measured CPU and memory")
                time.sleep(1)
            if not all(0 <= value < usage["ReservedCPUMillis"][0] for value in measured["CpuUsage"]) or not all(
                    0 < value < usage["ReservedMemoryMiB"][0] * (1 << 20) for value in measured["MemoryUsage"]):
                raise RuntimeError(f"observed usage should be positive and smaller than its reservations: {measured}")
            metrics_path = resource + "/providers/Microsoft.Insights/metrics"
            status, reply = foreign.request("GET", foreign.origin + metrics_path, query="api-version=2018-01-01")
            if status != 404 or reply["error"]["code"] != "SubscriptionNotFound":
                raise RuntimeError("the server accepted a foreign token for another subscription's measured usage")
            command("container-stop", name=name)
            health = command("resource-health-show", id=resource)["properties"]
            if health["availabilityState"] != "Unavailable" or health["reasonType"] != "UserInitiated" or reserved() != usage:
                raise RuntimeError("stopping the workload changed its reservation or failed to change Resource Health")
            command("container-delete", name=name)
            command("resource-health-show", expected="ResourceNotFound", id=resource)
            if reserved() != baseline:
                raise RuntimeError("deletion did not release the committed quota")
            rejected = next(candidate for candidate, response in results if response is None)
            command("quota-container-create", name=rejected)
            command("container-delete", name=rejected)
            if reserved() != baseline:
                raise RuntimeError("reused capacity did not return to the baseline")
            audits = [event for event in command("activity-log-list") if event["resourceId"].casefold() == resource.casefold()]
            required = {"write", "stop", "delete"}
            observed = {event["operationName"]["value"].split("/")[-1] for event in audits}
            if not required <= observed or any(not event.get("caller") or not event.get("status") for event in audits):
                raise RuntimeError("Activity Log did not expose actor, target, action, and outcome")
            foreign_events = command("activity-log-list", client=other)
            if any(event.get("resourceId", "").casefold() == resource.casefold() for event in foreign_events):
                raise RuntimeError("another tenant read the workload activity")
            return {"azureCLI": primary.version["azure-cli"], "availableToStopped": True, "healthMissingAfterDeletion": True,
                    "auditActionActorAndOutcome": True, "crossTenantReadDenied": True, "oneConcurrentReservation": True,
                    "baseline": baseline, "reserved": usage, "measured": measured, "reclaimedQuota": True}
        finally:
            for name in pair:
                command("container-delete", name=name)
            primary.command("group-delete", group)
            foreign.command("group-delete", group)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix, args.image), sort_keys=True))


if __name__ == "__main__":
    main()
