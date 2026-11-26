#!/usr/bin/env python3
"""Compare stock Azure CLI Cost Management tables with real cgroup measurements."""

import argparse
import base64
import json
import shlex
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from uuid import UUID

sys.dont_write_bytecode = True
from prepare_telemetry import CLIENT_PORT, COST_RATES
from region import DEST, NODES, OPERATOR, eventually, ssh
from verify_container_groups import pinned_image
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client

STORE = "farm-1-node-03"
METER_RATES = {"cpu-vcpu-hour": Decimal(COST_RATES["cpuPerVCPUHour"]) / Decimal(3_600_000_000),
               "memory-gib-hour": Decimal(COST_RATES["memoryPerGiBHour"]) / Decimal((1 << 30) * 3_600_000)}


def usage_samples(state, tenant, resource):
    _, _, sub, _, group, _, path = resource.split("/", 6)
    prefix = f"/ocean/v1/regions/farm-1/tenants/{UUID(tenant)}/arm/{UUID(sub)}/telemetry/{group.lower()}/{path.lower()}/"
    cmd = ["sudo", "-u", "ocean", f"{DEST}/bin/etcdctl", f"--endpoints=https://{NODES[STORE]}:{CLIENT_PORT}",
           f"--cacert={DEST}/pki/telemetry-client-ca.pem", f"--cert={DEST}/pki/{STORE}-telemetry-client.pem",
           f"--key={DEST}/pki/{STORE}-telemetry-client.key", "--command-timeout=3s", "get", prefix, "--prefix", "-w", "json"]
    response = json.loads(ssh(state, STORE, shlex.join(cmd)))
    samples = [json.loads(base64.b64decode(item["value"])) for item in response.get("kvs", [])]
    return [sample for sample in samples if sample.get("usage", {}).get("interval")]


def reference(samples):
    daily = defaultdict(lambda: [0, 0])
    last = None
    for sample in samples:
        end = datetime.fromisoformat(sample["time"]).astimezone(timezone.utc)
        usage = sample["usage"]
        millis, cpu = (usage["interval"][key] for key in ("milliseconds", "cpuTimeMicros"))
        start = end - timedelta(milliseconds=millis)
        if last is not None and start < last:
            raise RuntimeError("live cgroup measurements overlap")
        last = end
        boundary = datetime.combine(start.date() + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
        first_millis = min(millis, (boundary - start) // timedelta(milliseconds=1))
        first_cpu = cpu * first_millis // millis
        daily[start.date()][0] += first_cpu
        daily[start.date()][1] += first_millis * usage["memoryBytes"]
        if first_millis < millis:
            daily[boundary.date()][0] += cpu - first_cpu
            daily[boundary.date()][1] += (millis - first_millis) * usage["memoryBytes"]
    return daily


def verify_tables(replies, quantities, groups):
    paired = defaultdict(Decimal)
    daily = defaultdict(Decimal)
    for resource, days in quantities.items():
        for day, counts in days.items():
            for meter, amount in zip(METER_RATES, counts, strict=True):
                cost = Decimal(amount) * METER_RATES[meter]
                paired[(resource.lower(), meter)] += cost
                daily[(int(day.strftime("%Y%m%d")), meter)] += cost

    def verify_table(table, expected, *dimensions):
        columns = [{"name": "PreTaxCost", "type": "Number"}]
        columns.extend({"name": name, "type": "Number" if name == "UsageDate" else "String"} for name in dimensions)
        columns.append({"name": "Currency", "type": "String"})
        if table is None or table["columns"] != columns or table.get("nextLink") is not None:
            raise RuntimeError("the Cost Management projection did not return the expected typed columns")
        observed = {}
        for amount, *labels, currency in table["rows"]:
            if currency != COST_RATES["currency"]:
                raise RuntimeError("the Cost Management row did not use the configured currency")
            key = tuple(label.lower() if dim == "ResourceId" else label for dim, label in zip(dimensions, labels, strict=True))
            if key in observed:
                raise RuntimeError("the Cost Management table repeated a dimension combination")
            observed[key] = Decimal(str(amount))
        rounded = {key: cost.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP) for key, cost in expected.items()}
        if observed != rounded:
            raise RuntimeError(f"the Cost Management rows differ from the independent cgroup totals: {observed} versus {rounded}")

    verify_table(replies["byResourceAndMeter"], paired, "ResourceId", "MeterId")
    verify_table(replies["dailyByMeter"], daily, "UsageDate", "MeterId")
    for group in groups:
        scoped = {key: value for key, value in paired.items() if key[0].split("/", 6)[4] == group}
        verify_table(replies["byGroup"][group], scoped, "ResourceId", "MeterId")


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "cost_management_cli.py", "functions_cli.py",
                                    "application_gateway_cli.py", "telemetry_load_cli.py", "testdata/arm-contract.tsv"))
    folder = ssh(state, OPERATOR, "mktemp -d /tmp/ocean-cost-management.XXXXXXXX").decode().strip()
    if not folder.startswith("/tmp/ocean-cost-management.") or Path(folder).parent != Path("/tmp"):
        raise RuntimeError("the operator did not allocate a disposable Cost Management fixture")
    image = pinned_image("busybox")
    cleaned = False

    def cli(phase, first="", last=""):
        print(f"Cost Management phase {phase}", flush=True)
        args = ["python3", "-B", f"{CLIENT}/cost_management_cli.py", "--settings", f"{CLIENT}/operator.secret",
                "--matrix", f"{CLIENT}/arm-contract.tsv", "--image", image, "--folder", folder, "--phase", phase,
                "--first", str(first), "--last", str(last)]
        return json.loads(ssh(state, OPERATOR, shlex.join(args), timeout=360))

    try:
        setup = cli("setup")

        def snapshot():
            return {resource: usage_samples(state, setup["tenant"], resource) for resource in setup["resources"]}

        def measured():
            samples = snapshot()
            if any(len(rows) < 2 or not any(row["usage"]["interval"]["cpuTimeMicros"] > 0 for row in rows) for rows in samples.values()):
                raise RuntimeError("both workloads must publish measured CPU and memory intervals")
            return samples

        eventually(measured, 35)
        cli("stop")
        previous = {}
        last_change = time.monotonic()

        def stable():
            nonlocal previous, last_change
            sample = measured()
            if sample != previous:
                previous, last_change = sample, time.monotonic()
            if time.monotonic() - last_change < 4:
                raise RuntimeError("waiting for the last stopped-workload measurements")
            return sample

        samples = eventually(stable, 25)
        quantities = {resource: reference(rows) for resource, rows in samples.items()}
        dates = [day for days in quantities.values() for day in days]
        first, last = min(dates), max(dates)
        replies = cli("query", first, last)
        verify_tables(replies, quantities, setup["groups"])
        cli("delete")
        history = cli("history", first, last)
        if history["historical"] != replies["byResourceAndMeter"]:
            raise RuntimeError("deleting the workloads changed the measured historical cost")
        evidence = setup | replies | {"measuredIntervals": {resource: len(rows) for resource, rows in samples.items()},
                                       "referenceQuantities": {resource: {str(day): dict(zip(METER_RATES, counts, strict=True))
                                                                          for day, counts in days.items()}
                                                               for resource, days in quantities.items()},
                                       "retainedAfterDeletion": True, "firstUTCDate": str(first), "lastUTCDate": str(last),
                                       "rateSchedule": COST_RATES, "image": image}
        evidence.update(cli("cleanup"))
        cleaned = True
        return evidence
    except Exception:
        try:
            cli("cleanup")
            cleaned = True
        except RuntimeError as error:
            print(f"Cost fixture cleanup failed. Its protected state is in {folder} on the operator guest. {error}", file=sys.stderr)
        raise
    finally:
        if cleaned:
            ssh(state, OPERATOR, shlex.join(["rm", "-r", "--", folder]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state)
    output = state / "evidence/cost-management.json"
    output.parent.mkdir(mode=0o700, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("Azure CLI verified measured costs, daily grouping, tenant and resource group scope, and deleted-resource history.")


if __name__ == "__main__":
    main()
