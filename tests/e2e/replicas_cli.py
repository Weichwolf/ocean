#!/usr/bin/env python3
"""Exercise the local replica set contract through the pinned Azure CLI."""

import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from application_gateway_cli import fixture_bindings, issue_test_certificate
from arm_cli import GroupContract, create_customers, load_matrix
from functions_cli import command
from identity_cli import AzureCLI

API = "2026-11-01"
BASE = "Ocean.Compute/replicaSets"
PROGRAM = r'''set -eu
mkdir -p /tmp/ocean-http/cgi-bin
hostname >/tmp/ocean-http/index.html
cat >/tmp/ocean-http/cgi-bin/load <<'CGI'
#!/bin/sh
if [ "${REQUEST_METHOD:-}" = "POST" ] && mkdir /tmp/ocean-replica-load 2>/dev/null; then
    (
        (while :; do :; done) &
        worker=$!
        trap 'kill "$worker" 2>/dev/null || true; rmdir /tmp/ocean-replica-load' EXIT
        sleep 20
    ) </dev/null >/dev/null 2>&1 &
fi
printf 'Content-Type: text/plain\r\n\r\n'
hostname
CGI
chmod 0755 /tmp/ocean-http/cgi-bin/load
exec httpd -f -p 8080 -h /tmp/ocean-http
'''


def recipe(bindings, image, mode, tier, desired, minimum, maximum, cpu=0.15):
    policy = {"mode": mode, "desired": desired, "minimum": minimum, "maximum": maximum}
    if mode == "Local":
        policy["cpu"] = {"scaleOutAbove": 45, "scaleInBelow": 15, "windowSeconds": 12, "cooldownSeconds": 14}
    return {"location": bindings["location"], "properties": {"availabilityTier": tier, "subnetId": bindings["subnet_id"],
            "policy": policy, "container": {"image": image, "ports": [{"port": 8080, "protocol": "TCP"}],
            "resources": {"requests": {"cpu": cpu, "memoryInGB": 0.0625}}, "command": ["/bin/sh", "-c", PROGRAM]}}}


def wait_until(f, condition, limit=60):
    deadline = time.monotonic() + limit
    while True:
        result = f()
        if condition(result):
            return result
        if time.monotonic() >= deadline:
            raise RuntimeError(f"the replica set did not reach its declared state in {limit} seconds: {result}")
        time.sleep(1)


def exercise(settings, matrix, fixture, phase, image, target, excluded_host):
    if phase == "setup":
        tenant, foreign = create_customers(settings)
        nonce = uuid4().hex[:10]
        saved = {"tenant": tenant, "foreign": foreign, "group": "replicas-" + nonce,
                 "host": "replica-" + nonce + ".ocean.test"}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(saved, file)
    elif fixture.exists():
        saved = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"deleted": True}
    else:
        raise RuntimeError("the replica set test fixture has not been created")
    tenant, group = saved["tenant"], saved["group"]
    endpoints = f"/subscriptions/{tenant['subscription']}/resourceGroups/{group}/providers"
    resource = f"{endpoints}/{BASE}/fixture"
    rows = {}
    for case in ("SCALE-01", "NETWORK-01", "NETWORK-02", "NETWORK-03", "OBS-03"):
        rows.update(load_matrix(matrix, case))
    with tempfile.TemporaryDirectory(prefix="ocean-replicas-cli-") as directory:
        folder = Path(directory)
        cli = AzureCLI(tenant, str(folder / "azure"))
        cli.login_device()
        cli.check_subscription()
        contract = GroupContract(cli, load_matrix(matrix))
        bindings = fixture_bindings(tenant, group) | {"origin": contract.origin, "id": resource,
                    "body": str(folder / "replica-set.json"), "subscription": tenant["subscription"]}

        def run(label, *, expected=None, **overrides):
            return command(cli, rows, contract.version, bindings | overrides, label, expected=expected)

        def put(body, *, expected=None, address=resource):
            Path(bindings["body"]).write_text(json.dumps(body))
            return run("replica-set-put", expected=expected, id=address)

        def inspect():
            return run("replica-set-show")["properties"]

        def remove_fixture(address):
            path = contract.origin + address
            if contract.request("GET", path, query=f"api-version={API}")[0] == 200:
                run("replica-set-delete", id=address)
                wait_until(lambda: contract.request("GET", path, query=f"api-version={API}")[0], lambda code: code == 404)

        single = f"{endpoints}/{BASE}/single"
        if phase == "setup":
            contract.command("group-create", group)
            run("vnet-create")
            put(recipe(bindings, image, "Fixed", "LocallyRedundant", 2, 2, 3), expected="SubnetDelegationRequired")
            run("replica-subnet-delegate")
            put(recipe(bindings, image, "Fixed", "LocallyRedundant", 2, 1, 3), expected="InvalidReplicaSet")
            put(recipe(bindings, image, "Fixed", "LocallyRedundant", 2, 2, 3, cpu=0.3), expected="QuotaExceeded")
            initial = put(recipe(bindings, image, "Fixed", "LocallyRedundant", 2, 2, 3))
            if initial["id"] != resource or initial["properties"]["provisioningState"] not in ("Updating", "Succeeded"):
                raise RuntimeError("the API did not recognize the replica set provisioning intent")
            result = wait_until(inspect, lambda view: view["provisioningState"] == "Succeeded" and view["readyReplicas"] == 2)
            if len(result["members"]) != 4 or len({slot["host"] for slot in result["members"]}) != 4:
                raise RuntimeError("replicas and the spare were not reserved on four separate hosts")
            usage = {item["name"]["value"]: item["currentValue"] for item in run("regional-usage-show")["value"]}
            if usage["ReservedCPUMillis"] != 600 or usage["ReservedMemoryMiB"] != 256:
                raise RuntimeError("scale-out and spare capacity did not reserve tenant quota")
            other = AzureCLI(saved["foreign"], str(folder / "foreign"))
            other.login_device()
            stranger = GroupContract(other, load_matrix(matrix))
            status, answer = stranger.request("GET", stranger.origin + resource, query=f"api-version={API}")
            if status != 404 or answer["error"]["code"] != "SubscriptionNotFound":
                raise RuntimeError("a foreign tenant read replica placement")
            put(recipe(bindings, image, "Fixed", "NonRedundant", 1, 1, 1), address=single)
            fixed = wait_until(lambda: run("replica-set-show", id=single)["properties"], lambda view: view["readyReplicas"] == 1)
            remove_fixture(single)
            return {"azureCLI": contract.version["azure-cli"], "group": group, "tenant": tenant["tenant"],
                    "subscription": tenant["subscription"], "replicaSetId": resource, "host": saved["host"],
                    "result": result, "committedQuota": usage, "isolatedTenant": True, "tierConflictRejected": True,
                    "quotaConflictRejected": True, "nonRedundantSlots": fixed["reservedSlots"]}
        if phase == "publish":
            members = inspect()["members"]
            if len(members) != 4:
                raise RuntimeError("the fixed ingress pool requires four reserved addresses")
            bundle, password = issue_test_certificate(folder, saved["host"])
            public = run("public-ip-create")["publicIp"]
            backends = {f"backend{index}": slot["privateIpAddress"] for index, slot in enumerate(members, start=1)}
            run("replica-gateway-create", **backends, certificate_pfx=str(bundle), certificate_password=password)
            gateway = run("app-gateway-show")
            props = gateway.get("properties", gateway)
            pools = props["backendAddressPools"][0]
            deployed = pools.get("properties", pools)["backendAddresses"]
            if sorted(item["ipAddress"] for item in deployed) != sorted(backends.values()):
                raise RuntimeError("the published gateway did not retain all reserved backend addresses")
            return {"address": public.get("properties", public)["ipAddress"], "certificate": (folder / "ingress.pem").read_text(),
                    "host": saved["host"], "backends": list(backends.values())}
        if phase == "show":
            return inspect()
        if phase == "wait":
            def ready(view):
                eligible = {member["host"] for member in view["members"] if member["state"] == "Ready"}
                return view["desiredReplicas"] == target and view["readyReplicas"] == target and excluded_host not in eligible
            return wait_until(inspect, ready)
        if phase == "autoscale":
            return put(recipe(bindings, image, "Local", "LocallyRedundant", 2, 2, 3))["properties"]
        if phase == "management":
            temporary = "ha-check-" + uuid4().hex[:10]
            contract.command("group-create", temporary)
            try:
                observed = contract.command("group-show", temporary)
                if observed["name"] != temporary:
                    raise RuntimeError("the management endpoint returned the wrong resource")
            finally:
                contract.command("group-delete", temporary)
            return {"freshOAuth": True, "managementMutationVerified": True, "azureCLI": contract.version["azure-cli"]}
        if phase == "cleanup":
            status, _ = contract.request("GET", contract.origin + endpoints + "/Microsoft.Network/applicationGateways/ingress",
                                         query="api-version=2026-01-01")
            if status == 200:
                run("app-gateway-delete")
            remove_fixture(single)
            remove_fixture(resource)
            contract.delete_group(group)
            fixture.unlink()
            return {"deleted": True}
    raise RuntimeError("unsupported replica set probe phase")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--phase", required=True, choices=("setup", "publish", "show", "wait", "autoscale", "management", "cleanup"))
    parser.add_argument("--image", required=True)
    parser.add_argument("--target", type=int, default=2)
    parser.add_argument("--excluded-host", default="")
    args = parser.parse_args()
    print(json.dumps(exercise(json.loads(args.settings.read_text()), args.matrix, args.fixture, args.phase, args.image, args.target, args.excluded_host)))


if __name__ == "__main__":
    main()
