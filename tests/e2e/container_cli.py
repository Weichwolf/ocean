#!/usr/bin/env python3
"""Run the pinned Azure CLI container commands against real assigned workloads."""

import argparse
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI

TYPE = "Microsoft.ContainerInstance/containerGroups"
VERSION = "2024-05-01-preview"
PRIVATE_PORT = 8080
PUBLIC_PORT = 80


def run(settings, matrix, fixture, phase, image=None):
    if phase == "setup":
        tenant, foreign = create_customers(settings)
        saved = {"tenant": tenant, "foreign": foreign, "group": "containers-" + uuid4().hex[:10],
                 "secret": "ocean-secret-" + uuid4().hex}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as state:
            json.dump(saved, state)
    elif fixture.exists():
        saved = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"deleted": True}
    else:
        raise RuntimeError("the fixture setup is missing")
    tenant, group, secret = saved["tenant"], saved["group"], saved["secret"]
    private = phase in {"private-create", "private-show", "private-delete", "private-logs"}
    name = "private-http" if private else "public-http"
    with tempfile.TemporaryDirectory(prefix="ocean-container-cli-") as directory:
        cli = AzureCLI(tenant, str(Path(directory) / "customer"))
        cli.login_device()
        contract = GroupContract(cli, load_matrix(matrix))
        commands = load_matrix(matrix, "CONTAINER-01") | load_matrix(matrix, "CONTAINER-02")
        variables = {"group": group, "location": tenant["location"], "name": name, "image": image or "",
                     "port": PRIVATE_PORT if private else PUBLIC_PORT, "secret": secret,
                     "vnet": "private", "subnet": "workloads", "vnet_prefix": "10.91.0.0/16", "subnet_prefix": "10.91.1.0/24",
                     "subnet_id": (f"/subscriptions/{tenant['subscription']}/resourceGroups/{group}/providers/"
                                   "Microsoft.Network/virtualNetworks/private/subnets/workloads")}
        variables["command"] = shlex.join(["/bin/sh", "-ec", 'test "$STANDARD" = configured; test -n "$SECRET"; '
                                          'mkdir -p /tmp/web; echo configuration-present > /tmp/web/index.html; '
                                          'echo ocean-private-ready; exec busybox httpd -f -vv -p 8080 -h /tmp/web'])

        def command(label, *, selected=name, missing=False):
            row = commands[label]
            if row["api_version"].split("+")[-1] != VERSION:
                raise RuntimeError("the CLI operation used the wrong version")
            argv = command_args(row, contract.version, **(variables | {"name": selected}))
            result = subprocess.run(["az", *argv], env=cli.env, capture_output=True, text=True, timeout=80)
            if result.returncode:
                if missing and "ResourceNotFound" in result.stderr:
                    return None
                code = next((line[5:].strip() for line in result.stderr.splitlines() if line.startswith("Code:")), "")
                if not code:
                    code = next((line for line in result.stderr.splitlines() if line.startswith("ERROR:")), "")
                raise RuntimeError(f"{label} failed through Azure CLI ({result.returncode}): {code.replace(secret, '[redacted]')}")
            if secret in result.stdout or secret in result.stderr:
                raise RuntimeError("the CLI response exposed a secure environment value")
            if label == "container-logs":
                return result.stdout
            return json.loads(result.stdout) if result.stdout.strip() else None

        def show(expected="Running"):
            resource = command("container-show")
            if resource["provisioningState"] != "Succeeded" or resource["instanceView"]["state"] != expected:
                raise RuntimeError(f"the container did not report {expected}")
            address = resource["ipAddress"]["ip"]
            variables_out = resource["containers"][0].get("environmentVariables") or []
            if any(item.get("secureValue") for item in variables_out):
                raise RuntimeError("the CLI resource contains a secureValue")
            if private and {item["name"]: item.get("value") for item in variables_out} != {"STANDARD": "configured", "SECRET": None}:
                raise RuntimeError("redacted and standard environment variables did not round-trip")
            return {"azureCLI": contract.version["azure-cli"], "id": resource["id"], "address": address,
                    "subscription": tenant["subscription"], "tenant": tenant["tenant"], "group": group, "state": expected}

        if phase == "setup":
            contract.command("group-create", group)
            return {"group": group}
        if phase == "cleanup":
            for candidate in ("private-http", "public-http"):
                command("container-delete", selected=candidate)
            contract.command("group-delete", group)
            fixture.unlink()
            return {"deleted": True}
        if phase == "foreign-conflict":
            other = saved["foreign"]
            other_cli = AzureCLI(other, str(Path(directory) / "foreign"))
            other_cli.login_device()
            other_contract = GroupContract(other_cli, load_matrix(matrix))
            other_group = "conflict-" + uuid4().hex[:10]
            other_vars = variables | {"group": other_group, "name": "foreign-http", "port": PRIVATE_PORT,
                                      "subnet_id": (f"/subscriptions/{other['subscription']}/resourceGroups/{other_group}/providers/"
                                                    "Microsoft.Network/virtualNetworks/private/subnets/workloads")}
            other_contract.command("group-create", other_group)
            try:
                other_cli.run(*command_args(load_matrix(matrix, "NETWORK-01")["vnet-create"], other_contract.version, **other_vars))
                args = command_args(commands["container-private-create"], other_contract.version, **other_vars)
                reply = subprocess.run(["az", *args], env=other_cli.env, capture_output=True, text=True, timeout=35)
                if reply.returncode == 0 or "OverlappingAddressSpace" not in reply.stderr:
                    raise RuntimeError("a second tenant was not rejected by the overlapping address-space guard")
                return {"overlappingTenantAddressSpaceDenied": True}
            finally:
                args = command_args(commands["container-delete"], other_contract.version, **other_vars)
                other_cli.run(*args)
                other_contract.command("group-delete", other_group)
        if phase.endswith("-create"):
            if private:
                cli.run(*command_args(load_matrix(matrix, "NETWORK-01")["vnet-create"], contract.version, **variables))
            command("container-private-create" if private else "container-public-create")
            result = show()
            if not private:
                for label in ("container-list", "container-list-subscription"):
                    if not any(item["id"] == result["id"] for item in command(label)):
                        raise RuntimeError("the running group was missing from the scoped CLI list")
            return result
        if phase.endswith("-delete"):
            command("container-delete")
            if command("container-show", missing=True) is not None:
                raise RuntimeError("the deleted group still exists")
            command("container-delete")
            return {"deleted": True, "repeatedDeleteSucceeded": True}
        if phase.endswith("-logs"):
            log = command("container-logs")
            event = "ocean-private-ready" if private else "ocean-public-probe"
            if event not in log:
                raise RuntimeError("the CLI logs are missing the expected workload event")
            return {"logEventFound": True}
        if phase in {"start", "stop", "restart"}:
            command("container-" + phase)
            return show("Stopped" if phase == "stop" else "Running")
        return show()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--image")
    parser.add_argument("--phase", required=True, choices=("setup", "cleanup", "public-create", "private-create", "public-show",
                                                          "private-show", "start", "stop", "restart", "public-delete", "private-delete",
                                                          "public-logs", "private-logs", "foreign-conflict"))
    args = parser.parse_args()
    result = run(json.loads(args.settings.read_text()), args.matrix, args.fixture, args.phase, args.image)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
