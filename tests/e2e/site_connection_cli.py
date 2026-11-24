#!/usr/bin/env python3
"""Provision a WireGuard site connection through the pinned Azure CLI."""

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI

VERSION = "2026-11-01"
SITE_TYPE = "Ocean.Network/siteConnections"


def observe(check, deadline=30):
    expires = time.monotonic() + deadline
    while True:
        if check():
            return
        if time.monotonic() >= expires:
            raise RuntimeError("the WireGuard resource did not reach its requested state")
        time.sleep(0.5)


def lifecycle(settings, matrix, fixture, phase, peers_path=None):
    if phase == "create":
        tenant, _ = create_customers(settings)
        group = "vpn-" + uuid4().hex[:10]
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as state:
            json.dump({"tenant": tenant, "group": group}, state)
    else:
        if not fixture.exists():
            return {"deleted": True}
        saved = json.loads(fixture.read_text())
        tenant, group = saved["tenant"], saved["group"]
    with tempfile.TemporaryDirectory(prefix="ocean-site-connection-") as folder:
        path = Path(folder)
        cli = AzureCLI(tenant, str(path / "az"))
        cli.login_device()
        contract = GroupContract(cli, load_matrix(matrix))
        network_commands, site_commands = load_matrix(matrix, "NETWORK-01"), load_matrix(matrix, "NETWORK-05")
        base = f"/subscriptions/{tenant['subscription']}/resourceGroups/{group}/providers"
        address = base + "/" + SITE_TYPE + "/office"
        endpoint = tenant["arm"] + address + f"?api-version={VERSION}"
        variables = {"group": group, "location": tenant["location"], "request": path / "connection.json",
                     "vnet": "private", "subnet": "workloads", "vnet_prefix": "10.85.50.0/24",
                     "subnet_prefix": "10.85.50.0/24", "connection_url": endpoint}

        def command(name, expected_missing=False):
            row = site_commands.get(name) or network_commands[name]
            argv = command_args(row, contract.version, **variables)
            finished = subprocess.run(["az", *argv], env=cli.env, capture_output=True, text=True, timeout=32)
            if finished.returncode:
                if expected_missing and "ResourceNotFound" in finished.stderr:
                    return None
                message = next((line for line in finished.stderr.splitlines() if line.startswith("ERROR:")), "")
                raise RuntimeError(f"{name} failed through Azure CLI ({finished.returncode}): {message}")
            return json.loads(finished.stdout) if finished.stdout.strip() else None

        if phase == "delete":
            command("site-connection-delete")
            observe(lambda: command("site-connection-show", expected_missing=True) is None)
            command("site-connection-delete")
            contract.command("group-delete", group)
            fixture.unlink()
            return {"deleted": True, "repeatedDeleteSucceeded": True}

        contract.command("group-create", group)
        command("vnet-create")
        peers = json.loads(peers_path.read_text())
        body = {"location": tenant["location"], "properties": {
            "subnet": {"id": base + "/Microsoft.Network/virtualNetworks/private/subnets/workloads"},
            "customerPrefixes": ["10.85.60.0/24"], "peers": peers,
        }}
        variables["request"].write_text(json.dumps(body))
        queued = command("site-connection-create")
        if queued["id"] != address or queued["properties"]["provisioningState"] not in {"Updating", "Succeeded"}:
            raise RuntimeError("the API did not acknowledge the expected site connection")
        observe(lambda: command("site-connection-show")["properties"]["provisioningState"] == "Succeeded")
        replay = command("site-connection-create")
        if replay["id"] != address or replay["properties"]["provisioningState"] != "Succeeded":
            raise RuntimeError("a retry changed the provisioned site connection")
        return {"azureCLI": contract.version["azure-cli"], "id": address, "apiVersion": VERSION,
                "siteConnectionReady": True, "repeatedCreatePreservedConnection": True, "peers": len(peers)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--phase", required=True, choices=("create", "delete"))
    parser.add_argument("--peers", type=Path)
    args = parser.parse_args()
    if args.phase == "create" and args.peers is None:
        parser.error("--peers is required for site connection creation")
    config = json.loads(args.settings.read_text())
    print(json.dumps(lifecycle(config, args.matrix, args.fixture, args.phase, args.peers), sort_keys=True))


if __name__ == "__main__":
    main()
