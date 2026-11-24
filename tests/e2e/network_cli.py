#!/usr/bin/env python3
"""Verify the virtual network control plane through unmodified Azure CLI."""

import argparse
import concurrent.futures
import contextlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from arm_rbac_cli import require_error
from identity_cli import AzureCLI


def properties(row):
    return row.get("properties", row)


def subnet_prefixes(row):
    subnet = properties(row)
    return subnet.get("addressPrefixes") or [subnet.get("addressPrefix")]


def verify(config, matrix_path):
    first, second = create_customers(config)
    groups = load_matrix(matrix_path)
    networks = load_matrix(matrix_path, "NETWORK-01")
    name = "net-" + uuid.uuid4().hex[:10]
    with contextlib.ExitStack() as cleanup:
        def client(settings):
            directory = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="ocean-net-cli-"))
            cli = AzureCLI(settings, directory)
            cli.login_device()
            return GroupContract(cli, groups)

        primary, foreign = client(first), client(second)
        for contract in (primary, foreign):
            contract.command("group-create", name)
            cleanup.callback(contract.command, "group-delete", name)

        def command(contract, label, **changes):
            row = networks.get(label) or groups[label]
            values = {"group": name, "vnet": name, "location": first["location"], "vnet_prefix": "10.72.0.0/16",
                      "subnet": "inline", "subnet_prefix": "10.72.1.0/24"}
            values.update(changes)
            args = command_args(row, contract.version, **values)
            result = subprocess.run(["az", *args], env=contract.cli.env, capture_output=True, text=True, timeout=32)
            if result.returncode:
                error = next((line for line in result.stderr.splitlines() if line.startswith("ERROR:")), "CLI exited with an error")
                raise RuntimeError(f"{label}: {error}")
            return json.loads(result.stdout) if result.stdout else None

        primary_id = f"/subscriptions/{first['subscription']}/resourceGroups/{name}/providers/Microsoft.Network/virtualNetworks/{name}"
        foreign_id = primary_id.replace(first["subscription"], second["subscription"], 1)
        vnet_url = config["arm"] + primary_id
        vnet_version = "api-version=" + networks["vnet-show"]["api_version"]
        subnet_version = "api-version=" + networks["subnet-show"]["api_version"]
        master = command(primary, "vnet-create")["newVNet"]
        other = command(foreign, "vnet-create")["newVNet"]
        if master["id"] != primary_id or other["id"] != foreign_id or properties(master)["addressSpace"]["addressPrefixes"] != ["10.72.0.0/16"]:
            raise RuntimeError("the CLI did not create independent virtual networks with the requested address space")
        if {row["name"] for row in properties(master)["subnets"]} != {"inline"}:
            raise RuntimeError("the inline subnet was not created with its virtual network")
        if command(primary, "vnet-show", vnet=name.upper())["id"] != primary_id:
            raise RuntimeError("case-insensitive network lookup returned a different ARM ID")
        if [row["id"] for row in command(primary, "vnet-list")] != [primary_id] or [row["id"] for row in command(foreign, "vnet-list-subscription")] != [foreign_id]:
            raise RuntimeError("network listing crossed a resource group or subscription boundary")
        vnet_type = "Microsoft.Network/virtualNetworks"
        if [row["id"] for row in command(primary, "inventory-filtered-list", type=vnet_type)] != [primary_id]:
            raise RuntimeError("the virtual network was missing from generic ARM inventory")
        require_error(primary.request("GET", config["arm"] + foreign_id, query=vnet_version), 404, "SubscriptionNotFound")

        standalone = command(primary, "subnet-create", subnet="standalone", subnet_prefix="10.72.2.0/24")
        if standalone["id"] != primary_id + "/subnets/standalone" or command(primary, "subnet-show", subnet="STANDALONE")["id"] != standalone["id"]:
            raise RuntimeError("the standalone subnet did not round-trip with its ARM ID")
        updated = command(primary, "subnet-update", subnet="STANDALONE", subnet_prefix="10.72.3.0/24")
        if updated["id"] != standalone["id"] or subnet_prefixes(updated) != ["10.72.3.0/24"]:
            raise RuntimeError("subnet update did not retain the ARM ID or apply the requested address range")
        if {row["name"] for row in command(primary, "subnet-list")} != {"inline", "standalone"}:
            raise RuntimeError("the subnet list omitted an inline or standalone subnet")

        command(primary, "vnet-create")
        persisted = command(primary, "subnet-show", subnet="standalone")
        if persisted["id"] != standalone["id"] or subnet_prefixes(persisted) != ["10.72.3.0/24"]:
            raise RuntimeError("a repeated parent create discarded an independent subnet")
        require_error(primary.request("GET", vnet_url, query="api-version=2000-01-01"), 400, "InvalidApiVersionParameter")
        invalid = [({"properties": {"addressPrefix": "10.73.4.0/24"}}, "InvalidAddressPrefix"),
                   ({"properties": {"addressPrefix": "10.72.3.0/25"}}, "InvalidAddressPrefix"),
                   ({"properties": {"addressPrefix": "10.72.4.0/24", "natGateway": {"id": "invalid"}}}, "InvalidRequestContent")]
        for payload, code in invalid:
            require_error(primary.request("PUT", vnet_url + "/subnets/invalid", payload, subnet_version), 400, code)
        spoofed = {"id": foreign_id + "/subnets/standalone", "properties": {"addressPrefix": "10.72.4.0/24"}}
        require_error(primary.request("PUT", vnet_url + "/subnets/standalone", spoofed, subnet_version), 400, "InvalidAddressPrefix")
        if command(primary, "subnet-show", subnet="standalone") != persisted:
            raise RuntimeError("the rejected update changed the existing subnet")

        def contender(label):
            return primary.request("PUT", vnet_url + "/subnets/" + label, {"properties": {"addressPrefix": "10.72.8.0/24"}}, subnet_version)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(contender, ("race-a", "race-b")))
        if sorted(code for code, _ in results) != [201, 400]:
            raise RuntimeError("competing subnets reserved the same address range")
        attempted = next(row for status, row in results if status == 400)
        if attempted["error"]["code"] != "InvalidAddressPrefix":
            raise RuntimeError("an overlapping subnet was rejected for an unrelated reason")
        winner = next(row["name"] for status, row in results if status == 201)
        if {row["name"] for row in command(primary, "subnet-list")} != {"inline", "standalone", winner}:
            raise RuntimeError("a rejected network request changed the durable subnet list")

        command(primary, "subnet-delete", subnet="standalone")
        command(primary, "subnet-delete", subnet="standalone")
        require_error(primary.request("GET", vnet_url + "/subnets/standalone", query=subnet_version), 404, "SubnetNotFound")
        command(primary, "vnet-delete")
        command(primary, "vnet-delete")
        if command(primary, "vnet-list") or [row["id"] for row in command(foreign, "vnet-list")] != [foreign_id]:
            raise RuntimeError("virtual network cleanup crossed a tenant boundary")
        foreign.command("group-delete", name)
        if command(foreign, "vnet-list-subscription") or command(foreign, "inventory-list"):
            raise RuntimeError("resource group deletion left a virtual network projection")
        return {"azureCLI": primary.version["azure-cli"], "extensions": primary.version["extensions"], "commands": sorted(networks),
                "virtualNetworkAPIVersion": networks["vnet-create"]["api_version"], "subnetAPIVersion": networks["subnet-create"]["api_version"],
                "distinctTenantNetworks": True, "overlapRejectedAtomically": True, "parentRetryPreservedSubnets": True,
                "subnetUpdateVerified": True, "invalidRequestsPreservedState": True,
                "inventoryAndGroupCleanupVerified": True, "deletionVerified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix), sort_keys=True))


if __name__ == "__main__":
    main()
