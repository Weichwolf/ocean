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


def verify_security_group(command, primary, foreign, first_id, foreign_id, api_version, subnet_version):
    subnet_url = primary.origin + first_id + "/subnets/inline"
    first_id = first_id.replace("/virtualNetworks/", "/networkSecurityGroups/")
    foreign_id = foreign_id.replace("/virtualNetworks/", "/networkSecurityGroups/")
    url = primary.origin + first_id
    query = "api-version=" + api_version
    first = command(primary, "nsg-create")["NewNSG"]
    second = command(foreign, "nsg-create")["NewNSG"]
    if first["id"] != first_id or second["id"] != foreign_id or len(properties(first)["defaultSecurityRules"]) != 6:
        raise RuntimeError("security group creation did not return a tenant-specific ID and the default rules")
    if command(primary, "nsg-show")["id"] != first_id or [row["id"] for row in command(primary, "nsg-list")] != [first_id]:
        raise RuntimeError("the security group did not round-trip through its ARM view")
    require_error(primary.request("GET", primary.origin + foreign_id, query=query), 404, "SubscriptionNotFound")

    allow = command(primary, "nsg-rule-create", rule="allow-http", priority=110, source="10.77.2.0/24", port="8080-8082",
                    direction="Inbound", access="Allow")
    deny = command(primary, "nsg-rule-create", rule="deny-egress", priority=110, source="*", port=8081,
                   direction="Outbound", access="Deny")
    command(primary, "nsg-rule-create", rule="deny-ingress", priority=100, source="10.77.2.0/24", port=8081,
            direction="Inbound", access="Deny")
    command(primary, "nsg-rule-create", rule="allow-egress", priority=120, source="10.72.1.0/24", port="8080-8082",
            direction="Outbound", access="Allow")
    if (allow["id"] != first_id + "/securityRules/allow-http" or properties(allow).get("sourceAddressPrefix") != "10.77.2.0/24"
            or properties(deny).get("access") != "Deny" or command(primary, "nsg-rule-show", rule="ALLOW-HTTP")["id"] != allow["id"]):
        raise RuntimeError("the CLI did not create the requested security rules")
    conflicting_rule = {"properties": {"priority": 110, "access": "Deny", "protocol": "Tcp", "direction": "Inbound",
                                       "sourceAddressPrefix": "*", "destinationAddressPrefix": "*",
                                       "sourcePortRange": "*", "destinationPortRange": "443"}}
    require_error(primary.request("PUT", url + "/securityRules/conflict", conflicting_rule, query), 400, "SecurityRuleConflict")
    bad_range = dict(conflicting_rule["properties"], priority=120, destinationPortRange="443-80")
    require_error(primary.request("PUT", url + "/securityRules/invalid", {"properties": bad_range}, query), 400, "InvalidRequestContent")
    require_error(primary.request("DELETE", url + "/defaultSecurityRules/DenyAllInBound", query=query), 405, "MethodNotAllowed")
    listed = command(primary, "nsg-rule-list")
    if len(listed) != 10 or {row["name"] for row in listed if "/securityRules/" in row["id"]} != {
            "allow-http", "deny-egress", "deny-ingress", "allow-egress"}:
        raise RuntimeError("security rule listing omitted or added rules after a rejected change")
    command(primary, "nsg-create")
    if command(primary, "nsg-rule-show", rule="allow-http")["id"] != allow["id"]:
        raise RuntimeError("repeating security group creation removed a rule")
    policy = verify_subnet_association(command, primary, subnet_url, subnet_version, first_id, foreign_id, query)
    command(primary, "nsg-rule-delete", rule="allow-http")
    command(primary, "nsg-rule-delete", rule="allow-http")
    require_error(primary.request("GET", url + "/securityRules/allow-http", query=query), 404, "SecurityRuleNotFound")
    command(primary, "nsg-delete")
    command(primary, "nsg-delete")
    if command(primary, "nsg-list") or [row["id"] for row in command(foreign, "nsg-list")] != [foreign_id]:
        raise RuntimeError("security group deletion crossed tenant boundaries")
    return policy


def verify_subnet_association(command, primary, subnet_url, subnet_version, group_id, foreign_id, group_version):
    def linked(row):
        return (properties(row).get("networkSecurityGroup") or {}).get("id", "")

    attached = command(primary, "subnet-security-group")
    if linked(attached).lower() != group_id.lower():
        raise RuntimeError("subnet update did not attach its security group")
    # The packet test uses the rules resolved from the live subnet association.
    status, policy = primary.request("GET", primary.origin + linked(attached), query=group_version)
    if status != 200 or len(policy["properties"]["securityRules"]) != 4:
        raise RuntimeError("could not export the firewall policy linked from the subnet")
    require_error(primary.request("DELETE", primary.origin + group_id, query=group_version),
                  409, "InUseNetworkSecurityGroupCannotBeDeleted")
    command(primary, "vnet-create")
    if linked(command(primary, "subnet-show")).lower() != group_id.lower():
        raise RuntimeError("reapplying the parent VNet lost its subnet security group")

    def attach(identifier):
        body = {"properties": {"addressPrefix": "10.72.1.0/24", "networkSecurityGroup": {"id": identifier}}}
        return primary.request("PUT", subnet_url, body, subnet_version)

    require_error(attach(foreign_id), 400, "InvalidResourceReference")
    require_error(attach(group_id + "-missing"), 400, "InvalidResourceReference")
    if linked(command(primary, "subnet-show")).lower() != group_id.lower():
        raise RuntimeError("a rejected association changed the subnet")

    race_id = command(primary, "nsg-create", nsg="race")["NewNSG"]["id"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        attaching = pool.submit(attach, race_id)
        deleting = pool.submit(primary.request, "DELETE", primary.origin + race_id, query=group_version)
        attachment, removal = attaching.result(), deleting.result()
    if (attachment[0], removal[0]) == (200, 409):
        require_error(removal, 409, "InUseNetworkSecurityGroupCannotBeDeleted")
        if linked(command(primary, "subnet-show")) != race_id:
            raise RuntimeError("the accepted race attachment was not durable")
    elif (attachment[0], removal[0]) == (400, 204):
        require_error(attachment, 400, "InvalidResourceReference")
        if linked(command(primary, "subnet-show")).lower() != group_id.lower():
            raise RuntimeError("a deleted security group replaced the active attachment")
    else:
        raise RuntimeError(f"unexpected attachment/delete race response codes {attachment[0]} and {removal[0]}")

    detached = command(primary, "subnet-security-group", nsg="")
    if linked(detached) or linked(command(primary, "subnet-show")):
        raise RuntimeError("subnet update did not detach its security group")
    command(primary, "nsg-delete", nsg="race")
    return policy["properties"]


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
            values = {"group": name, "vnet": name, "nsg": name, "location": first["location"], "vnet_prefix": "10.72.0.0/16",
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
                   ({"properties": {"addressPrefix": "10.72.4.0/24", "natGateway": {"id": "invalid"}}}, "InvalidResourceReference")]
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
        firewall = verify_security_group(command, primary, foreign, primary_id, foreign_id, networks["nsg-create"]["api_version"], subnet_version)
        command(primary, "vnet-delete")
        command(primary, "vnet-delete")
        if command(primary, "vnet-list") or [row["id"] for row in command(foreign, "vnet-list")] != [foreign_id]:
            raise RuntimeError("virtual network cleanup crossed a tenant boundary")
        command(foreign, "subnet-security-group")
        foreign.command("group-delete", name)
        if command(foreign, "vnet-list-subscription") or command(foreign, "inventory-list"):
            raise RuntimeError("resource group deletion left a virtual network projection")
        foreign.command("group-create", name)
        command(foreign, "nsg-create")
        command(foreign, "nsg-delete")
        return {"azureCLI": primary.version["azure-cli"], "extensions": primary.version["extensions"], "commands": sorted(networks),
                "virtualNetworkAPIVersion": networks["vnet-create"]["api_version"], "subnetAPIVersion": networks["subnet-create"]["api_version"],
                "distinctTenantNetworks": True, "overlapRejectedAtomically": True, "parentRetryPreservedSubnets": True,
                "subnetUpdateVerified": True, "securityGroupLifecycleVerified": True, "securityGroupAssociationVerified": True,
                "invalidRequestsPreservedState": True,
                "inventoryAndGroupCleanupVerified": True, "deletionVerified": True, "firewallPolicy": firewall}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix), sort_keys=True))


if __name__ == "__main__":
    main()
