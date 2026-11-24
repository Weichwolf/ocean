#!/usr/bin/env python3
"""Verify static public IPv4 reservations and NAT associations through Azure CLI."""

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


def verify(config, matrix_path, pool):
    groups = load_matrix(matrix_path)
    egress = load_matrix(matrix_path, "NETWORK-03")
    networks = load_matrix(matrix_path, "NETWORK-01")
    group = "egress-" + uuid.uuid4().hex[:10]
    first, second = create_customers(config)
    with contextlib.ExitStack() as cleanup:
        def client(settings):
            cache = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="ocean-egress-cli-"))
            cli = AzureCLI(settings, cache)
            cli.login_device()
            return GroupContract(cli, groups)

        primary, other = client(first), client(second)
        for tenant in (primary, other):
            tenant.command("group-create", group)
            cleanup.callback(tenant.command, "group-delete", group)

        def command(tenant, label, **overrides):
            row = egress.get(label) or networks[label]
            values = {"group": group, "location": first["location"], "ip": "fixed", "nat": "outbound", "vnet": "private",
                      "subnet": "workloads", "vnet_prefix": "10.84.0.0/16", "subnet_prefix": "10.84.1.0/24"}
            values.update(overrides)
            args = command_args(row, tenant.version, **values)
            reply = subprocess.run(["az", *args], env=tenant.cli.env, capture_output=True, text=True, timeout=32)
            if reply.returncode:
                error = next((line for line in reply.stderr.splitlines() if line.startswith("ERROR:")), "CLI exited with an error")
                raise RuntimeError(f"{label}: {error}")
            result = json.loads(reply.stdout) if reply.stdout else None
            return result["publicIp"] if label == "public-ip-create" else result

        def arm_id(settings, kind, name):
            return f"/subscriptions/{settings['subscription']}/resourceGroups/{group}/providers/Microsoft.Network/{kind}/{name}"

        ip_version = "api-version=" + egress["public-ip-create"]["api_version"]
        nat_version = "api-version=" + egress["nat-create"]["api_version"]
        ip_id = arm_id(first, "publicIPAddresses", "fixed")
        other_id = arm_id(second, "publicIPAddresses", "fixed")
        nat_id = arm_id(first, "natGateways", "outbound")
        nat_url = primary.origin + nat_id
        ip_url = primary.origin + ip_id
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            own_ip, their_ip = executor.map(lambda tenant: command(tenant, "public-ip-create"), (primary, other))
        own_address = properties(own_ip)["ipAddress"]
        other_address = properties(their_ip)["ipAddress"]
        if {own_address, other_address} != set(pool) or own_ip["id"] != ip_id or their_ip["id"] != other_id:
            raise RuntimeError("the concurrent requests did not reserve distinct addresses from the regional pool")
        if {row["id"] for row in command(primary, "public-ip-list")} != {ip_id}:
            raise RuntimeError("the public IP list exposed a resource outside the tenant")
        require_error(primary.request("GET", primary.origin + other_id, query=ip_version), 404, "SubscriptionNotFound")
        repeated = command(primary, "public-ip-create", ip="FIXED")
        if repeated["id"] != ip_id or properties(repeated)["ipAddress"] != own_address:
            raise RuntimeError("the repeated create changed the resource ID or assigned address")
        ip_body = {"location": first["location"], "sku": {"name": "Standard", "tier": "Regional"},
                   "properties": {"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4"}}
        extra_url = primary.origin + arm_id(first, "publicIPAddresses", "exhausted")
        require_error(primary.request("PUT", extra_url, ip_body, ip_version), 409, "PublicIPPoolExhausted")
        override = dict(ip_body, properties=dict(ip_body["properties"], ipAddress=other_address))
        require_error(primary.request("PUT", extra_url, override, ip_version), 400, "InvalidRequestContent")

        gateway = command(primary, "nat-create")
        if gateway["id"] != nat_id or properties(gateway)["publicIpAddresses"][0]["id"].lower() != ip_id.lower():
            raise RuntimeError("the NAT gateway did not reference the selected IP")
        if [row["id"] for row in command(primary, "nat-list")] != [nat_id] or command(primary, "nat-show")["id"] != nat_id:
            raise RuntimeError("the NAT gateway was missing from its provider view")
        nat_body = {"location": first["location"], "sku": {"name": "Standard"},
                    "properties": {"publicIpAddresses": [{"id": ip_id}]}}
        alternative = primary.origin + arm_id(first, "natGateways", "alternate")
        require_error(primary.request("PUT", alternative, nat_body, nat_version), 409, "PublicIPAddressInUse")
        require_error(other.request("PUT", other.origin + arm_id(second, "natGateways", "foreign"), nat_body, nat_version),
                      400, "InvalidRequestContent")
        require_error(primary.request("DELETE", ip_url, query=ip_version), 409, "ResourceInUse")

        command(primary, "vnet-create")
        attached = command(primary, "subnet-nat")
        if properties(attached)["natGateway"]["id"].lower() != nat_id.lower() or properties(attached).get("defaultOutboundAccess") is not False:
            raise RuntimeError("the private subnet did not retain the requested gateway and outbound policy")
        require_error(primary.request("DELETE", nat_url, query=nat_version), 409, "ResourceInUse")
        if properties(command(primary, "subnet-nat", nat="")).get("natGateway"):
            raise RuntimeError("the CLI did not detach the NAT gateway")
        command(primary, "nat-delete")
        command(primary, "nat-delete")

        def claim(label):
            return primary.request("PUT", primary.origin + arm_id(first, "natGateways", label), nat_body, nat_version)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            contenders = list(executor.map(claim, ("race-a", "race-b")))
        if sorted(reply[0] for reply in contenders) != [201, 409]:
            raise RuntimeError("exclusive NAT association did not survive concurrent requests")
        require_error(next(reply for reply in contenders if reply[0] == 409), 409, "PublicIPAddressInUse")
        winner = next(result["name"] for code, result in contenders if code == 201)
        command(primary, "subnet-nat", nat=winner)
        primary.command("group-delete", group)
        primary.command("group-create", group)
        recycled = command(primary, "public-ip-create", ip="recycled")
        if properties(recycled)["ipAddress"] != own_address or properties(command(other, "public-ip-show"))["ipAddress"] != other_address:
            raise RuntimeError("group cleanup released the wrong regional reservation")
        command(primary, "public-ip-delete", ip="recycled")
        command(primary, "public-ip-delete", ip="recycled")
        if command(primary, "public-ip-list"):
            raise RuntimeError("public IP deletion left a resource in the regional inventory")
        return {"azureCLI": primary.version["azure-cli"], "commands": sorted(egress), "pool": pool,
                "versions": {"publicIP": egress["public-ip-create"]["api_version"], "nat": egress["nat-create"]["api_version"],
                             "subnet": egress["subnet-nat"]["api_version"]},
                "allocatedAddresses": [own_address, other_address], "reservationExhaustionRejected": True,
                "concurrentExclusiveClaims": [201, 409], "stableReservationOnRetry": True, "groupCleanupReleasedAddress": True,
                "attachedResourceDeletionRejected": True, "subnetNATAssociationVerified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--pool", nargs=2, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix, args.pool), sort_keys=True))


if __name__ == "__main__":
    main()
