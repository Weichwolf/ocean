#!/usr/bin/env python3
"""Exercise the regional inventory with the unmodified Azure CLI."""

import argparse
import contextlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from arm_rbac_cli import create_service_principal, require_error
from identity_cli import AzureCLI
from onboarding_cli import send_token

FIXTURE_TYPE = "Ocean.Test/widgets"
FIXTURE_VERSION = "2025-01-01"


def fixture_entry(customer, group, path):
    return {"scope": {"tenantId": customer["tenant"], "subscriptionId": customer["subscription"]},
            "resource": {"address": {"group": group, "path": path}, "apiVersion": FIXTURE_VERSION,
                         "location": customer["location"], "tags": {"owner": "inventory-fixture"},
                         "properties": {"provisioningState": "Succeeded", "fixtureValue": "persisted"},
                         "provisioningState": "Succeeded"}}


def resource_id(customer, group, path):
    return f"/subscriptions/{customer['subscription']}/resourceGroups/{group}/providers/{path}"


def verify(config, matrix_path, publisher):
    first, second = create_customers(config)
    matrix = load_matrix(matrix_path)
    roles = load_matrix(matrix_path, "IDENTITY-04")
    with contextlib.ExitStack() as cleanup:
        def client(settings):
            directory = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="ocean-inventory-cli-"))
            return AzureCLI(settings, directory)

        owner, foreign = client(first), client(second)
        for cli in (owner, foreign):
            cli.login_device()
        primary, other = (GroupContract(cli, matrix) for cli in (owner, foreign))
        shared = "inventory-" + uuid.uuid4().hex[:10] + "-A"
        hidden = shared + "-private"
        for contract, name in ((primary, shared), (primary, hidden), (other, shared)):
            cleanup.callback(contract.command, "group-delete", name)
            contract.command("group-create", name)
        fixtures = [f"Ocean.Test/widgets/widget-{index:02d}" for index in range(17)]
        child = fixtures[0] + "/parts/part-A"
        fixtures.append(child)
        private_path = "Ocean.Test/widgets/private-widget"
        foreign_path = "Ocean.Test/widgets/foreign-widget"
        entries = ([fixture_entry(first, shared, path) for path in fixtures] +
                   [fixture_entry(first, hidden, private_path), fixture_entry(second, shared, foreign_path)])
        seeded = subprocess.run([publisher, "-test.run=^TestPublishLabInventory$"], input=json.dumps(entries),
                                capture_output=True, text=True, timeout=28)
        if seeded.returncode != 0 or "PASS" not in seeded.stdout:
            raise RuntimeError("the regional store rejected the inventory fixture: " + seeded.stdout.strip())

        def command(cli, label, **bindings):
            args = command_args(matrix[label], primary.version, **bindings)
            result = subprocess.run(["az", *args], env=cli.env, capture_output=True, text=True, timeout=32)
            if result.returncode:
                error = next((line for line in result.stderr.splitlines() if line.startswith("ERROR:")), "CLI exited with an error")
                raise RuntimeError(f"{label}: {error}")
            return json.loads(result.stdout)

        shared_ids = {resource_id(first, shared, path) for path in fixtures}
        private_id = resource_id(first, hidden, private_path)
        foreign_id = resource_id(second, shared, foreign_path)
        nested_id = resource_id(first, shared, child)
        owner_ids = shared_ids | {private_id}

        def verify_list(items, ids):
            if len(items) != len(ids) or {item["id"] for item in items} != ids:
                raise RuntimeError("the inventory list returned duplicate, missing, or foreign IDs")
            if any(not row.get("createdTime") or not row.get("changedTime") or row.get("provisioningState") != "Succeeded" for row in items):
                raise RuntimeError("the inventory response omitted requested lifecycle metadata")

        verify_list(command(owner, "inventory-list"), owner_ids)
        verify_list(command(foreign, "inventory-list"), {foreign_id})
        verify_list(command(owner, "inventory-filtered-list", group=shared.lower(), type=FIXTURE_TYPE), shared_ids - {nested_id})
        nested = command(owner, "inventory-show", id=nested_id.lower(), version=FIXTURE_VERSION)
        if nested["id"] != nested_id or nested["type"] != "Ocean.Test/widgets/parts" or nested["name"] != "part-A" or nested["properties"]["fixtureValue"] != "persisted":
            raise RuntimeError("the nested resource did not round-trip with its provider fields")

        origin = config["arm"]
        endpoint = primary.collection.removesuffix("/resourcegroups") + "/resources"
        code, page = primary.request("GET", endpoint)
        cursor = page.get("nextLink", "")
        if code != 200 or len(page["value"]) != 16 or not cursor.startswith(endpoint + "?"):
            raise RuntimeError("the inventory API did not return an ARM continuation")
        code, last = send_token(first, primary.token, "GET", cursor)
        all_ids = [row["id"] for row in page["value"] + last["value"]]
        if code != 200 or "nextLink" in last or len(all_ids) != len(owner_ids) or set(all_ids) != owner_ids:
            raise RuntimeError("inventory pages did not contain every resource exactly once")
        require_error(primary.request("GET", origin + nested_id, query="api-version=2000-01-01"), 400, "InvalidApiVersionParameter")
        require_error(primary.request("GET", endpoint, query=f"api-version={primary.api}&%24top=2&%24filter=name%20ne%20'private'"),
                      400, "InvalidQueryParameter")
        require_error(primary.request("GET", origin + foreign_id, query=f"api-version={FIXTURE_VERSION}"), 404, "SubscriptionNotFound")

        app, principal, secret = create_service_principal(owner)
        scope = primary.collection.removesuffix("/resourcegroups").removeprefix(origin) + "/resourceGroups/" + shared
        role_args = {"scope": scope, "name": str(uuid.uuid4()), "principal": principal, "kind": "ServicePrincipal"}
        role = json.loads(owner.run(*command_args(roles["role-create"], primary.version, **role_args)))
        native = command(owner, "inventory-show", id=role["id"], version="2022-04-01")
        if native["id"] != role["id"] or native["properties"]["principalId"] != principal:
            raise RuntimeError("the CLI did not read the real role assignment by ARM resource ID")
        reader = client(first)
        reader.login_service_principal(app, secret)
        scoped = GroupContract(reader, matrix)
        verify_list(command(reader, "inventory-list"), shared_ids)
        group_query = f"api-version={primary.api}&%24expand=createdTime,changedTime,provisioningState"
        group_code, group_page = scoped.request("GET", primary.collection + "/" + shared + "/resources", query=group_query)
        group_next = group_page.get("nextLink", "")
        if group_code != 200 or not group_next.startswith(primary.collection.removesuffix("resourcegroups") + "resourceGroups/"):
            raise RuntimeError("the group-scoped inventory did not return its continuation")
        group_code, group_last = send_token(first, scoped.token, "GET", group_next)
        if group_code != 200 or "nextLink" in group_last:
            raise RuntimeError("the group-scoped inventory returned an unexpected final page")
        verify_list(group_page["value"] + group_last["value"], shared_ids)
        if command(reader, "inventory-show", id=nested_id, version=FIXTURE_VERSION)["id"] != nested_id:
            raise RuntimeError("the Reader could not inspect the granted resource")
        require_error(scoped.request("GET", origin + private_id, query=f"api-version={FIXTURE_VERSION}"), 403, "AuthorizationFailed")
        require_error(scoped.request("GET", primary.collection + "/" + hidden + "/resources"), 403, "AuthorizationFailed")
        require_error(scoped.request("GET", origin + foreign_id, query=f"api-version={FIXTURE_VERSION}"), 404, "SubscriptionNotFound")
        owner.run(*command_args(roles["role-delete"], primary.version, id=role["id"]))
        require_error(scoped.request("GET", origin + nested_id, query=f"api-version={FIXTURE_VERSION}"), 403, "AuthorizationFailed")
        if command(reader, "inventory-list"):
            raise RuntimeError("the old token retained inventory visibility after revocation")

        primary.command("group-delete", shared)
        require_error(primary.request("GET", origin + nested_id, query=f"api-version={FIXTURE_VERSION}"), 404, "ResourceNotFound")
        verify_list(command(owner, "inventory-list"), {private_id})
        verify_list(command(foreign, "inventory-list"), {foreign_id})
        return {"azureCLI": primary.version["azure-cli"], "extensions": primary.version["extensions"],
                "commands": sorted(key for key in matrix if key.startswith("inventory-")), "inventoryAPIVersion": primary.api,
                "fixtureAPIVersion": FIXTURE_VERSION, "publishedFixtureRecords": len(entries), "ownerResources": len(owner_ids),
                "readerResources": len(shared_ids), "pages": 2, "unsupportedRequestsRejected": True,
                "realRoleAssignmentRead": True, "revokedTokenDenied": True, "crossTenantDenied": True, "groupInventoryRemoved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--publisher", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix, args.publisher), sort_keys=True))


if __name__ == "__main__":
    main()
