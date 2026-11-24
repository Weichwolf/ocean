#!/usr/bin/env python3
"""Exercise the published ARM resource group contract with Azure CLI."""

import argparse
import concurrent.futures
import csv
import json
import shlex
import tempfile
import uuid
from pathlib import Path

from identity_cli import AzureCLI
from onboarding_cli import fixture, put, send_token


def load_matrix(path):
    with path.open(newline="") as stream:
        return {row["command_id"]: row for row in csv.DictReader(stream, delimiter="\t")}


class GroupContract:
    def __init__(self, cli, matrix):
        self.cli = cli
        self.matrix = matrix
        self.version = json.loads(cli.run("version", "-o", "json"))
        row = matrix["group-list"]
        self.api = row["api_version"]
        self.origin = cli.config["arm"]
        self.collection = f"{self.origin}/subscriptions/{cli.config['subscription']}/resourcegroups"
        self.token = cli.run("account", "get-access-token", "--resource", self.origin,
                             "--query", "accessToken", "-o", "tsv").strip()

    def command(self, label, group="", tag="primary"):
        row = self.matrix[label]
        extensions = ",".join(f"{name}={version}" for name, version in sorted(self.version["extensions"].items())) or "none"
        if (row["azure_cli"], row["extensions"], row["api_version"]) != (self.version["azure-cli"], extensions, self.api):
            raise RuntimeError("the CLI installation or API version differs from the compatibility matrix")
        args = [value.format(group=group, location=self.cli.config["location"], tag=tag) for value in shlex.split(row["command"])]
        output = self.cli.run(*args)
        return json.loads(output) if output else None

    def request(self, method, route, data=None, query=None, discard=False):
        query = f"api-version={self.api}" if query is None else query
        return send_token(self.cli.config, self.token, method, route + "?" + query, data, discard)


def verify_group(group, path, name, tag):
    expected_id = path.split("/subscriptions/", 1)[1].replace("/resourcegroups/", "/resourceGroups/")
    if (group.get("id") != "/subscriptions/" + expected_id or group.get("name") != name or
            group.get("type") != "Microsoft.Resources/resourceGroups" or group.get("tags") != {"ocean-fixture": tag} or
            group.get("properties", {}).get("provisioningState") != "Succeeded"):
        raise RuntimeError("the resource group did not round-trip with its ARM ID, tags, and provisioning state")


def verify(config, matrix):
    customers = []
    with tempfile.TemporaryDirectory(prefix="ocean-arm-operator-") as directory:
        operator = AzureCLI(config, directory)
        operator.login_service_principal(config["app"], config["secret"])
        request_file = Path(directory) / "tenant-request.json"
        for _ in range(2):
            tenant, data = fixture()
            allocation = put(operator, tenant, data, request_file)
            customers.append(dict(config, tenant=tenant, subscription=allocation["subscriptionId"], location="farm-1",
                                  user=data["administratorUserPrincipalName"], password=data["administratorPassword"]))

    with tempfile.TemporaryDirectory(prefix="ocean-arm-first-") as first_dir, tempfile.TemporaryDirectory(prefix="ocean-arm-second-") as second_dir:
        first, second = [AzureCLI(customer, directory) for customer, directory in zip(customers, (first_dir, second_dir), strict=True)]
        for cli in (first, second):
            cli.login_device()
            cli.check_subscription()
        primary, foreign = (GroupContract(cli, matrix) for cli in (first, second))
        name = f"rg-{uuid.uuid4().hex[:10]}-A"
        concurrent_name = name + "-race"
        synthetic = [f"{name}-{index:02d}" for index in range(16)]
        primary_path = primary.collection + "/" + name
        foreign_path = foreign.collection + "/" + name
        payload = {"location": first.config["location"], "tags": {"ocean-fixture": "primary"}}
        try:
            provider = primary.command("provider-show")
            supported = [{"resourceType": "resourceGroups", "locations": [first.config["location"]], "apiVersions": [primary.api]}]
            metadata = [{key: resource[key] for key in supported[0]} for resource in provider["resourceTypes"]]
            if (provider["namespace"] != "Microsoft.Resources" or provider["registrationState"] != "Registered" or
                    provider["id"] != f"/subscriptions/{first.config['subscription']}/providers/Microsoft.Resources" or metadata != supported):
                raise RuntimeError("provider discovery did not describe the implemented resource type")
            unknown = primary.collection.removesuffix("/resourcegroups") + "/providers/Microsoft.Compute"
            status, reply = primary.request("GET", unknown)
            if status != 404 or reply["error"]["code"] != "InvalidResourceNamespace":
                raise RuntimeError("provider discovery advertised an unsupported namespace")
            created = primary.command("group-create", name)
            verify_group(created, primary_path, name, "primary")
            verify_group(primary.command("group-show", name.lower()), primary_path, name, "primary")
            if primary.command("group-exists", name.upper()) is not True:
                raise RuntimeError("HEAD did not confirm the resource group exists")
            verify_group(foreign.command("group-create", name, "foreign"), foreign_path, name, "foreign")
            status, reply = primary.request("GET", foreign_path)
            if status != 404 or reply["error"]["code"] != "SubscriptionNotFound":
                raise RuntimeError("a tenant accessed a foreign group")

            for query, code in (("api-version=2000-01-01", "InvalidApiVersionParameter"),
                                (f"api-version={primary.api}&forceDeletionTypes=unsupported", "InvalidQueryParameter")):
                status, reply = primary.request("DELETE", primary_path, query=query)
                if status != 400 or reply["error"]["code"] != code:
                    raise RuntimeError("an unsupported ARM query was not rejected")
            status, reply = primary.request("PUT", primary_path, dict(payload, managedBy="unsupported"))
            if status != 400 or reply["error"]["code"] != "InvalidRequestContent":
                raise RuntimeError("an unsupported resource group property was not rejected")
            verify_group(primary.command("group-show", name), primary_path, name, "primary")

            update = dict(payload, tags={"ocean-fixture": "updated"})
            status, _ = primary.request("PUT", primary_path, update, discard=True)
            if status != 200:
                raise RuntimeError("the resource group update did not commit")
            verify_group(primary.command("group-create", name.lower(), "updated"), primary_path, name, "updated")
            verify_group(primary.command("group-show", name), primary_path, name, "updated")

            race_path = primary.collection + "/" + concurrent_name
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                races = list(pool.map(lambda _: primary.request("PUT", race_path, payload), range(8)))
                filler = list(pool.map(lambda group: primary.request("PUT", primary.collection + "/" + group, payload), synthetic))
            if sorted(code for code, _ in races) != [200] * 7 + [201] or any(code != 201 for code, _ in filler):
                raise RuntimeError("concurrent requests did not converge to one resource group")
            for _, group in races:
                verify_group(group, race_path, concurrent_name, "primary")
            expected = {name, concurrent_name, *synthetic}
            listed = primary.command("group-list")
            if len(listed) != len(expected) or {group["name"] for group in listed} != expected:
                raise RuntimeError("the paged CLI response did not enumerate each group once")
            first_status, page = primary.request("GET", primary.collection)
            next_link = page.get("nextLink", "")
            if first_status != 200 or not next_link.startswith(primary.collection + "?") or len(page["value"]) >= len(expected):
                raise RuntimeError("the server did not return a continuation for the group list")
            second_status, last = send_token(primary.cli.config, primary.token, "GET", next_link)
            paged_names = [group["name"] for group in page["value"] + last["value"]]
            if second_status != 200 or "nextLink" in last or len(paged_names) != len(expected) or set(paged_names) != expected:
                raise RuntimeError("the ARM continuation did not enumerate each group once")

            primary.command("group-delete", name)
            primary.command("group-delete", name)
            if primary.command("group-exists", name) is not False:
                raise RuntimeError("the resource group remained after deletion")
            verify_group(foreign.command("group-show", name), foreign_path, name, "foreign")
        finally:
            for contract, groups in ((primary, [name, concurrent_name, *synthetic]), (foreign, [name])):
                for group in groups:
                    status, _ = contract.request("DELETE", contract.collection + "/" + group, discard=True)
                    if status != 200:
                        raise RuntimeError("failed to remove a disposable resource group")
        if primary.command("group-list") or foreign.command("group-list"):
            raise RuntimeError("cleanup left resource groups behind")
    return {"azureCLI": primary.version["azure-cli"], "extensions": primary.version["extensions"], "apiVersion": primary.api,
            "commands": sorted(matrix), "concurrentRequests": len(races), "groupsEnumerated": len(expected), "pages": 2,
            "crossTenantRequestDenied": True, "unsupportedRequestsRejected": True, "providerDiscoveryVerified": True,
            "discardedUpdateResponseRecovered": True,
            "cleanupVerified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), load_matrix(args.matrix)), sort_keys=True))


if __name__ == "__main__":
    main()
