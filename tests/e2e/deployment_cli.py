#!/usr/bin/env python3
"""Verify Bicep previews, incremental deployment, and drift on the pinned Azure CLI."""

import argparse
import concurrent.futures
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from arm_rbac_cli import require_error
from identity_cli import AzureCLI


def verify(config, matrix_path, template, bicep):
    version = subprocess.check_output([bicep, "--version"], text=True).strip()
    if not version.startswith("Bicep CLI version 0.49.2 "):
        raise RuntimeError("the installed Bicep compiler differs from the protocol")
    compiled = json.loads(subprocess.check_output([bicep, "build", "--stdout", template], text=True))
    first, second = create_customers(config)
    with tempfile.TemporaryDirectory(prefix="ocean-deploy-cli-") as cache:
        cli = AzureCLI(first, cache)
        cli.env["PATH"] = str(bicep.parent) + ":" + cli.env["PATH"]
        cli.env["AZURE_BICEP_USE_BINARY_FROM_PATH"] = "true"
        cli.env["AZURE_BICEP_CHECK_VERSION"] = "false"
        cli.login_device()
        groups = load_matrix(matrix_path)
        deployment = load_matrix(matrix_path, "NETWORK-04")
        networks = load_matrix(matrix_path, "NETWORK-01")
        egress = load_matrix(matrix_path, "NETWORK-03")
        contract = GroupContract(cli, groups)
        group = "bicep-" + uuid.uuid4().hex[:10]

        def command(label, **changes):
            row = deployment.get(label) or networks.get(label) or egress.get(label) or groups[label]
            settings = {"group": group, "deployment": "topology", "prefix": "fixture", "template": str(template),
                        "location": first["location"], "vnet": "existing", "subnet": "retained",
                        "subnet_prefix": "10.72.1.0/24", "vnet_prefix": "10.75.0.0/16",
                        "ip": "fixture-outbound", "nat": "fixture-nat"}
            settings.update(changes)
            args = command_args(row, contract.version, **settings)
            result = subprocess.run(["az", *args], env=cli.env, capture_output=True, text=True, timeout=36)
            if result.returncode:
                messages = [line for line in result.stderr.splitlines()
                            if line.startswith(("ERROR:", "AttributeError:", "TypeError:", "ValueError:", "KeyError:"))]
                error = " ".join(messages[-3:]) or "CLI exited with an error"
                raise RuntimeError(f"{label}: {error}")
            return json.loads(result.stdout) if result.stdout else None

        def preview():
            changes = command("deployment-preview")["changes"]
            return {entry["resourceId"].lower(): entry["changeType"] for entry in changes}

        scope = f"/subscriptions/{first['subscription']}/resourceGroups/{group}/providers"
        deployment_id = scope + "/Microsoft.Resources/deployments/topology"
        vnet_id = scope + "/Microsoft.Network/virtualNetworks/fixture-vnet"
        subnet_id = vnet_id + "/subnets/workloads"
        nat_id = scope + "/Microsoft.Network/natGateways/fixture-nat"
        ip_id = scope + "/Microsoft.Network/publicIPAddresses/fixture-outbound"
        expected = {identifier.lower() for identifier in (vnet_id, subnet_id, nat_id, ip_id)}
        version_query = "api-version=" + deployment["deployment-create"]["api_version"]
        contract.command("group-create", group)
        try:
            unrelated = command("vnet-create", subnet_prefix="10.75.1.0/24")["newVNet"]
            before = command("inventory-list")
            changes = preview()
            if changes != dict.fromkeys(expected, "Create"):
                raise RuntimeError(f"initial preview returned unexpected changes: {changes}")
            if command("inventory-list") != before:
                raise RuntimeError("what-if mutated the resource group")
            require_error(contract.request("GET", contract.origin + deployment_id, query=version_query), 404, "DeploymentNotFound")

            body = {"properties": {"mode": "Incremental", "template": compiled,
                                   "parameters": {"namePrefix": {"value": "rejected"}, "subnetPrefix": {"value": "172.30.1.0/24"}}}}
            require_error(contract.request("PUT", contract.origin + deployment_id, body, version_query), 400, "InvalidTemplate")
            if command("inventory-list") != before:
                raise RuntimeError("a rejected deployment left resources or a deployment record")

            created = command("deployment-create")
            props = created["properties"]
            if created["id"] != deployment_id or props["provisioningState"] != "Succeeded":
                raise RuntimeError("Azure CLI did not observe completed deployment")
            outputs = props["outputs"]
            if outputs["subnetId"]["value"] != subnet_id or outputs["outboundIpId"]["value"] != ip_id:
                raise RuntimeError("deployment outputs did not point to the provisioned topology")
            if command("deployment-show")["id"] != deployment_id:
                raise RuntimeError("the deployment record was not durable")
            foreign = deployment_id.replace(first["subscription"], second["subscription"], 1)
            require_error(contract.request("GET", contract.origin + foreign, query=version_query), 404, "SubscriptionNotFound")
            subnet = command("subnet-show", vnet="fixture-vnet", subnet="workloads")
            gateway = command("nat-show")
            assigned = command("public-ip-show")["ipAddress"]
            if subnet["id"] != subnet_id or subnet["natGateway"]["id"] != nat_id or gateway["publicIpAddresses"][0]["id"] != ip_id:
                raise RuntimeError("the deployed subnet, gateway, and public IP were not connected")
            if command("vnet-show") != unrelated:
                raise RuntimeError("incremental deployment changed an unrelated VNet")
            if preview() != dict.fromkeys(expected, "NoChange"):
                raise RuntimeError("the deployed topology produced material changes against its own template")

            deployed_inventory = command("inventory-list")
            two_addresses = dict(compiled, resources=list(compiled["resources"]))
            public_ip = next(item for item in two_addresses["resources"] if item["type"] == "Microsoft.Network/publicIPAddresses")
            two_addresses["resources"].append(dict(public_ip, name="[format('{0}-spare', parameters('namePrefix'))]"))
            overflow = {"properties": {"mode": "Incremental", "template": two_addresses,
                                       "parameters": {"namePrefix": {"value": "overflow"}}}}
            overflow_id = deployment_id.removesuffix("topology") + "overflow"
            require_error(contract.request("PUT", contract.origin + overflow_id, overflow, version_query), 409, "PublicIPPoolExhausted")
            if command("inventory-list") != deployed_inventory:
                raise RuntimeError("the failed address reservation published part of the deployment")

            command("subnet-update", vnet="fixture-vnet", subnet="workloads", subnet_prefix="10.72.2.0/24")
            drift = preview()
            if drift.get(subnet_id.lower()) != "Modify" or {key for key, value in drift.items() if value != "NoChange"} != {subnet_id.lower()}:
                raise RuntimeError("what-if did not isolate the subnet drift")
            body["properties"]["parameters"] = {"namePrefix": {"value": "fixture"}}

            def retry(_):
                return contract.request("PUT", contract.origin + deployment_id, body, version_query)[0]

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
                statuses = list(workers.map(retry, range(2)))
            if statuses != [200, 200] or command("public-ip-show")["ipAddress"] != assigned:
                raise RuntimeError("concurrent redeployment lost the static reservation")
            if preview() != dict.fromkeys(expected, "NoChange"):
                raise RuntimeError("redeployment did not reconcile the subnet")

            return {"azureCLI": contract.version["azure-cli"], "bicep": version, "commands": sorted(deployment),
                    "apiVersion": deployment["deployment-create"]["api_version"], "initialChanges": changes,
                    "driftChanges": drift, "noWritesDuringPreview": True, "invalidDeploymentLeftNoResources": True,
                    "preservedUnmanagedResources": True, "failedReservationRolledBack": True, "reconciledDrift": True, "retryStatuses": statuses,
                    "verifiedOutputs": outputs}
        finally:
            contract.command("group-delete", group)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--bicep", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix, args.template, args.bicep), sort_keys=True))


if __name__ == "__main__":
    main()
