#!/usr/bin/env python3
"""Exercise the Cost Management and workload contracts through Azure CLI."""

import argparse
import json
import os
import shlex
import subprocess
from datetime import date, timedelta
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from arm_rbac_cli import create_service_principal
from functions_cli import command
from identity_cli import AzureCLI
from telemetry_load_cli import LOAD


def exercise(settings, matrix, folder, phase, image, first, last):
    fixture = folder / "state.secret"
    if phase == "setup":
        customer, foreign = create_customers(settings)
        nonce = uuid4().hex[:10]
        state = {"customer": customer, "foreign": foreign, "groups": ["cost-a-" + nonce, "cost-b-" + nonce]}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            json.dump(state, output)
    elif fixture.exists():
        state = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"removed": True}
    else:
        raise RuntimeError("the Cost Management workload was not set up")
    customer, foreign = state["customer"], state["foreign"]
    admin = AzureCLI(customer, str(folder / "admin"), register=phase == "setup")
    if phase == "setup":
        admin.login_device()
        admin.check_subscription()
    contract = GroupContract(admin, load_matrix(matrix))
    rows = {}
    for case in ("PROFILE-03", "CONTAINER-01", "NETWORK-01", "OBS-02"):
        rows.update(load_matrix(matrix, case))
    subscription_path = f"/subscriptions/{customer['subscription']}"
    values = {"origin": contract.origin, "location": customer["location"], "subscription": customer["subscription"],
              "name": "load", "image": image, "vnet": "private", "subnet": "load",
              "program": shlex.join(["/bin/sh", "-c", LOAD]), "cpu": "0.25", "memory": "0.0625"}

    def run(label, **bindings):
        return command(admin, rows, contract.version, values | bindings, label)

    if phase == "setup":
        resources = []
        for number, group in enumerate(state["groups"], 1):
            contract.command("group-create", group)
            prefix = f"10.97.{number}."
            subnet_id = f"{subscription_path}/resourceGroups/{group}/providers/Microsoft.Network/virtualNetworks/private/subnets/load"
            run("vnet-create", group=group, vnet_prefix=prefix + "0/24", subnet_prefix=prefix + "0/27")
            deployed = run("telemetry-load-create", group=group, subnet_id=subnet_id)
            logs = admin.run(*command_args(rows["container-logs"], contract.version, **(values | {"group": group})))
            if "ocean telemetry load ready" not in logs:
                raise RuntimeError("the metered workload did not produce its runtime log marker")
            resources.append(deployed["id"])
        return {"azureCLI": contract.version["azure-cli"], "tenant": customer["tenant"],
                "subscription": customer["subscription"], "resources": resources, "groups": state["groups"]}
    if phase in ("stop", "delete", "cleanup"):
        verb = "delete" if phase == "cleanup" else phase
        for group in state["groups"]:
            if contract.command("group-exists", group):
                run("container-" + verb, group=group)
                if phase == "cleanup":
                    contract.delete_group(group)
        return {phase: True}
    if phase not in ("query", "history"):
        raise RuntimeError("unrecognized Cost Management acceptance phase")

    def query(client, definition, group="", subscription=customer["subscription"], error=None):
        request = folder / "query.json"
        request.write_text(json.dumps(definition))
        command_id = "cost-query-group" if group else "cost-query-subscription"
        args = command_args(rows[command_id], contract.version, **(values | {
            "body": str(request), "group": group, "subscription": subscription}))
        if error:
            reply = subprocess.run(["az", *args], env=client.env, capture_output=True, text=True, timeout=30)
            if reply.returncode == 0 or error not in reply.stderr:
                raise RuntimeError(f"Cost Management did not report {error}")
            return None
        output = client.run(*args)
        return json.loads(output)["properties"] if output.strip() else None

    def definition(begin, finish, granularity, *dimensions):
        return {"type": "Usage", "timeframe": "Custom",
                "timePeriod": {"from": begin + "T00:00:00Z", "to": finish + "T00:00:00Z"},
                "dataset": {"granularity": granularity, "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}},
                            "grouping": [{"name": dim, "type": "Dimension"} for dim in dimensions]}}

    combined = definition(first, last, "None", "ResourceId", "MeterId")
    if phase == "history":
        return {"historical": query(admin, combined)}
    other = AzureCLI(foreign, str(folder / "foreign"))
    other.login_device()
    other.check_subscription()
    foreign_contract = GroupContract(other, load_matrix(matrix))
    # az rest selects its token from the URL's subscription. Send the token
    # from the foreign CLI session directly to verify the server's boundary.
    status, payload = foreign_contract.request("POST", contract.origin + subscription_path + "/providers/Microsoft.CostManagement/query",
                                               combined, query="api-version=" + rows["cost-query-subscription"]["api_version"])
    if status != 404 or payload["error"]["code"] != "SubscriptionNotFound":
        raise RuntimeError("Cost Management did not reject the token from a different subscription")
    if query(other, combined, subscription=foreign["subscription"]) is not None:
        raise RuntimeError("a different subscription received the metered tenant's usage")
    empty_day = (date.fromisoformat(first) - timedelta(days=2)).isoformat()
    if query(admin, definition(empty_day, empty_day, "None", "MeterId")) is not None:
        raise RuntimeError("an empty UTC window returned a cost table")
    bad = definition(first, last, "None", "MeterId")
    bad["dataset"]["filter"] = {"dimensions": {"name": "MeterId", "operator": "In", "values": ["cpu-vcpu-hour"]}}
    query(admin, bad, error="InvalidCostQuery")
    bad_window = definition(first, last, "None", "MeterId")
    bad_window["timePeriod"]["from"] = first + "T12:00:00Z"
    query(admin, bad_window, error="InvalidCostQuery")
    group_tables = {group: query(admin, combined, group=group) for group in state["groups"]}
    allowed, denied = state["groups"]
    app, principal, password = create_service_principal(admin)
    assignments = load_matrix(matrix, "IDENTITY-04")
    grant = command(admin, assignments, contract.version,
                    {"scope": subscription_path + "/resourceGroups/" + allowed, "name": str(uuid4()),
                     "principal": principal, "kind": "ServicePrincipal"}, "role-create")
    try:
        reader = AzureCLI(customer, str(folder / "reader"))
        reader.login_service_principal(app, password)
        reader.check_subscription()
        if query(reader, combined, group=allowed) != group_tables[allowed]:
            raise RuntimeError("the Reader's group costs differed from the owner's scoped table")
        query(reader, combined, group=denied, error="AuthorizationFailed")
        query(reader, combined, error="AuthorizationFailed")
    finally:
        command(admin, assignments, contract.version, {"id": grant["id"]}, "role-delete")
    query(reader, combined, group=allowed, error="AuthorizationFailed")
    return {"byResourceAndMeter": query(admin, combined),
            "dailyByMeter": query(admin, definition(first, last, "Daily", "MeterId")),
            "byGroup": group_tables, "readerScopeAndRevocationVerified": True,
            "foreignEmptyAndCrossTenantDenied": True, "emptyWindowVerified": True,
            "unsupportedFilterRejected": True, "unsupportedWindowRejected": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--phase", choices=("setup", "stop", "query", "delete", "history", "cleanup"), required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--first", default="")
    parser.add_argument("--last", default="")
    args = parser.parse_args()
    result = exercise(json.loads(args.settings.read_text()), args.matrix, args.folder, args.phase, args.image, args.first, args.last)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
