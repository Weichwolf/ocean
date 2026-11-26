#!/usr/bin/env python3
"""Run the prebuilt Functions package contract using the installed Azure CLI."""

import argparse
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from uuid import uuid4

from application_gateway_cli import fixture_bindings
from arm_cli import GroupContract, create_customers, load_matrix
from functions_cli import command
from identity_cli import AzureCLI
from onboarding_cli import send_token


def write_secret(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(value, output)


def exercise(config, matrix, folder, image, phase):
    fixture = folder / "state.secret"
    if phase == "tenant":
        tenant, = create_customers(config, count=1)
        nonce = uuid4().hex[:10]
        state = {"tenant": tenant, "group": "fxzip-" + nonce, "app": "fxzip" + nonce,
                 "account": "oceanfxzip" + nonce, "plan": "basic", "slot": "staging",
                 "keys": {label: secrets.token_urlsafe(32) for label in ("production", "staging")}}
        write_secret(fixture, state)
    elif phase == "cleanup" and not fixture.exists():
        return {"removed": True}
    else:
        state = json.loads(fixture.read_text())
    tenant = state["tenant"]
    cli = AzureCLI(tenant, str(folder / "az"), register=phase == "tenant")
    if phase == "tenant":
        cli.login_device()
        cli.check_subscription()
        return {"tenant": tenant["tenant"], "subscription": tenant["subscription"], "app": state["app"]}
    contract = GroupContract(cli, load_matrix(matrix))
    rows = {}
    for case in ("PROFILE-02", "FUNCTION-01", "FUNCTION-02", "NETWORK-01", "NETWORK-03", "OBS-02", "STORAGE-01"):
        rows.update(load_matrix(matrix, case))
    providers = f"/subscriptions/{tenant['subscription']}/resourceGroups/{state['group']}/providers"
    app = providers + "/Microsoft.Web/sites/" + state["app"]
    slot = app + "/slots/" + state["slot"]
    args = fixture_bindings(tenant, state["group"]) | {
        key: state[key] for key in ("account", "app", "plan", "slot")
    } | {"image": image, "slot_url": config["arm"] + slot, "api_version": "2025-05-01"}

    def run(label, **overrides):
        return command(cli, rows, contract.version, args | overrides, label)

    def exists(path, api=args["api_version"]):
        status, _ = contract.request("GET", config["arm"] + path, query="api-version=" + api)
        if status not in (200, 404):
            raise RuntimeError(f"fixture inspection returned HTTP {status}")
        return status == 200

    def deploy(label, release, host, expected):
        package = folder / (release + ".zip")
        began = time.monotonic()
        command(cli, rows, contract.version, args | {"package": str(package)}, label,
                expected="Zip deployment failed" if expected == 3 else None)
        status, body = send_token(tenant, contract.token, "GET", f"https://{host}/api/deployments/latest")
        if status != 200 or body.get("status") != expected or body.get("complete") is not True or not body.get("id"):
            raise RuntimeError("the authenticated SCM deployment status did not match the CLI result")
        return {"status": expected, "operation": body["id"], "elapsedMs": round((time.monotonic() - began) * 1000),
                "packageSHA256": hashlib.sha256(package.read_bytes()).hexdigest()}

    scm = state["app"] + "." + config["scm"]
    scm_slot = state["app"] + "-" + state["slot"] + "." + config["scm"]
    if phase == "create":
        contract.command("group-create", state["group"])
        run("storage-account-create")
        run("function-plan-create")
        run("function-node-create")
        run("vnet-create")
        run("function-vnet-add")
        created = run("functions-slot-create")
        listed = run("functions-slot-list")
        if created["id"] != slot or [item["id"] for item in listed] != [slot] or run("functions-slot-discovery")["value"]:
            raise RuntimeError("the new slot did not round-trip as a separate empty ARM resource")
        production = deploy("functions-zip-production", "first", scm, 4)
        staging = deploy("functions-zip-slot", "second", scm_slot, 4)
        for label in ("production", "staging"):
            run("functions-" + ("production" if label == "production" else "slot") + "-settings", setting=label, sticky=label)
        run("function-key-set", key=state["keys"]["production"])
        key_file = folder / "staging-key.secret"
        write_secret(key_file, {"properties": {"name": "e2e", "value": state["keys"]["staging"]}})
        run("functions-slot-key-set", key_file=str(key_file), key=state["keys"]["staging"])
        key_file.unlink()
        if [item["name"].split("/")[-1] for item in run("functions-slot-discovery")["value"]] != ["hello"]:
            raise RuntimeError("the staging ZIP did not expose its Functions index")
        return {"azureCLI": contract.version["azure-cli"], "subscription": tenant["subscription"], "tenant": tenant["tenant"],
                "production": production, "staging": staging, "productionId": app, "slotId": slot, "probeKeys": state["keys"]}
    if phase == "reject":
        return deploy("functions-zip-production", "unindexed", scm, 3)
    if phase == "swap":
        began = time.monotonic()
        run("functions-slot-swap")
        return {"elapsedMs": round((time.monotonic() - began) * 1000)}
    if phase == "cleanup":
        if exists(slot):
            run("functions-slot-delete")
            if run("functions-slot-list") or exists(slot):
                raise RuntimeError("the deleted slot remained in the app collection")
        if exists(app):
            run("function-app-delete")
        if exists(providers + "/Microsoft.Web/serverfarms/" + state["plan"]):
            run("function-plan-delete")
        account = providers + "/Microsoft.Storage/storageAccounts/" + state["account"]
        if exists(account, "2026-09-01"):
            for site in (slot, app):
                share = "func-" + hashlib.sha256(site.encode()).hexdigest()[:24]
                if exists(account + "/fileServices/default/shares/" + share, "2024-01-01"):
                    run("storage-share-delete", share=share)
            run("storage-account-delete")
        if contract.command("group-exists", state["group"]):
            contract.command("group-delete", state["group"])
        if contract.command("group-exists", state["group"]):
            raise RuntimeError("the disposable Functions resource group remained after cleanup")
        return {"removed": True, "slotRemoved": True}
    raise RuntimeError(f"unrecognized Functions ZIP phase {phase}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--scm", required=True)
    parser.add_argument("--phase", choices=("tenant", "create", "reject", "swap", "cleanup"), required=True)
    args = parser.parse_args()
    config = json.loads(args.settings.read_text()) | {"scm": args.scm}
    print(json.dumps(exercise(config, args.matrix, args.folder, args.image, args.phase), sort_keys=True))


if __name__ == "__main__":
    main()
