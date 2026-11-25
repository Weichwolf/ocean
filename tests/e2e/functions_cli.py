#!/usr/bin/env python3
"""Exercise the Functions ARM contract with the pinned, unmodified Azure CLI."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from application_gateway_cli import fixture_bindings, issue_test_certificate
from arm_cli import GroupContract, command_args, create_customers, load_matrix
from arm_rbac_cli import create_service_principal
from identity_cli import AzureCLI


def command(cli, rows, version, values, label, *, expected=None):
    args = command_args(rows[label], version, **values)
    result = subprocess.run(["az", *args], env=cli.env, capture_output=True, text=True, timeout=100)
    if expected:
        if result.returncode == 0 or expected not in result.stderr:
            raise RuntimeError(f"{label} did not fail with {expected}")
        return None
    if result.returncode:
        error = next((line for line in result.stderr.splitlines() if line.startswith(("Code:", "ERROR:"))), "")
        for key in ("key", "certificate_password"):
            if values.get(key):
                error = error.replace(values[key], "[redacted]")
        if any(field in error.lower() for field in ("accountkey=", "machinekey_decryptionkey=", "authorization: bearer")):
            error = "[redacted]"
        raise RuntimeError(f"{label} failed ({result.returncode}) {error[:250]}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def exercise(settings, matrix, fixture, phase, images):
    if phase == "setup":
        tenant, foreign = create_customers(settings)
        nonce = uuid4().hex[:10]
        state = {"tenant": tenant, "foreign": foreign, "group": "fx-" + nonce, "plan": "b1", "app": "fx" + nonce,
                 "account": "oceanfunc" + nonce, "key": secrets.token_urlsafe(32), "setting": "configured",
                 "observer": "http://198.51.100.30:8080/source"}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            json.dump(state, stream)
    elif fixture.exists():
        state = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"removed": True}
    else:
        raise RuntimeError("the isolated Function fixture has no state")
    tenant = state["tenant"]
    app_id = (f"/subscriptions/{tenant['subscription']}/resourceGroups/{state['group']}/providers/Microsoft.Web/sites/" + state["app"])
    state["share"] = "func-" + hashlib.sha256(app_id.encode()).hexdigest()[:24]
    rows = {}
    for case in ("FUNCTION-01", "FUNCTION-02", "NETWORK-01", "NETWORK-02", "NETWORK-03", "STORAGE-01"):
        rows.update(load_matrix(matrix, case))
    with tempfile.TemporaryDirectory(prefix="ocean-functions-cli-") as folder:
        folder = Path(folder)
        cli = AzureCLI(tenant, str(folder / "tenant"))
        cli.login_device()
        contract = GroupContract(cli, load_matrix(matrix))
        defaults = fixture_bindings(tenant, state["group"])
        params = defaults | state | {"image": images["v1"], "backend_port": "80", "nat": "fixed-egress"}

        def run(label, *, expected=None, **override):
            return command(cli, rows, contract.version, params | override, label, expected=expected)

        def public_properties(output):
            return output.get("properties", output)

        if phase == "setup":
            contract.command("group-create", state["group"])
            run("storage-account-create")
            run("function-plan-create")
        if phase in ("setup", "inspect"):
            profile = run("function-plan-show")
            if profile["sku"]["name"] != "B1" or not public_properties(profile)["reserved"]:
                raise RuntimeError("the ARM Functions plan did not round-trip")
            if phase == "setup":
                run("function-app-create")
            shown = run("function-app-show")
            if shown["id"] != app_id or public_properties(shown)["state"] != "Running":
                raise RuntimeError("the Azure CLI returned before the native Function host was ready")
            discovered = run("function-list")
            if len(discovered) != 1 or discovered[0]["name"].split("/")[-1] != "hello":
                raise RuntimeError("the native Java Function was not discovered")
            if phase == "setup":
                run("function-key-set")
            listed = run("function-key-list")
            if listed.get("e2e") != state["key"] or "_master" in listed:
                raise RuntimeError("the native Function key state did not round-trip securely")
            return {"id": app_id, "host": public_properties(shown)["defaultHostName"], "azureCLI": contract.version["azure-cli"],
                    "nativeFunctionDiscovered": True, "configuredKeyRoundTrip": True}
        if phase == "authorize":
            client, principal, credential = create_service_principal(cli)
            scope = app_id.split("/providers/")[0]
            reader_roles = load_matrix(matrix, "IDENTITY-04")
            variables = {"scope": scope, "name": str(uuid4()), "principal": principal, "kind": "ServicePrincipal"}
            grant = command(cli, reader_roles, contract.version, variables, "role-create")
            try:
                for attempt in range(3):
                    reader = AzureCLI(tenant, str(folder / f"reader-{attempt}"))
                    try:
                        reader.login_service_principal(client, credential)
                    except RuntimeError:
                        if attempt == 2:
                            raise
                        time.sleep(1)
                    else:
                        break
                command(reader, rows, contract.version, params, "function-app-show")
                for label in ("function-key-set", "function-key-list"):
                    command(reader, rows, contract.version, params, label, expected="AuthorizationFailed")
            finally:
                command(cli, reader_roles, contract.version, {"id": grant["id"]}, "role-delete")
            return {"readerCanReadApp": True, "readerKeyReadDenied": True, "readerKeyWriteDenied": True}
        if phase == "update":
            run("function-settings-set")
            settings_list = {item["name"]: item["value"] for item in run("function-settings-list")}
            if settings_list.get("OCEAN_SETTING") != state["setting"]:
                raise RuntimeError("the effective Functions environment did not match its ARM configuration")
            run("function-container-set", image=images["v2"])
            shown = run("function-container-show")
            if not any(item["value"].removeprefix("DOCKER|") == images["v2"] for item in shown):
                raise RuntimeError("the Azure CLI did not report the new Function image")
            apps = run("function-app-list")
            if len(apps) != 1 or apps[0]["id"] != app_id:
                raise RuntimeError("the app did not appear in the resource group collection")
            return {"settingsRoundTrip": True, "imageRevisionVerified": True, "appListVerified": True}
        if phase in ("start", "stop", "restart"):
            run("function-app-" + phase)
            shown = run("function-app-show")
            actual = public_properties(shown)["state"]
            if actual != ("Stopped" if phase == "stop" else "Running"):
                raise RuntimeError(f'the Function {phase} did not reach the intended state')
            return {"state": actual}
        if phase == "integrate":
            run("vnet-create")
            run("function-vnet-add")
        if phase in ("integrate", "integration-status"):
            connections = run("function-vnet-list")
            if len(connections) != 1 or not connections[0]["vnetResourceId"].endswith("/virtualNetworks/private"):
                raise RuntimeError("the Azure CLI did not report the integrated private VNet")
            return {"privateVNetVerified": True}
        if phase == "egress":
            public = run("public-ip-create", ip="fixed-ip")
            address = public_properties(public["publicIp"])["ipAddress"]
            created = run("nat-create", ip="fixed-ip")
            attached = run("subnet-nat")
            shown = run("nat-show")
            public_ip = run("public-ip-show", ip="fixed-ip")
            if (shown["id"] != created["id"] or public_properties(public_ip)["ipAddress"] != address or
                    public_properties(attached)["natGateway"]["id"] != shown["id"] or
                    [item["id"] for item in public_properties(shown)["publicIpAddresses"]] != [public_ip["id"]]):
                raise RuntimeError("the assigned fixed IPv4 path did not round-trip through ARM")
            return {"fixedIPv4": address, "natAndSubnetVerified": True}
        if phase == "publish":
            bundle, password = issue_test_certificate(folder, state["app"] + ".functions.farm-1.ocean.test")
            public = run("public-ip-create")
            address = public_properties(public["publicIp"])["ipAddress"]
            run("app-gateway-create", certificate_pfx=str(bundle), certificate_password=password)
            return {"httpsIPv4": address, "certificate": (folder / "ingress.pem").read_text()}
        if phase == "cleanup":
            gateway_id = app_id.split("/providers/")[0] + "/providers/Microsoft.Network/applicationGateways/" + params["gateway"]
            if contract.request("GET", contract.origin + gateway_id, query="api-version=2026-01-01")[0] == 200:
                run("app-gateway-delete")
            run("function-app-delete")
            run("function-plan-delete")
            run("function-plan-show", expected="ResourceNotFound")
            # Host storage is an independent, tenant-owned resource.
            status, _ = contract.request("GET", contract.origin + app_id, query="api-version=2025-05-01")
            if status != 404:
                raise RuntimeError("a deleted Function App remained in ARM")
            exit_status, _ = contract.request("GET",
                contract.origin + app_id.split("/providers/")[0] + "/providers/Microsoft.Storage/storageAccounts/" +
                state["account"] + "/fileServices/default/shares/" + state["share"], query="api-version=2024-01-01")
            if exit_status == 200:
                run("storage-share-delete")
            run("storage-account-delete")
            contract.command("group-delete", state["group"])
            fixture.unlink()
            return {"removed": True}
    raise RuntimeError("unrecognized Functions fixture phase")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--images", required=True, type=Path)
    parser.add_argument("--phase", required=True,
                        choices=("setup", "inspect", "authorize", "update", "publish", "egress", "integrate",
                                 "integration-status", "start", "stop", "restart", "cleanup"))
    args = parser.parse_args()
    result = exercise(json.loads(args.settings.read_text()), args.matrix, args.fixture, args.phase, json.loads(args.images.read_text()))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
