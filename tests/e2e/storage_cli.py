#!/usr/bin/env python3
"""Exercise the Azure Files mount contract with the pinned Azure CLI."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI

ACCOUNT_VERSION = "2026-09-01"
SHARE_VERSION = "2024-01-01"


def wait_ready(check):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        result = check()
        if result and result["properties"]["provisioningState"] == "Succeeded":
            return result
        time.sleep(1)
    raise RuntimeError("the File Share did not complete its data-plane operation")


def exercise(settings, matrix, fixture, program, phase, image):
    if phase == "setup":
        customer, foreign = create_customers(settings)
        nonce = uuid4().hex[:10]
        saved = {"tenant": customer, "foreign": foreign, "group": "files-" + nonce, "account": "oceanfiles" + nonce,
                 "share": "checkpoint", "checksum": hashlib.sha256(nonce.encode()).hexdigest()}
        with os.fdopen(os.open(fixture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as state:
            json.dump(saved, state)
    elif fixture.exists():
        saved = json.loads(fixture.read_text())
    elif phase == "cleanup":
        return {"removed": True}
    else:
        raise RuntimeError("the storage fixture has not been set up")
    tenant = saved["tenant"]
    ids = {key: saved[key] for key in ("group", "account", "share")}
    vol_id = (f"/subscriptions/{tenant['subscription']}/resourceGroups/{ids['group']}/providers/Microsoft.Storage/"
              f"storageAccounts/{ids['account']}/fileServices/default/shares/{ids['share']}")
    common = load_matrix(matrix)
    containers = load_matrix(matrix, "CONTAINER-01")
    storage = load_matrix(matrix, "STORAGE-01")
    with tempfile.TemporaryDirectory(prefix="ocean-storage-cli-") as directory:
        cli = AzureCLI(tenant, str(Path(directory) / "customer"))
        cli.login_device()
        contract = GroupContract(cli, common)
        mount_key = saved.get("key", "")
        variables = ids | {"location": tenant["location"], "name": "first-writer", "image": image or "", "mount_key": mount_key}

        def command(label, *, values=None, client=cli, expected=None):
            override = variables | (values or {})
            row = storage.get(label) or containers[label]
            args = command_args(row, contract.version, **override)
            reply = subprocess.run(["az", *args], env=client.env, capture_output=True, text=True, timeout=90)
            if expected:
                if reply.returncode == 0 or expected not in reply.stderr:
                    raise RuntimeError(f"{label} did not report {expected}")
                return None
            if reply.returncode:
                message = next((line for line in reply.stderr.splitlines() if line.startswith(("Code:", "ERROR:"))), "")
                if mount_key:
                    message = message.replace(mount_key, "[redacted]")
                raise RuntimeError(f"{label} failed ({reply.returncode}) {message}")
            if label == "storage-account-key":
                return reply.stdout.strip()
            if mount_key and (mount_key in reply.stdout or mount_key in reply.stderr):
                raise RuntimeError("an ARM response exposed the storage key")
            return json.loads(reply.stdout) if reply.stdout.strip() else None

        def show_share():
            status, result = contract.request("GET", contract.origin + vol_id, query=f"api-version={SHARE_VERSION}")
            if status == 200:
                return result
            if status != 404:
                raise RuntimeError(f"share read returned HTTP {status}")
            return None

        if phase == "setup":
            contract.command("group-create", ids["group"])
            command("storage-account-create")
            account = command("storage-account-show")
            if account["kind"] != "StorageV2" or account["sku"]["name"] != "Standard_LRS":
                raise RuntimeError("storage account metadata did not round-trip")
            key = command("storage-account-key")
            if len(key) != 88:
                raise RuntimeError("the account returned no mount credential")
            saved["key"] = key
            with fixture.open("w") as state:
                json.dump(saved, state)
            command("storage-share-create")
            ready = wait_ready(show_share)
            shown = command("storage-share-show")
            if shown["id"] != ready["id"] or shown["shareQuota"] != 1:
                raise RuntimeError("file share metadata did not round-trip")
            return {"azureCLI": contract.version["azure-cli"], "shareId": vol_id, "checksum": saved["checksum"],
                    "tenant": tenant["tenant"], "subscription": tenant["subscription"], "group": ids["group"]}
        if phase == "cache-arm-token":
            saved["armToken"] = contract.token
            with fixture.open("w") as state:
                json.dump(saved, state)
            return {"cachedARMToken": True}
        if phase == "cleanup":
            for name in ("first-writer", "replacement-writer"):
                command("container-delete", values={"name": name})
            if show_share() is not None:
                command("storage-share-delete")
                until = time.monotonic() + 30
                while show_share() is not None and time.monotonic() < until:
                    time.sleep(1)
                if show_share() is not None:
                    raise RuntimeError("storage share cleanup did not complete")
            command("storage-account-delete")
            contract.command("group-delete", ids["group"])
            fixture.unlink()
            return {"removed": True}
        if phase == "metadata-check":
            args = command_args(common["inventory-show"], contract.version, id=vol_id, version=SHARE_VERSION)
            result = json.loads(cli.run(*args))
            if result["id"] != vol_id or result["properties"]["shareQuota"] != 1 or command("storage-account-key") != saved["key"]:
                raise RuntimeError("the restored metadata or account credential differs from the backup checkpoint")
            other = AzureCLI(saved["foreign"], str(Path(directory) / "other"))
            other.login_device()
            denied = subprocess.run(["az", *args], env=other.env, capture_output=True, text=True, timeout=30)
            if denied.returncode == 0 or "SubscriptionNotFound" not in denied.stderr:
                raise RuntimeError("the restored environment exposed the share to a foreign tenant")
            return {"azureResourceShowVerified": True, "accountCredentialMatched": True, "restoredTenantScopeEnforced": True}
        script = program.read_text()
        action = "write" if phase == "write" else "read"
        variables["command_line"] = shlex.join(["/bin/sh", "-c", script, "checkpoint-http", action, saved["checksum"]])
        if phase == "deny-foreign":
            other = AzureCLI(saved["foreign"], str(Path(directory) / "other"))
            other.login_device()
            other_contract = GroupContract(other, common)
            other_group = "storage-foreign-" + uuid4().hex[:10]
            other_contract.command("group-create", other_group)
            try:
                command("container-create-mounted", client=other, values={"group": other_group}, expected="StorageAuthorizationFailed")
                return {"foreignMountDenied": True}
            finally:
                command("container-delete", client=other, values={"group": other_group})
                other_contract.command("group-delete", other_group)
        if phase == "stop-writer":
            command("container-delete")
            wait_ready(show_share)
            return {"shareSurvivedDeletion": True}
        if phase == "deny-second":
            command("container-create-mounted", values={"name": "replacement-writer"}, expected="StorageResourceInUse")
            return {"secondWriterDenied": True}
        if phase == "recover":
            variables["name"] = "replacement-writer"
        command("container-create-mounted")
        workload = command("container-show")
        if workload["instanceView"]["state"] != "Running":
            raise RuntimeError("the mounted workload was not running")
        return {"address": workload["ipAddress"]["ip"], "id": workload["id"], "tenant": tenant["tenant"],
                "subscription": tenant["subscription"], "group": ids["group"], "checksum": saved["checksum"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--image")
    parser.add_argument("--phase", required=True, choices=("setup", "cleanup", "write", "stop-writer", "recover", "deny-foreign", "deny-second", "metadata-check", "cache-arm-token"))
    args = parser.parse_args()
    result = exercise(json.loads(args.settings.read_text()), args.matrix, args.fixture, args.program, args.phase, args.image)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
