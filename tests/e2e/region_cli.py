#!/usr/bin/env python3
"""Use one isolated Azure CLI cloud profile through regional management faults."""

import argparse
import base64
import hashlib
import http.client
import json
import re
import socket
import ssl
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from arm_cli import command_args, create_customers, load_matrix, verify_group
from identity_cli import AzureCLI
from arm_operations_cli import save_state


def canary_command(cli, matrix, label, **bindings):
    args = command_args(matrix[label], cli.version, **bindings)
    deadline = time.monotonic() + 18
    reason = "deadline"
    while time.monotonic() < deadline:
        try:
            reply = subprocess.run(["az", *args], env=cli.env, capture_output=True, text=True,
                                   timeout=min(10, deadline-time.monotonic()))
            if not reply.returncode:
                return reply.stdout
            code = re.search(r"(?m)^Code: ([A-Za-z][A-Za-z0-9]{1,63})$", reply.stderr)
            reason = code[1] if code else f"exit {reply.returncode}"
        except subprocess.TimeoutExpired:
            reason = "deadline"
        time.sleep(0.5)
    raise RuntimeError(f"{label} failed through the existing Azure CLI profile ({reason})")


def exercise(args):
    session = args.session
    fixture_path = session / "fixture.secret"
    if args.stage == "setup":
        config, _ = create_customers(json.loads(args.settings.read_text()))
        cli = AzureCLI(config, str(session / "az"))
        cli.login_device()
        fixture = {"config": config, "group": "region-" + uuid4().hex[:12],
                   "armToken": cli.run("account", "get-access-token", "--resource", config["arm"],
                                       "--query", "accessToken", "-o", "tsv").strip()}
        save_state(fixture_path, fixture)
        claims = fixture["armToken"].split(".")[1]
        expires = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))["exp"]
        if expires - time.time() < 480:
            raise RuntimeError("the ARM token has insufficient cache time for the fault window")
    elif fixture_path.exists():
        fixture = json.loads(fixture_path.read_text())
        config = fixture["config"]
        if args.stage == "observe":
            observe(args, fixture)
            return
        cli = AzureCLI(config, str(session / "az"), register=False)
    elif args.stage == "cleanup":
        return
    else:
        raise RuntimeError("the regional CLI session has not been prepared")

    cli.version = json.loads(cli.run("version", "-o", "json"))
    matrix = load_matrix(args.matrix, "HA-05") | load_matrix(args.matrix, "HA-06")
    group = fixture["group"]
    prefix = f"/subscriptions/{config['subscription']}/resourcegroups/"
    bindings = {"group": group, "location": config["location"], "tag": "acknowledged",
                "name": "retained-http", "port": 80, "image": args.image}

    def az(label, **overrides):
        response = canary_command(cli, matrix, label, **(bindings | overrides))
        return json.loads(response) if response.strip() else None

    if args.stage == "setup":
        verify_group(az("management-group-create"), prefix + group, group, "acknowledged")
        az("voter-container-create")
        container = az("voter-container-show")
        if container.get("instanceView", {}).get("state") != "Running":
            raise RuntimeError("the acknowledged workload fixture is not running")
        return
    if args.stage == "cleanup":
        az("voter-container-delete")
        az("management-group-delete")
        for label in ("gateway", "api", "leader"):
            candidate = group + "-" + label
            if az("management-group-exists", group=candidate):
                az("management-group-delete", group=candidate)
        return

    accounts = az("management-account-list")
    if [(row["id"], row["tenantId"]) for row in accounts] != [(config["subscription"], config["tenant"])]:
        raise RuntimeError("the existing cloud profile lost its assigned account")
    verify_group(az("management-group-show"), prefix + group, group, "acknowledged")
    container_id = ""
    if args.stage == "leader":
        container = az("voter-container-show")
        container_id = container["id"]
        if container_id.lower() != prefix + group + "/providers/microsoft.containerinstance/containergroups/retained-http":
            raise RuntimeError("the acknowledged workload could not be read after the election")
    candidate = group + "-" + args.stage
    created = az("management-group-create", group=candidate, tag=args.stage)
    retry = az("management-group-create", group=candidate, tag=args.stage)
    verify_group(created, prefix + candidate, candidate, args.stage)
    verify_group(retry, prefix + candidate, candidate, args.stage)
    if sum(row["id"] == created["id"] for row in az("management-group-list")) != 1:
        raise RuntimeError("the retried mutation did not preserve exactly one resource")
    az("management-group-delete", group=candidate)
    if az("management-group-exists", group=candidate):
        raise RuntimeError("the acknowledged deletion remained visible")
    return {"azureCLI": cli.version["azure-cli"], "subscriptionId": config["subscription"],
            "retainedGroup": group, "retainedContainerId": container_id, "newMutationId": created["id"],
            "retriedMutationUnique": True, "deletedThroughSameCloud": True}


def observe(args, fixture):
    config = fixture["config"]
    host = urlsplit(config["arm"]).hostname
    route = f"/subscriptions/{config['subscription']}/resourceGroups/{fixture['group']}?api-version=2024-11-01"
    tls = ssl.create_default_context(cafile=config["ca"])
    failure_codes = {ConnectionResetError: "connection reset", socket.gaierror: "DNS lookup failed",
                     TimeoutError: "connection timed out", ConnectionRefusedError: "connection refused"}
    with (args.session / "observations.jsonl").open("w") as observations:
        while not (args.session / "stop-observer").exists():
            phase = (args.session / "phase").read_text().strip()
            started = time.monotonic()
            attempts = []
            acknowledged = False
            while time.monotonic() - started < 12:
                connection = http.client.HTTPSConnection(host, timeout=2, context=tls)
                attempt_started = time.monotonic()
                report = {}
                try:
                    answers = {item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}
                    if answers != {args.vip}:
                        raise RuntimeError("unexpected regional DNS records")
                    report["resolvedAddress"] = args.vip
                    connection.connect()
                    certificate = connection.sock.getpeercert()
                    report["dnsIdentity"] = host if ("DNS", host) in certificate["subjectAltName"] else "missing"
                    if report["dnsIdentity"] != host:
                        raise RuntimeError("missing management TLS identity")
                    report["leafSHA256"] = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
                    connection.request("GET", route, headers={"Authorization": "Bearer " + fixture["armToken"]})
                    response = connection.getresponse()
                    report["status"] = response.status
                    body = response.read(1 << 16)
                    if response.status == 200 and json.loads(body).get("name") == fixture["group"]:
                        acknowledged = True
                except (OSError, http.client.HTTPException, ValueError, RuntimeError) as failure:
                    report["error"] = failure_codes.get(type(failure), type(failure).__name__)
                finally:
                    connection.close()
                report["durationMs"] = round(1000 * (time.monotonic() - attempt_started))
                attempts.append(report)
                if acknowledged:
                    break
                time.sleep(0.2)
            observations.write(json.dumps({"phase": phase, "timestamp": time.time(), "durationMs": round(1000 * (time.monotonic() - started)),
                                           "acknowledged": acknowledged, "attempts": attempts}) + "\n")
            observations.flush()
            time.sleep(0.4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("setup", "gateway", "api", "leader", "observe", "cleanup"))
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--vip", required=True)
    result = exercise(parser.parse_args())
    if result is not None:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
