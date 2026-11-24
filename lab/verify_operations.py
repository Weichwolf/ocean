#!/usr/bin/env python3
"""Verify durable ARM operation recovery after restarting a lab API process."""

import argparse
import base64
import copy
import json
import shlex
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
from region import ARM, DEST, NODES, OPERATOR, etcdctl, eventually, ssh, upload
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def wait_api(state, node):
    eventually(lambda: ssh(state, node, f"curl -fsS --max-time 3 --cacert {DEST}/pki/ingress-ca.pem "
                                       f"--resolve {ARM}:8443:{NODES[node]} https://{ARM}:8443/readyz"), 30)


def configure(state, node, config):
    upload(state, node, {"api.json": json.dumps(config).encode()})
    ssh(state, node, "sudo systemctl restart ocean-api.service")
    wait_api(state, node)


def reset_api(state, node):
    command = "systemctl show ocean-api.service --property=MainPID --value"
    previous = int(ssh(state, node, command))
    if previous <= 0:
        raise RuntimeError("the API service has no process to restart")
    ssh(state, node, "sudo systemctl kill --kill-whom=main --signal=SIGKILL ocean-api.service")

    def replacement():
        current = int(ssh(state, node, command))
        if current <= 0 or current == previous:
            raise RuntimeError("the API service has not started a replacement process")
        return current

    current = eventually(replacement, 25)
    wait_api(state, node)
    return {"node": node, "previousPID": previous, "replacementPID": current}


def verify_store(state, result):
    tenant, subscription, operation = (uuid.UUID(result[key]) for key in ("tenantId", "subscriptionId", "operationId"))
    root = "/ocean/v1/regions/farm-1/operations"
    prefix = f"{root}/records/{tenant}/{subscription}/"
    records = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix} --prefix --write-out=json")))
    if records.get("count") != 1 or len(records.get("kvs", [])) != 1:
        raise RuntimeError("retried deletion did not retain exactly one durable operation record")
    item = records["kvs"][0]
    record = json.loads(base64.b64decode(item["value"]))
    if (record["operationId"] != str(operation) or record["status"] != "Succeeded" or
            not record.get("endTime") or int(item["create_revision"]) >= int(item["mod_revision"])):
        raise RuntimeError("the persisted operation did not advance from acceptance to completion")
    pending = json.loads(ssh(state, OPERATOR, etcdctl(f"get {root}/pending/{operation} --write-out=json")))
    if pending.get("count", 0) != 0:
        raise RuntimeError("the completed operation remained queued")
    return {"acceptedRevision": item["create_revision"], "completedRevision": item["mod_revision"], "operationsForFirstDeletion": 1}


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "arm_operations_cli.py", "testdata/arm-contract.tsv"))
    session_dir = ssh(state, OPERATOR, "mktemp -d /tmp/ocean-operation.XXXXXXXX").decode().strip()
    if not session_dir.startswith("/tmp/ocean-operation.") or not session_dir.removeprefix("/tmp/ocean-operation.").isalnum():
        raise RuntimeError("the operator guest created an unexpected session path")

    def stage(name):
        command = ["python3", f"{CLIENT}/arm_operations_cli.py", name, "--settings", f"{CLIENT}/operator.secret",
                   "--matrix", f"{CLIENT}/arm-contract.tsv", "--session", session_dir + "/session.json"]
        response = ssh(state, OPERATOR, shlex.join(command))
        return json.loads(response) if response.strip() else None

    settings = {node: json.loads(ssh(state, node, f"cat {DEST}/api.json")) for node in NODES}
    changed = set()
    try:
        stage("prepare")
        for node, config in settings.items():
            disabled = copy.deepcopy(config)
            disabled["region"]["operationController"] = False
            changed.add(node)
            configure(state, node, disabled)
        pending = stage("start")
        print("An accepted deletion stayed pending during the operation controller outage. Six retries returned the same operation.", flush=True)
        crashed = next(iter(NODES))
        restarted = reset_api(state, crashed)
        if stage("pending") != pending:
            raise RuntimeError("the same pending operation was not available after the API restart")

        recovered = next(node for node in NODES if node != crashed and settings[node]["region"].get("operationController", True))
        configure(state, recovered, settings[recovered])
        changed.remove(recovered)
        evidence = stage("finish")
        evidence.update({"restartedAPI": restarted, "reconcilingNode": recovered, "pendingAfterAPIRestart": True,
                         "crossTenantPollDenied": pending["crossTenantPollDenied"], **verify_store(state, evidence)})
        print("A different controller completed the original operation and its terminal state survived a group recreation.", flush=True)
        return evidence
    finally:
        try:
            for node in NODES:
                if node in changed:
                    configure(state, node, settings[node])
            stage("cleanup")
        finally:
            ssh(state, OPERATOR, shlex.join(["rm", "-f", "--", session_dir + "/session.json"]) + " && " +
                shlex.join(["rmdir", "--", session_dir]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    state = parser.parse_args().state.resolve()
    evidence = verify(state)
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "arm-operations.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
