#!/usr/bin/env python3
"""Run the ARM compatibility matrix in the isolated local CLI guest."""

import argparse
import base64
import json
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, etcdctl, ssh
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def verify_role_audit(state, result):
    tenant = uuid.UUID(result["tenantId"])
    subscription = uuid.UUID(result["subscriptionId"])
    prefix = f"/ocean/v1/regions/farm-1/tenants/{tenant}/arm/{subscription}/audit/"
    response = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix} --prefix --write-out=json")))
    observed = {}
    for item in response["kvs"]:
        event = json.loads(base64.b64decode(item["value"]))
        key = (event["actor"], event["action"], event["target"].casefold(), event["outcome"])
        if not event["time"] or int(item["mod_revision"]) < 1:
            raise RuntimeError("an authorization audit record has no timestamp or revision")
        observed.setdefault(key, []).append(int(item["mod_revision"]))
    administrator, reader = result["administratorId"], result["principalId"]
    assignment, group = (result[key].casefold() for key in ("assignmentId", "groupId"))
    expected = [(administrator, "Microsoft.Authorization/roleAssignments/write", assignment, "Succeeded", 2),
                (administrator, "Microsoft.Authorization/roleAssignments/delete", assignment, "Succeeded", 1),
                (reader, "Microsoft.Authorization/roleAssignments/delete", assignment, "Denied", 1),
                (reader, "Microsoft.Resources/subscriptions/resourceGroups/delete", group, "Denied", 1)]
    if any(len(observed.get((actor, action, target, outcome), [])) != count for actor, action, target, outcome, count in expected):
        raise RuntimeError("durable audit records did not match role changes and denied privileged actions")
    result["auditRevisions"] = sorted(revision for revisions in observed.values() for revision in revisions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--rbac", action="store_true")
    args = parser.parse_args()
    state = args.state.resolve()
    scripts = ["arm_cli.py", "testdata/arm-contract.tsv"]
    if args.rbac:
        scripts.append("arm_rbac_cli.py")
    prepare_operator_client(state, scripts)
    script = "arm_rbac_cli.py" if args.rbac else "arm_cli.py"
    result = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/{script} --settings {CLIENT}/operator.secret "
                                            f"--matrix {CLIENT}/arm-contract.tsv"))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    if args.rbac:
        verify_role_audit(state, result)
        (directory / "arm-rbac.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"Azure CLI {result['azureCLI']} verified scoped role assignment, retained token revocation, isolation, and durable audit records.")
        return
    (directory / "arm-resource-groups.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Azure CLI {result['azureCLI']} verified provider discovery, resource group lifecycle, {result['pages']} inventory pages, "
          f"{result['concurrentRequests']} concurrent requests, isolation, and cleanup.")


if __name__ == "__main__":
    main()
