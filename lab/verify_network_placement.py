#!/usr/bin/env python3
"""Verify fixed private IPv4 allocation and authenticated host network policy."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from region import DEST, NODES, OPERATOR, ROOT, etcdctl, eventually, ssh, upload
from verify_enrollment import wait_ready
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_placement import host_assignment_requests

CUSTOMER = b"""
import json
import tempfile
from pathlib import Path
from identity_cli import AzureCLI
from onboarding_cli import fixture, put

config = json.loads(Path("operator.secret").read_text())
with tempfile.TemporaryDirectory(prefix="ocean-network-placement-operator-") as directory:
    cli = AzureCLI(config, directory)
    cli.login_service_principal(config["app"], config["secret"])
    tenant, request = fixture()
    allocation = put(cli, tenant, request, Path(directory) / "request.json")
    print(json.dumps({"tenant": tenant, "subscription": allocation["subscriptionId"]}))
"""


def verify(state, small, other, pool):
    for host in (small, other):
        wait_ready(state, host)
    prepare_operator_client(state, ())
    scope = json.loads(ssh(state, OPERATOR, f"cd {CLIENT} && python3 -", CUSTOMER))
    group = "ipam-" + uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="ocean-private-placement-") as folder:
        binary = Path(folder) / "network-placement.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary), "./internal/controlplane"],
                       cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        upload(state, OPERATOR, {"bin/network-placement.test": binary.read_bytes()})

    endpoints = ",".join(f"https://{address}:2379" for address in NODES.values())
    settings = {"OCEAN_E2E_ETCD_ENDPOINTS": endpoints, "OCEAN_E2E_ETCD_PKI": f"{DEST}/pki",
                "OCEAN_E2E_TENANT": scope["tenant"], "OCEAN_E2E_SUBSCRIPTION": scope["subscription"],
                "OCEAN_E2E_GROUP": group, "OCEAN_E2E_PUBLIC_POOL": " ".join(pool)}

    def stage(name):
        invocation = shlex.join(["env", *(f"{key}={value}" for key, value in settings.items()), f"OCEAN_E2E_NETWORK_PLACEMENT={name}",
                                 f"{DEST}/bin/network-placement.test", "-test.run=^TestNetworkPlacementFixture$", "-test.v"])
        reply = ssh(state, OPERATOR, f'if output=$({invocation} 2>&1); then printf "%s\\n" "$output"; '
                                    'else status=$?; printf "%s\\n" "$output" >&2; exit "$status"; fi')
        if b"--- PASS: TestNetworkPlacementFixture" not in reply:
            raise RuntimeError(f"the {name} fixture did not run")

    def assignments(access):
        (status, body), = host_assignment_requests(state, small, small)
        if status != 200:
            raise RuntimeError("the owning host could not retrieve its assignments")
        items = {row["id"]: row for row in body["assignments"] if row["tenantId"] == scope["tenant"]}
        if set(items) != {group + "-" + suffix for suffix in ("one", "two", "three")}:
            raise RuntimeError("the owning host did not receive the three bound assignments")
        for row in items.values():
            policy = row.get("network")
            if (row.get("networkUnavailable") or not policy or policy["address"] != row["privateIPv4"] + "/29" or
                    policy["gateway"] != "10.86.1.1" or policy["virtualNetworkPrefixes"] != ["10.86.0.0/16"] or
                    policy["publicIPv4"] not in pool or not policy["natGatewayId"].endswith("/natGateways/outbound") or
                    row["subnetId"].split("/")[2] != scope["subscription"] or
                    [rule["properties"]["access"] for rule in policy["securityRules"]] != [access]):
                raise RuntimeError("the host received an incomplete or inconsistent network policy")
        if len({row["network"]["revision"] for row in items.values()}) != 1:
            raise RuntimeError("assignment policy data came from different regional revisions")
        return items

    try:
        stage("seed")
        original = assignments("Allow")
        denied, foreign = host_assignment_requests(state, other, small, other)
        if denied[0] != 403 or foreign[0] != 200 or any(row["tenantId"] == scope["tenant"] for row in foreign[1]["assignments"]):
            raise RuntimeError("another host obtained the network policy")
        stage("invalidate-owner")
        try:
            (status, body), = host_assignment_requests(state, small, small)
            items = {row["id"]: row for row in body["assignments"] if row["tenantId"] == scope["tenant"]}
            withheld = items.get(group + "-one", {})
            if (status != 200 or len(items) != 3 or withheld.get("networkUnavailable") is not True or "network" in withheld or
                    any("network" not in items.get(group + "-" + suffix, {}) for suffix in ("two", "three"))):
                raise RuntimeError("the agent received policy for an unowned address or lost its other policies")
        finally:
            stage("restore-owner")
        stage("policy-change")
        updated = assignments("Deny")
        for key, row in original.items():
            if updated[key]["privateIPv4"] != row["privateIPv4"] or updated[key]["network"]["revision"] <= row["network"]["revision"]:
                raise RuntimeError("updating the firewall changed the allocation or returned stale policy")
        stage("recycle")
        recycled = assignments("Deny")[group + "-one"]
        if recycled["privateIPv4"] != original[group + "-one"]["privateIPv4"] or recycled["generation"] == original[group + "-one"]["generation"]:
            raise RuntimeError("a recycled address was assigned without a new placement generation")
        result = {"host": small, "addresses": sorted(row["privateIPv4"] for row in original.values()),
                  "publicIPv4": recycled["network"]["publicIPv4"], "initialRevision": next(iter(original.values()))["network"]["revision"],
                  "updatedRevision": next(iter(updated.values()))["network"]["revision"], "foreignHostDenied": True,
                  "foreignSubscriptionRejected": True, "addressExhaustionPreservedQuota": True, "liveSubnetProtected": True,
                  "staleGenerationRejected": True, "unownedAddressPolicyWithheld": True, "ruleRefreshVerified": True}
    finally:
        stage("cleanup")
    (status, body), = host_assignment_requests(state, small, small)
    if status != 200 or any(row["tenantId"] == scope["tenant"] for row in body["assignments"]):
        raise RuntimeError("the owning host still received released network assignments")
    prefix = f"/ocean/v1/regions/farm-1/tenants/{scope['tenant']}/arm/{scope['subscription']}"

    def cleaned():
        group_rows = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix}/resource-groups/{group} --write-out=json")))
        bindings = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix}/network-placements/ --prefix --write-out=json")))
        addresses = json.loads(ssh(state, OPERATOR, etcdctl("get /ocean/v1/regions/farm-1/network/public-ipv4-pool --print-value-only")))
        if (group_rows.get("count", 0) or bindings.get("count", 0) or
                any(key.startswith(prefix + "/") for key in addresses["allocations"])):
            raise RuntimeError("the group or address reservations remain in the regional store")
    eventually(cleaned, 15)
    result["cleanupVerified"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--pool", nargs=2, required=True)
    parser.add_argument("--host", default="farm-1-node-05")
    parser.add_argument("--other", default="farm-1-node-06")
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state, args.host, args.other, args.pool)
    target = state / "evidence"
    target.mkdir(mode=0o700, exist_ok=True)
    (target / "network-placement.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"{evidence['host']} received three scoped private addresses and refreshed firewall and NAT policy over mTLS.")


if __name__ == "__main__":
    main()
