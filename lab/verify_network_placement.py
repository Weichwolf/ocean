#!/usr/bin/env python3
"""Verify fixed private IPv4 allocation and authenticated host network policy."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path
from uuid import uuid4

import yaml

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


ROUTER = "ocean-packet"
CLIENT_NAMESPACE = "ocean-probe"
REGISTRY = "/etc/ocean-agent/network.json"
SERVICE = "ocean-network-agent.service"
WORKLOAD = "ocean-network-fixture"
PODMAN = """
cd /tmp
uid=$(id -u ocean-agent)
pod() { sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" nice -n 10 podman "$@"; }
"""


@contextmanager
def packet_probe(state, host, assignment):
    resource = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())["images"]["busybox"]
    image = shlex.quote(f"{resource['repository']}@{resource['digest']}")
    address = assignment["privateIPv4"]
    gateway = assignment["network"]["gateway"]
    endpoint = {key: assignment[key] for key in ("tenantId", "subscriptionId", "id", "generation")}
    endpoint.update({"namespace": ROUTER, "interface": "work0"})
    registry = {"protectedPrefixes": ["10.231.1.0/24"], "endpoints": [endpoint]}
    ssh(state, host, f"""set -eu
{PODMAN}
sudo test ! -e {REGISTRY}
sudo test ! -e /run/netns/{ROUTER}
sudo test ! -e /run/netns/{CLIENT_NAMESPACE}
if pod container exists {WORKLOAD}; then exit 1; fi
""")

    def probe(allowed):
        def check():
            reply = ssh(state, host, f"""
status=0
body=$(sudo ip netns exec {CLIENT_NAMESPACE} curl --noproxy '*' --silent --fail --max-time 1 http://{address}:8080/) || status=$?
printf '%s:%s' "$status" "$body"
""")
            expected = b"0:ocean-firewall" if allowed else b"28:"
            if reply != expected:
                raise RuntimeError(f"expected {'allowed' if allowed else 'blocked'} HTTP, got {reply!r}")
        eventually(check, 12)

    try:
        observed = ssh(state, host, f"""set -eu
{PODMAN}
pod run --pull=missing --detach --name {WORKLOAD} --network none --memory 32m {image} \
    sh -ec 'mkdir /www; printf ocean-firewall >/www/index.html; exec httpd -f -p 8080 -h /www' >/dev/null
pid=$(pod inspect --format '{{{{.State.Pid}}}}' {WORKLOAD})
sudo ip netns add {ROUTER}
sudo ip netns add {CLIENT_NAMESPACE}
sudo ip -n {ROUTER} link add work0 type veth peer name eth0 netns "$pid"
sudo ip -n {ROUTER} link add vpn0 type veth peer name peer0 netns {CLIENT_NAMESPACE}
sudo ip -n {ROUTER} addr add {gateway}/29 dev work0
sudo ip -n {ROUTER} addr add 10.87.1.1/24 dev vpn0
sudo ip -n {ROUTER} link set work0 up
sudo ip -n {ROUTER} link set vpn0 up
sudo nsenter -t "$pid" -n ip addr add {address}/29 dev eth0
sudo nsenter -t "$pid" -n ip link set eth0 up
sudo nsenter -t "$pid" -n ip route add default via {gateway}
sudo ip -n {CLIENT_NAMESPACE} addr add 10.87.1.4/24 dev peer0
sudo ip -n {CLIENT_NAMESPACE} link set peer0 up
sudo ip -n {CLIENT_NAMESPACE} route add 10.86.1.0/29 via 10.87.1.1
pod info --format '{{{{.Host.Security.Rootless}}}}'
ps -o ni= -p "$pid" | tr -d ' '
""").splitlines()
        if observed != [b"true", b"10"]:
            raise RuntimeError("the packet fixture did not run in rootless Podman at nice 10")
        ssh(state, host, f"""set -eu
sudo sh -c 'umask 077; content=$(mktemp /etc/ocean-agent/.packet.XXXXXXXX); cat > "$content"; mv "$content" {REGISTRY}'
sudo systemctl start {SERVICE}
""", json.dumps(registry).encode())
        eventually(lambda: ssh(state, host, f"sudo ip netns exec {ROUTER} nft list table inet ocean_776f726b30"))
        ssh(state, host, f"sudo ip netns exec {ROUTER} sysctl -q -w net.ipv4.ip_forward=1")
        probe(True)
        yield probe
    finally:
        ssh(state, host, f"""set -eu
{PODMAN}
sudo systemctl kill --kill-whom=main --signal=SIGCONT {SERVICE} 2>/dev/null || true
sudo systemctl stop {SERVICE}
sudo rm -f {REGISTRY}
pod rm -f --ignore --time=0 {WORKLOAD} >/dev/null
if sudo test -e /run/netns/{CLIENT_NAMESPACE}; then sudo ip netns delete {CLIENT_NAMESPACE}; fi
if sudo test -e /run/netns/{ROUTER}; then sudo ip netns delete {ROUTER}; fi
""")


def verify(state, small, other, pool, packets):
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
        evidence = {}
        with (packet_probe(state, small, original[group + "-one"]) if packets else nullcontext()) as probe:
            stage("invalidate-owner")
            try:
                (status, body), = host_assignment_requests(state, small, small)
                items = {row["id"]: row for row in body["assignments"] if row["tenantId"] == scope["tenant"]}
                withheld = items.get(group + "-one", {})
                if (status != 200 or len(items) != 3 or withheld.get("networkUnavailable") is not True or "network" in withheld or
                        any("network" not in items.get(group + "-" + suffix, {}) for suffix in ("two", "three"))):
                    raise RuntimeError("the agent received policy for an unowned address or lost its other policies")
                if probe:
                    probe(False)
            finally:
                stage("restore-owner")
            if probe:
                probe(True)
            stage("policy-change")
            updated = assignments("Deny")
            for key, row in original.items():
                if updated[key]["privateIPv4"] != row["privateIPv4"] or updated[key]["network"]["revision"] <= row["network"]["revision"]:
                    raise RuntimeError("updating the firewall changed the allocation or returned stale policy")
            if probe:
                probe(False)
                stage("policy-allow")
                probe(True)
                ssh(state, small, f"sudo systemctl kill --kill-whom=main --signal=SIGSTOP {SERVICE}")
                started = time.monotonic()
                try:
                    probe(False)
                    evidence["kernelExpiryObservedAfterSeconds"] = round(time.monotonic() - started, 2)
                finally:
                    ssh(state, small, f"sudo systemctl kill --kill-whom=main --signal=SIGCONT {SERVICE}")
                probe(True)
            stage("recycle")
            recycled = assignments("Allow" if probe else "Deny")[group + "-one"]
            if probe:
                probe(False)
                evidence.update({"rootless": True, "nice": 10, "revokedOwnershipBlockedTraffic": True,
                                 "nsgChangeBlockedTraffic": True, "staleEndpointBlockedTraffic": True,
                                 "trafficRestoredAfterRenewal": True})
        if recycled["privateIPv4"] != original[group + "-one"]["privateIPv4"] or recycled["generation"] == original[group + "-one"]["generation"]:
            raise RuntimeError("a recycled address was assigned without a new placement generation")
        result = {"host": small, "addresses": sorted(row["privateIPv4"] for row in original.values()),
                  "publicIPv4": recycled["network"]["publicIPv4"], "initialRevision": next(iter(original.values()))["network"]["revision"],
                  "updatedRevision": next(iter(updated.values()))["network"]["revision"], "foreignHostDenied": True,
                  "foreignSubscriptionRejected": True, "addressExhaustionPreservedQuota": True, "liveSubnetProtected": True,
                  "staleGenerationRejected": True, "unownedAddressPolicyWithheld": True, "ruleRefreshVerified": True,
                  **evidence}
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
    parser.add_argument("--packets", action="store_true")
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state, args.host, args.other, args.pool, args.packets)
    target = state / "evidence"
    target.mkdir(mode=0o700, exist_ok=True)
    (target / "network-placement.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"{evidence['host']} received three scoped private addresses and refreshed firewall and NAT policy over mTLS.")


if __name__ == "__main__":
    main()
