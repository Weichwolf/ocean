#!/usr/bin/env python3
"""Verify placement against leased capacity in a disposable regional lab."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
from keycloak import TENANT
from region import ARM, DEST, NODES, OPERATOR, ROOT, etcdctl, eventually, ssh, upload
from verify_enrollment import agent_command, region_record, wait_ready
from verify_identity import SUBSCRIPTION


def record_capacity(state, node):
    registered, host = region_record(state, f"registered/{node}")
    live, advertised = region_record(state, f"live/{node}")
    snapshot, report = json.loads(advertised), json.loads(host)["report"]
    if not int(live.get("lease", 0)) or snapshot["capacity"] != {"cpuMillis": report["cpu"] * 1000 - 100,
                                                               "memoryMiB": report["memoryMiB"] - 128}:
        raise RuntimeError("the host lease does not contain its reserved-adjusted capacity")
    return snapshot, int(live["lease"]), registered["mod_revision"]


def host_assignment_requests(state, certificate_host, *targets):
    script = r'''
set -eu
files=$(mktemp -d)
trap 'rm -rf -- "$files"' EXIT
identity=/var/lib/ocean-agent/host-enrollment
openssl x509 -inform DER -in "$identity/identity.crt" -out "$files/cert.pem"
openssl pkey -inform DER -in "$identity/identity.key" -out "$files/key.pem"
for url do
    curl -sS --max-time 5 --cacert /etc/ocean-agent/management-ca.pem --cert "$files/cert.pem" \
        --key "$files/key.pem" -w '\n%{http_code}\n' "$url"
done
'''
    urls = [f"https://{ARM}/ocean/hosts/{node}/placements" for node in targets]
    result = agent_command(state, certificate_host, "sh", "-c", script, "assignment-check", *urls).decode().splitlines()
    values = [line for line in result if line]
    if len(values) != 2 * len(targets):
        raise RuntimeError("unexpected response from the host assignment endpoint")
    return [(int(values[index + 1]), json.loads(values[index])) for index in range(0, len(values), 2)]


def verify_host_endpoint(state, small, large):
    own, foreign = host_assignment_requests(state, small, small, large)
    if own != (200, {"assignments": []}) or foreign[0] != 403:
        raise RuntimeError("the host assignment endpoint did not enforce certificate scope")


def verify(state, small, large):
    with tempfile.TemporaryDirectory(prefix="ocean-placement-check-") as directory:
        binary = Path(directory) / "placement.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary), "./internal/controlplane"],
                       cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        upload(state, OPERATOR, {"bin/placement.test": binary.read_bytes()})

    def test(stage):
        endpoints = ",".join(f"https://{address}:2379" for address in NODES.values())
        command = ["env", f"OCEAN_E2E_ETCD_ENDPOINTS={endpoints}", f"OCEAN_E2E_ETCD_PKI={DEST}/pki",
                   f"OCEAN_E2E_PLACEMENT={stage}", f"OCEAN_E2E_TENANT={TENANT}", f"OCEAN_E2E_SUBSCRIPTION={SUBSCRIPTION}",
                   f"OCEAN_E2E_SMALL_HOST={small}", f"OCEAN_E2E_LARGE_HOST={large}", f"{DEST}/bin/placement.test", "-test.run=^TestRegionalPlacement$", "-test.v"]
        result = ssh(state, OPERATOR, shlex.join(command))
        if b"--- PASS: TestRegionalPlacement" not in result:
            raise RuntimeError("the placement checks did not run")

    for node in (small, large):
        wait_ready(state, node)
    small_capacity, _, _ = record_capacity(state, small)
    large_capacity, old_lease, revision = record_capacity(state, large)
    no_certificate = ssh(state, OPERATOR, f"curl -sS --max-time 5 --cacert {DEST}/pki/ingress-ca.pem "
                         f"-o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json' -d '{{}}' "
                         f"https://{ARM}/ocean/hosts/{shlex.quote(small)}/heartbeat")
    if no_certificate != b"401":
        raise RuntimeError("a caller without a host certificate was able to submit capacity")
    verify_host_endpoint(state, small, large)
    test("active")
    print("The regional store enforced mixed host capacity, concurrent quota, idempotent retries, and drain.", flush=True)

    started = time.monotonic()
    try:
        agent_command(state, large, "systemctl", "--user", "stop", "ocean-agent.service")

        def expired():
            record = json.loads(ssh(state, OPERATOR, etcdctl(f"get /ocean/v1/regions/farm-1/hosts/live/{shlex.quote(large)} --write-out=json")))
            if record.get("count", 0):
                raise RuntimeError("the stopped host lease is still active")

        eventually(expired, 25)
        expired_in = round(time.monotonic() - started, 2)
        test("disconnected")
    finally:
        agent_command(state, large, "systemctl", "--user", "start", "ocean-agent.service")
        wait_ready(state, large)
    restored, new_lease, current = record_capacity(state, large)
    if (new_lease == old_lease or current != revision or restored != large_capacity):
        raise RuntimeError("the reconnected host changed its registered identity or capacity")
    evidence = {"activeHosts": [small_capacity, large_capacity], "leaseExpiredAfterSeconds": expired_in,
                "disconnectedHostExcluded": True, "sameIdentityAfterReconnect": True, "anonymousHeartbeatDenied": True,
                "crossPoolDenied": True, "oversizedRequestDenied": True, "sameRequestSingleReservation": True,
                "concurrentQuotaEnforced": True, "tenantQuotaReusable": True, "drainingHostExcluded": True,
                "drainPreservedExistingReservation": True, "oldGenerationReleaseDenied": True,
                "assignmentProjectionVerified": True, "crossHostAssignmentsDenied": True}
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "host-placement.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"The disconnected host lost capacity after {expired_in:.2f} seconds and rejoined with the same identity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--small", required=True)
    parser.add_argument("--large", required=True)
    args = parser.parse_args()
    verify(args.state.resolve(), args.small, args.large)


if __name__ == "__main__":
    main()
