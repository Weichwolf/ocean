#!/usr/bin/env python3
"""Provision, reach, and remove the HTTPS gateway using Azure CLI and enrolled hosts."""

import argparse
import json
import shlex
import sys
import time
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from prepare_application_gateway import GATEWAYS, NAMESPACE, SLOT
from region import OPERATOR, eventually, ssh
from verify_egress_hosts import require, worker_command
from verify_https_hosts import BACKEND, DEST, HOST, POD, PROBE, cleanup_probe, configure_probe, configure_worker, outside
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client

WORKER = "farm-1-node-05"
CUSTOMER = "farm-1-customer"
SERVICE = "ocean-https-agent.service"
DEADLINE = 8


def gateway_owns_address(state, node, address):
    response = ssh(state, node, f"sudo ip -n {NAMESPACE} -4 -j address show dev public0")
    return any(item["local"] == address for link in json.loads(response) for item in link["addr_info"])


def assert_closed(state, address):
    reply = ssh(state, CUSTOMER, f"""status=0
sudo ip netns exec {PROBE} curl --noproxy '*' --silent --max-time 1 --cacert {DEST}/ca.pem \
  --resolve {HOST}:443:{address} -o /dev/null https://{HOST}/ || status=$?
printf '%s' "$status"
""")
    require(reply in {b"7", b"28"}, "the deleted gateway remained reachable through the cached public address")


def verify(state):
    for node in GATEWAYS:
        ssh(state, node, f"sudo systemctl is-active --quiet {SERVICE}")
    ssh(state, CUSTOMER, f"sudo test ! -e /run/netns/{PROBE} && sudo test ! -e /etc/netns/{PROBE}")
    worker_command(state, f"if pod container exists {POD}; then exit 1; fi", WORKER)
    prepare_operator_client(state, ("arm_cli.py", "application_gateway_cli.py", "testdata/arm-contract.tsv"))
    fixture = f"/tmp/ocean-application-gateway-{uuid4().hex}.secret"

    def invoke(phase):
        command = shlex.join(["python3", f"{CLIENT}/application_gateway_cli.py", "--settings", f"{CLIENT}/operator.secret",
                              "--matrix", f"{CLIENT}/arm-contract.tsv", "--phase", phase, "--fixture", fixture])
        return json.loads(ssh(state, OPERATOR, command))

    probe = False
    disposed = False
    stopped = None
    try:
        image = configure_worker(state, WORKER)
        created = invoke("create")
        address = created["publicIPv4"]
        probe = True
        configure_probe(state, created.pop("certificate").encode(), CUSTOMER, "customer0", address)

        def public():
            result = outside(state, "--cacert", f"{DEST}/ca.pem", "-w", ":%{remote_ip}", f"https://{HOST}/", observer=CUSTOMER)
            require(result == f"ocean-https-nginx:{address}", "the CLI gateway did not expose its intended HTTPS workload")

        eventually(public, 15)
        status = ssh(state, CUSTOMER, f"sudo ip netns exec {PROBE} curl --noproxy '*' --silent --max-time 2 "
                     f"--cacert {DEST}/ca.pem -H 'Host: other.ocean.test' -o /dev/null -w '%{{http_code}}' https://{HOST}/")
        require(status == b"421", "an unauthorized HTTP route reached the workload")
        direct = ssh(state, CUSTOMER, f"sudo ip netns exec {PROBE} curl --noproxy '*' --max-time 1 "
                     f"-s -o /dev/null http://{BACKEND}/ >/dev/null; printf '%s' \"$?\"")
        require(direct in {b"7", b"28"}, "the external client could access the private workload directly")

        owners = [node for node in GATEWAYS if gateway_owns_address(state, node, address)]
        require(len(owners) == 1, "the public address did not have exactly one owner")
        stopped = owners[0]
        survivor = next(node for node in GATEWAYS if node != stopped)
        started = time.monotonic()
        ssh(state, stopped, f"sudo systemctl stop {SERVICE}")

        def recovered():
            require(gateway_owns_address(state, survivor, address), "the surviving gateway has not acquired the public address")
            public()

        eventually(recovered, DEADLINE)
        recovery_ms = round((time.monotonic() - started) * 1000)
        require(recovery_ms <= DEADLINE * 1000, "the CLI-provisioned gateway exceeded the failover deadline")
        ssh(state, stopped, f"sudo systemctl start {SERVICE}")
        stopped = None
        deletion = invoke("delete")
        disposed = deletion["deleted"]
        require(disposed and deletion["repeatedDeleteSucceeded"], "the Azure CLI failed to complete gateway teardown")
        eventually(lambda: assert_closed(state, address), 12)
        for node in GATEWAYS:
            ssh(state, node, f"sudo test ! -e /run/ocean-https-agent/{SLOT}/ingress.pem")
        return {**created, **deletion, "trustedHTTPS": True, "unknownHostRejected": True,
                "directBackendBlocked": True, "cachedAddressWithdrawn": True, "rootless": True, "nice": 10, "image": image,
                "agentFailoverRecoveryMs": recovery_ms, "deadlineMs": DEADLINE * 1000}
    finally:
        try:
            if stopped:
                ssh(state, stopped, f"sudo systemctl start {SERVICE}")
            if not disposed:
                invoke("delete")
        finally:
            if probe:
                cleanup_probe(state, CUSTOMER)
            worker_command(state, f"pod rm -f --ignore --time=0 {POD} >/dev/null", WORKER)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state)
    folder = state / "evidence"
    folder.mkdir(mode=0o700, exist_ok=True)
    (folder / "application-gateway-lifecycle.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} provisioned and removed a working HTTPS gateway through both enrolled hosts.")


if __name__ == "__main__":
    main()
