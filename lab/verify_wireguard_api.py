#!/usr/bin/env python3
"""Provision redundant WireGuard with az rest and verify the actual routed traffic."""

import argparse
import json
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from enrollment import publish
from region import OPERATOR, ROOT, eventually, ssh, upload
from verify_agent_package import INSTALL
from verify_enrollment import wait_ready
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_wireguard_hosts import (
    CLIENT as CUSTOMER_PROBE, CLOUD, CUSTOMER, DEADLINE, GATEWAYS, KEYS, SITE, TENANT, VIP, attach_gateway_links, available, cleanup,
    configure_customer, configure_workload, customer_http, customer_router, gateway_address, gateway_mac, make_key,
    management_ready, owner, probe_workload, recover, require, selected,
)

SLOT = "wireguard-lab"
CONFIG = "/etc/ocean-agent/wireguard.json"
SERVICE = "ocean-wireguard-agent.service"


def package_gateways(state, package):
    payload = package.read_bytes()
    with ThreadPoolExecutor(max_workers=2) as executor:
        installs = [executor.submit(ssh, state, host, INSTALL, payload) for host in GATEWAYS]
        for item in installs:
            item.result()
    for node in GATEWAYS:
        wait_ready(state, node)


def gateway_slot(state, index):
    host = GATEWAYS[index]
    slot = {"namespace": CLOUD, "tunnel": "wg0", "underlay": "wan0", "inside": "lan0", "listenPort": 51820,
            "privateKeyFile": f"{KEYS}/{CLOUD}.key", "router": f"{VIP}/24", "vrrpId": 97,
            "priority": 150 if index == 0 else 100, "redundancy": {"address": gateway_address(index),
                                                                  "peer": gateway_address(1 - index),
                                                                  "peerMac": gateway_mac(1 - index)}}
    attach_gateway_links(state, index)
    upload(state, host, {"wireguard.json": json.dumps({"slots": {SLOT: slot}}).encode()}, "/etc/ocean-agent")
    ssh(state, host, f"sudo systemctl start {SERVICE}")


def verify(state, package):
    available(state)
    for host in GATEWAYS:
        ssh(state, host, f"sudo test ! -e {CONFIG} && sudo test ! -e {KEYS}/{CLOUD}.key")
    publish(state, wireguard={"slots": [{"name": SLOT, "hosts": list(GATEWAYS)}],
                              "protectedPrefixes": ["10.231.1.0/24"]})
    package_gateways(state, package)
    prepare_operator_client(state, ("arm_cli.py", "site_connection_cli.py", "testdata/arm-contract.tsv"))
    identifier = uuid4().hex
    fixture = f"/tmp/ocean-wireguard-api-{identifier}.secret"
    peer_file = f"gateway-site-peers-{identifier}.json"
    binary = (ROOT / "bin/ocean-gateway").read_bytes()

    def invoke(phase):
        arguments = ["python3", f"{CLIENT}/site_connection_cli.py", "--settings", f"{CLIENT}/operator.secret",
                     "--matrix", f"{CLIENT}/arm-contract.tsv", "--phase", phase, "--fixture", fixture]
        if phase == "create":
            arguments.extend(["--peers", f"{CLIENT}/{peer_file}"])
        return json.loads(ssh(state, OPERATOR, shlex.join(arguments)))

    disposed = False
    stopped = None
    try:
        cloud_public = [make_key(state, host, CLOUD) for host in GATEWAYS]
        site_public = [make_key(state, CUSTOMER, namespace) for namespace in SITE]
        configure_customer(state, cloud_public, binary)
        for index in range(len(GATEWAYS)):
            gateway_slot(state, index)
        peers = [{"publicKey": public, "endpoint": f"10.233.1.{201 + index}:51820",
                  "gatewayTunnel": f"10.85.99.{2 * index}/31", "customerTunnel": f"10.85.99.{2 * index + 1}"}
                 for index, public in enumerate(site_public)]
        upload(state, OPERATOR, {peer_file: json.dumps(peers).encode()}, CLIENT)
        image = configure_workload(state)
        result = invoke("create")
        try:
            eventually(lambda: probe_workload(state), 12)
        except RuntimeError as error:
            owners = [node for index, node in enumerate(GATEWAYS) if owner(state, index)]
            packet_rules = [ssh(state, node, f"sudo ip netns exec {CLOUD} nft list chain inet ocean_wireguard forwarded").decode()
                            for node in GATEWAYS]
            raise RuntimeError(f"public probes selected {selected(state)} and cloud owners were {owners}; "
                               f"forwarding policies: {packet_rules}") from error
        management_ready(state)
        for url in ("https://10.231.1.10/readyz", "http://10.85.51.4:8080/"):
            require(customer_http(state, url).split(b":", 1)[0] in {b"7", b"28"}, "a protected or unapproved network was reachable")
        owners = [index for index in range(len(GATEWAYS)) if owner(state, index)]
        require(len(owners) == 1, "the site connection has more than one active router")
        failed = owners[0]
        survivor = 1 - failed
        original_route = selected(state)
        require(len(original_route) == 1, "the customer has no active site route")

        def use_customer_route(gateway):
            ssh(state, CUSTOMER, f"sudo ip -n {CUSTOMER_PROBE} route replace {TENANT} via {gateway}")

        try:
            use_customer_route(customer_router(survivor))
            probe_workload(state)
        finally:
            use_customer_route(original_route[0])
        stopped = GATEWAYS[failed]
        started = time.monotonic()
        ssh(state, stopped, f"sudo systemctl stop --no-block {SERVICE}")
        recovery_ms = recover(state, survivor, started)
        require(not owner(state, failed), "the stopped gateway still owns the tenant router")
        management_ready(state)
        ssh(state, stopped, f"sudo systemctl start {SERVICE}")
        stopped = None
        deletion = invoke("delete")
        disposed = deletion["deleted"]
        require(disposed and deletion["repeatedDeleteSucceeded"], "the WireGuard API failed to complete teardown")
        blocked = customer_http(state, "http://10.85.50.4:8080/").split(b":", 1)[0]
        require(blocked in {b"7", b"28"}, "the site could reach the workload after deleting its connection")
        for host in GATEWAYS:
            ssh(state, host, f"if sudo ip -n {CLOUD} link show dev wg0 >/dev/null 2>&1; then exit 1; fi")
        return {**result, **deletion, "rootless": True, "nice": 10, "image": image,
                "gatewayLossRecoveryMs": recovery_ms, "deadlineMs": DEADLINE * 1000,
                "independentManagementReady": True, "protectedManagementBlocked": True,
                "unapprovedPrefixBlocked": True, "asymmetricRoutingVerified": True, "trafficWithdrawnOnDelete": True}
    finally:
        try:
            if stopped:
                ssh(state, stopped, f"sudo systemctl start {SERVICE}")
            if not disposed:
                invoke("delete")
        finally:
            for host in GATEWAYS:
                ssh(state, host, f"sudo systemctl stop {SERVICE}; "
                    f"if sudo test -e {CONFIG}; then sudo unlink {CONFIG}; fi")
            ssh(state, OPERATOR, f"if sudo test -e {CLIENT}/{peer_file}; then sudo unlink {CLIENT}/{peer_file}; fi")
            cleanup(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    report = verify(state, args.package.resolve())
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "wireguard-api.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Azure CLI {report['azureCLI']} provisioned two WireGuard paths and recovered traffic in {report['gatewayLossRecoveryMs']} ms.")


if __name__ == "__main__":
    main()
