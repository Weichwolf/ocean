#!/usr/bin/env python3
"""Verify the public IP and NAT control plane on the dedicated regional lab."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, ROOT, ssh, upload
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def verify_gateway(state, node, reserved_address):
    import yaml

    lock = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())
    busybox = lock["images"]["busybox"]
    image = f"{busybox['repository']}@{busybox['digest']}"
    path = "/opt/ocean-egress-check"
    with tempfile.TemporaryDirectory(prefix="ocean-fixed-egress-") as directory:
        binary = Path(directory) / "egress.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary),
                        "./internal/network"], cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        upload(state, node, {"bin/egress.test": binary.read_bytes()}, path)
    invocation = shlex.join(["sudo", "env", f"OCEAN_E2E_PUBLIC_ADDRESS={reserved_address}", f"OCEAN_E2E_BUSYBOX_IMAGE={image}",
                            f"{path}/bin/egress.test", "-test.run=^TestFixedEgressFailover$", "-test.v"])
    result = ssh(state, node, f'cd /tmp && if result=$({invocation} 2>&1); then printf "%s\\n" "$result"; '
                              'else status=$?; printf "%s\\n" "$result" >&2; exit "$status"; fi').decode()
    if "--- PASS: TestFixedEgressFailover" not in result:
        raise RuntimeError("the guest did not run the fixed egress packet checks")
    return f"Node: {node}\nImage: {image}\n{result}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--pool", nargs=2, required=True)
    parser.add_argument("--gateway-node", help="disposable Debian guest with the agent, nftables, and keepalived")
    args = parser.parse_args()
    state = args.state.resolve()
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "egress_cli.py", "testdata/arm-contract.tsv"))
    command = ["python3", f"{CLIENT}/egress_cli.py", "--settings", f"{CLIENT}/operator.secret",
               "--matrix", f"{CLIENT}/arm-contract.tsv", "--pool", *args.pool]
    evidence = json.loads(ssh(state, OPERATOR, shlex.join(command)))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "public-ip-nat-arm.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} verified static IPv4 reservations, exclusive NAT claims, subnet attachment, and cleanup.",
          flush=True)
    if args.gateway_node:
        result = verify_gateway(state, args.gateway_node, evidence["allocatedAddresses"][0])
        (directory / "fixed-egress-packet.log").write_text(result)
        print("The outside observer saw the reserved address before and after the active gateway uplink was disabled.")


if __name__ == "__main__":
    main()
