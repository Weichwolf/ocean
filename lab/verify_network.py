#!/usr/bin/env python3
"""Run the selected virtual network commands from the isolated CLI guest."""

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


def verify_firewall(state, node, policy):
    import yaml

    image_lock = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())
    busybox = image_lock["images"]["busybox"]
    image = f"{busybox['repository']}@{busybox['digest']}"
    with tempfile.TemporaryDirectory(prefix="ocean-workload-firewall-") as directory:
        binary = Path(directory) / "firewall.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary),
                        "./internal/network"], cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        path = "/opt/ocean-firewall-check"
        upload(state, node, {"bin/firewall.test": binary.read_bytes(),
                             "security-group.json": json.dumps(policy).encode()}, path)
    command = ["sudo", "env", f"OCEAN_E2E_GATEWAY_POLICY={path}/security-group.json",
               f"OCEAN_E2E_BUSYBOX_IMAGE={image}", f"{path}/bin/firewall.test",
               "-test.run=^TestRoutedPodmanFirewall$", "-test.v"]
    invocation = shlex.join(command)
    result = ssh(state, node, f'cd /tmp && if result=$({invocation} 2>&1); then printf "%s\\n" "$result"; '
                              'else status=$?; printf "%s\\n" "$result" >&2; exit "$status"; fi').decode()
    if "--- PASS: TestRoutedPodmanFirewall" not in result:
        raise RuntimeError("the guest did not run the firewall packet checks")
    return image, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--firewall-node", help="disposable Debian guest with the agent package, nftables, curl, and Python 3")
    args = parser.parse_args()
    state = args.state.resolve()
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "network_cli.py", "testdata/arm-contract.tsv"))
    evidence = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/network_cli.py --settings {CLIENT}/operator.secret "
                                               f"--matrix {CLIENT}/arm-contract.tsv", timeout=600))
    output = state / "evidence"
    output.mkdir(mode=0o700, exist_ok=True)
    (output / "virtual-network-arm.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} verified VNet, subnet, and security group lifecycle, atomic overlap rejection, and tenant isolation.",
          flush=True)
    if args.firewall_node:
        image, result = verify_firewall(state, args.firewall_node, evidence["firewallPolicy"])
        (output / "routed-podman-firewall.log").write_text(f"Node: {args.firewall_node}\nImage: {image}\n{result}")
        print("Azure CLI rules filtered real ingress and egress on the rootless Podman workload.")


if __name__ == "__main__":
    main()
