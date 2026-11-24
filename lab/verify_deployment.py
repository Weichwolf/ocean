#!/usr/bin/env python3
"""Run the pinned Bicep and Azure CLI deployment checks in the operator guest."""

import argparse
import json
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, ROOT, ssh, upload
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--bicep", default="/home/ocean/.local/bin/bicep", help="pinned compiler path in the operator guest")
    args = parser.parse_args()
    state = args.state.resolve()
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "deployment_cli.py", "testdata/arm-contract.tsv"))
    fixture = ROOT / "tests/e2e/testdata/bicep/network.bicep"
    upload(state, OPERATOR, {"network.bicep": fixture.read_bytes()}, CLIENT)
    command = ["python3", f"{CLIENT}/deployment_cli.py", "--settings", f"{CLIENT}/operator.secret",
               "--matrix", f"{CLIENT}/arm-contract.tsv", "--template", f"{CLIENT}/network.bicep", "--bicep", args.bicep]
    evidence = json.loads(ssh(state, OPERATOR, shlex.join(command)))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "network-deployment-arm.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} and {evidence['bicep']} verified read-only preview, deployment, and drift reconciliation.")


if __name__ == "__main__":
    main()
