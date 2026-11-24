#!/usr/bin/env python3
"""Run the Application Gateway CLI validation checks in the operator guest."""

import argparse
import json
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, ssh
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    prepare_operator_client(state, ("arm_cli.py", "application_gateway_cli.py", "testdata/arm-contract.tsv"))
    command = shlex.join(["python3", f"{CLIENT}/application_gateway_cli.py", "--settings", f"{CLIENT}/operator.secret",
                          "--matrix", f"{CLIENT}/arm-contract.tsv"])
    evidence = json.loads(ssh(state, OPERATOR, command))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "application-gateway-validation.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} validated the HTTPS Application Gateway without changing the inventory.")


if __name__ == "__main__":
    main()
