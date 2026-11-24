#!/usr/bin/env python3
"""Run the selected virtual network commands from the isolated CLI guest."""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, ssh
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    state = parser.parse_args().state.resolve()
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "network_cli.py", "testdata/arm-contract.tsv"))
    evidence = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/network_cli.py --settings {CLIENT}/operator.secret "
                                               f"--matrix {CLIENT}/arm-contract.tsv"))
    output = state / "evidence"
    output.mkdir(mode=0o700, exist_ok=True)
    (output / "virtual-network-arm.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Azure CLI {evidence['azureCLI']} verified VNet, subnet, and security group lifecycle, atomic overlap rejection, and tenant isolation.")


if __name__ == "__main__":
    main()
