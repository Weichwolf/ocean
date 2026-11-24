#!/usr/bin/env python3
"""Run the ARM compatibility matrix in the isolated local CLI guest."""

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
    prepare_operator_client(state, ("arm_cli.py", "testdata/arm-contract.tsv"))
    result = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/arm_cli.py --settings {CLIENT}/operator.secret "
                                            f"--matrix {CLIENT}/arm-contract.tsv"))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "arm-resource-groups.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Azure CLI {result['azureCLI']} verified resource group lifecycle, {result['pages']} inventory pages, "
          f"{result['concurrentRequests']} concurrent requests, isolation, and cleanup.")


if __name__ == "__main__":
    main()
