#!/usr/bin/env python3
"""Verify the regional ARM health, activity, and reservation reporting paths."""

import argparse
import json
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import OPERATOR, ssh
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client

IMAGE = "docker.io/library/nginx@sha256:836c5af5a07dbff704e8ba7971d20dd55bc96d5748a03129f02bd4ce25836e0d"


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "monitor_cli.py", "testdata/arm-contract.tsv"))
    command = shlex.join(["python3", f"{CLIENT}/monitor_cli.py", "--settings", f"{CLIENT}/operator.secret",
                          "--matrix", f"{CLIENT}/arm-contract.tsv", "--image", IMAGE])
    result = json.loads(ssh(state, OPERATOR, command))
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "monitor-controlplane.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Azure CLI verified tenant Resource Health, activity events, and committed reservation limits.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    verify(args.state.resolve())


if __name__ == "__main__":
    main()
