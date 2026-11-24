#!/usr/bin/env python3
"""Run the tenant onboarding contract in the isolated local CLI guest."""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from keycloak import OPERATOR_TENANT, OPERATOR_APP
from region import ARM, DEST as REGION, GRAPH, IDENTITY, OAUTH, OPERATOR, ROOT, ssh, upload
from verify_identity import CLIENT


def verify(state):
    config = {
        "ca": f"{REGION}/pki/ingress-ca.pem", "arm": f"https://{ARM}", "graph": f"https://{GRAPH}",
        "provider": f"https://{OAUTH}", "authority": f"https://{IDENTITY}", "tenant": OPERATOR_TENANT,
        "app": OPERATOR_APP, "secret": (state / "identity-pki/operator.secret").read_text(),
    }
    upload(state, OPERATOR, {
        "operator.secret": json.dumps(config).encode(),
        "identity_cli.py": (ROOT / "tests/e2e/identity_cli.py").read_bytes(),
        "onboarding_cli.py": (ROOT / "tests/e2e/onboarding_cli.py").read_bytes(),
    }, CLIENT)
    result = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/onboarding_cli.py --settings {CLIENT}/operator.secret"))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "tenant-onboarding.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Azure CLI verified two tenant allocations, a recovered response, and tenant authorization.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    verify(args.state.resolve())


if __name__ == "__main__":
    main()
