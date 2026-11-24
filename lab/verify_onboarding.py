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


def prepare_operator_client(state, scripts):
    config = {
        "ca": f"{REGION}/pki/ingress-ca.pem", "arm": f"https://{ARM}", "graph": f"https://{GRAPH}",
        "provider": f"https://{OAUTH}", "authority": f"https://{IDENTITY}", "tenant": OPERATOR_TENANT,
        "app": OPERATOR_APP, "secret": (state / "identity-pki/operator.secret").read_text(),
    }
    files = {"operator.secret": json.dumps(config).encode()}
    files.update({Path(name).name: (ROOT / "tests/e2e" / name).read_bytes()
                  for name in ("identity_cli.py", "onboarding_cli.py", *scripts)})
    upload(state, OPERATOR, files, CLIENT)


def verify(state, directory_users=False, directory_apps=False):
    prepare_operator_client(state, ())
    options = " --directory-users" if directory_users else ""
    if directory_apps:
        options += " --directory-apps"
    result = json.loads(ssh(state, OPERATOR, f"python3 {CLIENT}/onboarding_cli.py --settings {CLIENT}/operator.secret{options}"))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    name = "graph-applications.json" if directory_apps else "graph-users.json" if directory_users else "tenant-onboarding.json"
    (directory / name).write_text(json.dumps(result, indent=2) + "\n")
    print("Azure CLI verified two tenant allocations, a recovered response, and tenant authorization.", flush=True)
    if directory_users:
        print("Azure CLI verified tenant user creation, list, read, update, and deletion.", flush=True)
    if directory_apps:
        print("Azure CLI verified tenant applications, service principals, credential append, and revocation.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--directory-users", action="store_true")
    parser.add_argument("--directory-apps", action="store_true")
    args = parser.parse_args()
    verify(args.state.resolve(), args.directory_users, args.directory_apps)


if __name__ == "__main__":
    main()
