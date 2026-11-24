#!/usr/bin/env python3
"""Run the regional inventory compatibility check in the operator guest."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from region import DEST, NODES, OPERATOR, ROOT, ssh, upload
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "arm_inventory_cli.py", "testdata/arm-contract.tsv"))
    with tempfile.TemporaryDirectory(prefix="ocean-inventory-publisher-") as directory:
        publisher = Path(directory) / "inventory-fixture.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(publisher), "./internal/controlplane"],
                       cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        upload(state, OPERATOR, {"bin/inventory-fixture.test": publisher.read_bytes()}, CLIENT)
    endpoints = ",".join(f"https://{address}:2379" for address in NODES.values())
    command = ["env", f"OCEAN_E2E_ETCD_ENDPOINTS={endpoints}", f"OCEAN_E2E_ETCD_PKI={DEST}/pki", "python3",
               f"{CLIENT}/arm_inventory_cli.py", "--settings", f"{CLIENT}/operator.secret",
               "--matrix", f"{CLIENT}/arm-contract.tsv", "--publisher", f"{CLIENT}/bin/inventory-fixture.test"]
    result = json.loads(ssh(state, OPERATOR, shlex.join(command)))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "arm-inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Azure CLI {result['azureCLI']} verified {result['ownerResources']} resources across {result['pages']} pages, "
          f"{result['readerResources']} scoped resources, revocation, and group cleanup.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    verify(parser.parse_args().state.resolve())


if __name__ == "__main__":
    main()
