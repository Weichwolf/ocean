#!/usr/bin/env python3
"""Run the routed IPsec probe inside a prepared, disposable Debian guest."""

import argparse
import shlex
import subprocess
import tempfile
from pathlib import Path

from region import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    args = parser.parse_args()
    guest_probe = """
set -eu
dpkg-query -W strongswan-charon strongswan-swanctl nftables iputils-ping
binary=$(mktemp /var/tmp/ocean-ipsec-test.XXXXXXXX)
trap 'rm -f -- "$binary"' EXIT
cat > "$binary"
chmod 0700 "$binary"
OCEAN_E2E_IPSEC_GATEWAY=1 "$binary" -test.v -test.run '^TestRoutedIPsec$'
"""
    with tempfile.TemporaryDirectory(prefix="ocean-ipsec-build-") as directory:
        binary = Path(directory) / "ipsec.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-c", "-o", binary, "./internal/network"],
                       cwd=ROOT, timeout=120, check=True)
        with binary.open("rb") as payload:
            result = subprocess.run([ROOT / "bin/ocean-lab", "ssh", "-state", args.state, "farm-1-node-01", "--",
                                     shlex.join(["sudo", "-n", "sh", "-c", guest_probe])],
                                    stdin=payload, stdout=subprocess.PIPE, text=True, timeout=120)
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise SystemExit("The routed IPsec probe failed inside the Debian guest.")
    if "--- PASS: TestRoutedIPsec (" not in result.stdout:
        raise SystemExit("The Debian guest did not report a passing routed IPsec probe.")


if __name__ == "__main__":
    main()
