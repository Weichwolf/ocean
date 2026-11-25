#!/usr/bin/env python3
"""Install the directory controller runtime and client tools in a disposable KVM lab."""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from region import eventually, ssh
from verify_agent_package import INSTALL

CONTROLLERS = ("farm-1-node-01", "farm-1-node-02")
CLIENT = "farm-1-node-03"
LOAD = r'''
set -eu
cd /
uid=$(id -u ocean-agent)
sudo loginctl enable-linger ocean-agent
sudo systemctl start "user@$uid.service"
sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" nice -n 10 podman load --quiet
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--samba-archive", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    package = args.package.read_bytes()
    image = args.samba_archive.read_bytes()

    def prepare(host):
        eventually(lambda: ssh(state, host, "cloud-init status --wait", timeout=20), 90)
        if host == CLIENT:
            ssh(state, host, "sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install "
                "-yqq --no-install-recommends adcli bind9-dnsutils krb5-user smbclient", timeout=300)
        else:
            # The test supplies its own regional origin, enrollment and network configuration.
            ssh(state, host, "OCEAN_AGENT_DEFER_START=1\n" + INSTALL, package, timeout=300)
            ssh(state, host, LOAD, image, timeout=180)
        print(f"Prepared {host}.", flush=True)

    with ThreadPoolExecutor(max_workers=3) as executor:
        list(executor.map(prepare, (*CONTROLLERS, CLIENT)))


if __name__ == "__main__":
    main()
