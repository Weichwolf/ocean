#!/usr/bin/env python3
"""Install and verify the Debian agent package in a disposable lab guest."""

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import eventually, ssh

INSTALL = r'''
set -eu
package_dir=$(mktemp -d /tmp/ocean-agent-package.XXXXXXXX)
trap 'rm -rf -- "$package_dir"' EXIT
chmod 0755 "$package_dir"
cat > "$package_dir/ocean-agent.deb"
if ! dpkg-query -W -f='${db:Status-Status}' podman 2>/dev/null | grep -qx installed; then
    sudo apt-get -qq update
fi
if ! sudo env OCEAN_AGENT_DEFER_START="${OCEAN_AGENT_DEFER_START:-0}" DEBIAN_FRONTEND=noninteractive \
    apt-get -yqq --no-install-recommends --reinstall \
    install "$package_dir/ocean-agent.deb" > "$package_dir/install.log" 2>&1; then
    tail -35 "$package_dir/install.log" >&2
    exit 1
fi
'''

PROBE = r'''
set -eu
cd /
uid=$(id -u ocean-agent)
test "$uid" -gt 0
dpkg-query -W -f='${Version}\n' ocean-agent
printf '%s\n' "$uid"
sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user is-enabled ocean-agent.service
sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user is-active ocean-agent.service
sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" podman info --format '{{.Host.Security.Rootless}} {{.Host.CgroupManager}}'
curl -fsS -o /dev/null -w '%{http_code}\n' --max-time 2 http://127.0.0.1:8081/readyz
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    ssh(state, args.node, INSTALL, args.package.read_bytes())
    version, uid, *observed = eventually(lambda: ssh(state, args.node, PROBE).decode().splitlines())
    if observed != ["enabled", "active", "true systemd", "204"]:
        raise RuntimeError("the agent's user service did not start with rootless Podman and systemd cgroups")
    evidence = {"node": args.node, "packageVersion": version, "uid": int(uid), "enabled": True, "rootless": True,
                "cgroupManager": "systemd", "readinessStatus": 204}
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "agent-package.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Debian package {version} is active as UID {uid} with rootless Podman on {args.node}.")


if __name__ == "__main__":
    main()
