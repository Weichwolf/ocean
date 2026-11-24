#!/usr/bin/env python3
"""Verify retryable package enrollment with a disposable Debian host."""

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import approval
from region import ARM, DEST, NODES, OPERATOR, ROOT, etcdctl, eventually, ssh, upload

HOST_STATE = "/var/lib/ocean-agent/host-enrollment"
CONFIG_DIR = "/etc/ocean-agent"


def agent_command(state, node, *command):
    return ssh(state, node, 'cd /; uid=$(id -u ocean-agent); ' +
               'sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" ' + shlex.join(command))


def wait_ready(state, node):
    def ready():
        reply = ssh(state, node, "curl -fsS -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8081/readyz")
        if reply != b"204":
            raise RuntimeError("the enrolled agent has not reached readiness")
    eventually(ready, 30)


def region_record(state, path):
    response = json.loads(ssh(state, OPERATOR, etcdctl(f"get /ocean/v1/regions/farm-1/hosts/{path} --write-out=json")))
    rows = response.get("kvs", [])
    if len(rows) != 1:
        raise RuntimeError("expected exactly one host record in the regional store")
    return rows[0], base64.b64decode(rows[0]["value"])


def revoke(state, node):
    with tempfile.TemporaryDirectory(prefix="ocean-revoke-host-") as temp:
        binary = Path(temp) / "host-fixture.test"
        subprocess.run(["go", "test", "-mod=readonly", "-tags=e2e", "-trimpath", "-c", "-o", str(binary), "./internal/controlplane"],
                       cwd=ROOT, env=dict(os.environ, CGO_ENABLED="0"), check=True)
        upload(state, OPERATOR, {"bin/host-fixture.test": binary.read_bytes()}, DEST)
    endpoints = ",".join(f"https://{address}:2379" for address in NODES.values())
    result = ssh(state, OPERATOR, shlex.join(["env", f"OCEAN_E2E_ETCD_ENDPOINTS={endpoints}", f"OCEAN_E2E_ETCD_PKI={DEST}/pki",
                                            f"OCEAN_E2E_REVOKE_HOST={node}", f"{DEST}/bin/host-fixture.test", "-test.run=^TestRevokeLabHost$"]))
    if b"PASS" not in result:
        raise RuntimeError("the regional operator could not revoke the host")


def verify(state, node):
    _, secret, _ = approval(state, node)
    config = {"origin": f"https://{ARM}", "hostId": node, "managementInterface": "mgmt0",
              "caFile": f"{DEST}/pki/ingress-ca.pem", "tokenFile": f"{CONFIG_DIR}/enrollment.secret", "stateDirectory": HOST_STATE}
    upload(state, node, {"enrollment.secret": secret.read_bytes(),
                         "verify-enrollment.py": (ROOT / "tests/e2e/host_enrollment.py").read_bytes()}, CONFIG_DIR, "ocean-agent")

    def configure(origin):
        data = {"listenAddress": "127.0.0.1:8081", "enrollment": dict(config, origin=origin)}
        upload(state, node, {"config.json": json.dumps(data).encode()}, CONFIG_DIR)

    configure(f"https://{NODES[node]}:8446")
    agent_command(state, node, "systemctl", "--user", "restart", "ocean-agent.service")
    eventually(lambda: agent_command(state, node, "test", "-s", f"{HOST_STATE}/identity.key"), 25)
    agent_command(state, node, "systemctl", "--user", "stop", "ocean-agent.service")
    key_before = agent_command(state, node, "sha256sum", f"{HOST_STATE}/identity.key").split()[0]
    configure(config["origin"])
    result = json.loads(agent_command(state, node, "python3", f"{CONFIG_DIR}/verify-enrollment.py", "register"))
    first, encoded = region_record(state, f"registered/{node}")
    host = json.loads(encoded)
    redemption, digest = region_record(state, f"redeemed/{node}")
    if first["mod_revision"] != redemption["mod_revision"] or host["keySHA256"].encode() != digest:
        raise RuntimeError("the identity and credential redemption were not atomic")
    agent_command(state, node, "systemctl", "--user", "start", "ocean-agent.service")
    wait_ready(state, node)
    identity = json.loads(agent_command(state, node, "python3", f"{CONFIG_DIR}/verify-enrollment.py", "verify"))
    second, _ = region_record(state, f"registered/{node}")
    if (first["mod_revision"] != second["mod_revision"] or identity["pool"] != "lab-default" or identity["cell"] != "cell-1" or
            identity["hostCertificateSHA256"] != hashlib.sha256(base64.b64decode(host["certificate"])).hexdigest() or
            agent_command(state, node, "sha256sum", f"{HOST_STATE}/identity.key").split()[0] != key_before):
        raise RuntimeError("the agent recovered a different registration or private key")
    result.update(identity, redemptionRevision=redemption["mod_revision"], retryPreservedIdentity=True)
    revoke(state, node)
    result.update(json.loads(agent_command(state, node, "python3", f"{CONFIG_DIR}/verify-enrollment.py", "revoked")))
    if ssh(state, node, "curl -sS -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8081/readyz") != b"503":
        raise RuntimeError("the revoked node continued to report readiness")
    result["revokedReadinessStatus"] = 503
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "host-enrollment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"The Debian agent on {node} recovered its original certificate after a discarded response and rejected a revoked identity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--node", choices=NODES, required=True)
    args = parser.parse_args()
    verify(args.state.resolve(), args.node)


if __name__ == "__main__":
    main()
