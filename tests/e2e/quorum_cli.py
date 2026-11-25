#!/usr/bin/env python3
"""Exercise an authenticated, well-formed container mutation during and after quorum loss."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from arm_cli import command_args, load_matrix


def verify(matrix, fixture, image, phase):
    state = json.loads(fixture.read_text())
    tenant = state["tenant"]
    origin = tenant["arm"]
    address = (f"/subscriptions/{tenant['subscription']}/resourceGroups/{state['group']}"
               "/providers/Microsoft.ContainerInstance/containerGroups/quorum-canary")
    rows = load_matrix(matrix, "HA-03")
    with tempfile.TemporaryDirectory(prefix="ocean-quorum-cli-") as temporary:
        directory = Path(temporary)
        env = dict(os.environ, AZURE_CONFIG_DIR=str(directory/"az"), AZURE_CORE_COLLECT_TELEMETRY="0",
                   REQUESTS_CA_BUNDLE=tenant["ca"])
        az = json.loads(subprocess.run(["az", "version", "-o", "json"], env=env, check=True,
                                       capture_output=True, text=True, timeout=15).stdout)
        header = directory/"headers.secret"
        fd = os.open(header, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"Authorization": "Bearer " + state["armToken"]}, stream)
        body = directory/"group.json"
        ports = [{"port": 8080, "protocol": "TCP"}]
        body.write_text(json.dumps({"location": tenant["location"], "properties": {
            "osType": "Linux", "restartPolicy": "Always", "ipAddress": {"type": "Public", "ports": ports},
            "containers": [{"name": "quorum-canary", "properties": {"image": image, "ports": ports,
                "resources": {"requests": {"cpu": 0.1, "memoryInGB": 0.0625}},
                "command": ["/bin/busybox", "httpd", "-f", "-p", "8080"]}}],
        }}))
        bindings = {"origin": origin, "id": address, "body": str(body), "headers": str(header)}

        def execute(label):
            args = command_args(rows[label], az, **bindings)
            try:
                return subprocess.run(["az", *args], env=env, capture_output=True, text=True, timeout=35)
            except subprocess.TimeoutExpired:
                raise RuntimeError(f"the quorum probe exceeded its CLI deadline for {label}") from None

        if phase == "outage":
            denied = execute("quorum-container-put")
            errors = denied.stderr.lower()
            signals = {
                "HTTP 503": ("503", "serviceunavailable", "service unavailable", "no server is available"),
                "connection closed": ("connection reset", "remote end closed", "unexpected eof", "unexpected_eof_while_reading", "connection aborted"),
                "connection refused": ("connection refused",),
                "connection deadline": ("read timed out", "connect timeout", "connection timed out"),
            }
            reason = next((reason for reason, words in signals.items() if any(word in errors for word in words)), None)
            if not denied.returncode or not reason:
                lines = [line for line in denied.stderr.splitlines() if line.startswith(("Code:", "ERROR:"))]
                diagnostic = " ".join(lines).replace(state["armToken"], "[redacted]")
                if len(diagnostic) > 360:
                    diagnostic = diagnostic[:160] + " … " + diagnostic[-195:]
                raise RuntimeError(f"unexpected quorum response (exit {denied.returncode}): {diagnostic}")
            return {"mutationUnacknowledgedDuringQuorumLoss": True, "outageSignal": reason, "azureCLI": az["azure-cli"]}
        baseline = execute("quorum-container-show")
        if baseline.returncode == 0 or "resourcenotfound" not in baseline.stderr.lower():
            raise RuntimeError("the rejected operation left unexpected container state")
        created = execute("quorum-container-put")
        if created.returncode != 0:
            raise RuntimeError("the same authenticated request did not succeed after quorum recovery")
        try:
            deadline = time.monotonic()+30
            while time.monotonic() < deadline:
                response = execute("quorum-container-show")
                if response.returncode == 0:
                    observed = json.loads(response.stdout)["properties"]
                    if observed.get("instanceView", {}).get("state") == "Running":
                        return {"rejectedOperationLeftNoResource": True, "replayProvisionedRealContainer": True}
                time.sleep(1)
            raise RuntimeError("the post-recovery canary did not become active")
        finally:
            if execute("quorum-container-delete").returncode != 0:
                raise RuntimeError("could not delete the post-recovery canary")
            deadline = time.monotonic()+20
            while time.monotonic() < deadline:
                result = execute("quorum-container-show")
                if result.returncode != 0 and "resourcenotfound" in result.stderr.lower():
                    break
                time.sleep(1)
            else:
                raise RuntimeError("the canary reservation was not released")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--phase", choices=("outage", "recover"), required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.matrix, args.fixture, args.image, args.phase)))


if __name__ == "__main__":
    main()
