#!/usr/bin/env python3
"""Approve, boot, and verify a fresh host without guest-side provisioning commands."""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import approval, publish
from region import ARM, OPERATOR, ROOT, etcdctl, eventually, run, ssh
from verify_enrollment import agent_command, region_record, wait_ready


def verify_restarts(state, name, revision):
    agent_command(state, name, "systemctl", "--user", "restart", "ocean-agent.service")
    wait_ready(state, name)
    original_boot = ssh(state, name, "cat /proc/sys/kernel/random/boot_id").strip()
    ssh(state, name, "sudo systemctl reboot --no-block")

    def new_boot():
        current = ssh(state, name, "cat /proc/sys/kernel/random/boot_id").strip()
        if not current or current == original_boot:
            raise RuntimeError("the guest has not rebooted")

    eventually(new_boot, 75)
    wait_ready(state, name)
    registered, _ = region_record(state, f"registered/{name}")
    if registered["mod_revision"] != revision:
        raise RuntimeError("the host acquired another identity during restart")
    return {"agentRestartPreservedIdentity": True, "guestRebootPreservedIdentity": True}


def bootstrap(state, profile, package, name, check_restarts=False):
    lab = ROOT / "bin/ocean-lab"
    plan = json.loads(run([lab, "plan", "-profile", profile]))
    guest = next((entry for entry in plan["guests"] if entry["name"] == name), None)
    if guest is None or "compute" not in guest["roles"] or "control-plane" in guest["roles"] or guest["farm"] != 1:
        raise RuntimeError("select an additional compute guest in the regional lab profile")
    machines = json.loads((state / "state.json").read_text())["machines"]
    if any(machine["guest"]["name"] == name for machine in machines):
        raise RuntimeError("first-boot verification requires an unused guest")
    existing = json.loads(ssh(state, OPERATOR, etcdctl(f"get /ocean/v1/regions/farm-1/hosts/registered/{name} --write-out=json")))
    if existing.get("count", 0):
        raise RuntimeError("first-boot verification requires an unused regional host identity")
    interface = next(item for item in guest["interfaces"] if item["name"] == "mgmt0")
    address = interface["address"].split("/", 1)[0]
    directory, credential, record = approval(state, name, mac=interface["mac"], address=address, profile="lab-kvm")
    approved = json.loads(record.read_text())["hosts"][0]
    if approved["address"] != address or approved["mac"] != interface["mac"]:
        raise RuntimeError("the new plan differs from the approved address or MAC")
    manifest = directory / f"{name}-bootstrap.json"
    fd = os.open(manifest, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump({"hostId": name, "origin": f"https://{ARM}", "caFile": str(state / "region-pki/ingress-ca.pem"),
                   "tokenFile": str(credential), "packageFile": str(package)}, stream)
    publish(state)
    print(f"Starting {name} with an approved NoCloud enrollment seed.", flush=True)
    run([lab, "up", "-state", state, "-profile", profile, "-enrollment-file", manifest])
    registered, encoded = eventually(lambda: region_record(state, f"registered/{name}"), 240)
    redeemed, public_key_digest = region_record(state, f"redeemed/{name}")
    host = json.loads(encoded)
    if (host.get("revokedAt") or host["report"]["mac"] != approved["mac"] or host["report"]["address"] != approved["address"] or
            host["report"]["cpu"] != guest["resources"]["vcpus"] or host["keySHA256"].encode() != public_key_digest or
            registered["mod_revision"] != redeemed["mod_revision"]):
        raise RuntimeError("the first-boot registration differs from the approved guest or credential redemption")
    wait_ready(state, name)
    runtime = ssh(state, name, "cloud-init status --wait && dpkg-query -W -f='${Version}\\n' ocean-agent").decode().splitlines()
    if "status: done" not in runtime or len(runtime) < 2:
        raise RuntimeError("cloud-init did not complete the package installation")
    seed = state / "nodes" / name / "seed.iso"
    if seed.stat().st_mode & 0o077:
        raise RuntimeError("the enrollment seed is readable outside the lab account")
    evidence = {"hostId": name, "firstBootEnrollment": True, "mTLSReadinessHTTP": 204, "packageVersion": runtime[-1],
                "managementMAC": approved["mac"], "managementIPv4": approved["address"], "cell": host["cell"], "pool": host["pool"],
                "configuredRAMMiB": guest["resources"]["memoryMiB"], "configuredVCPUs": guest["resources"]["vcpus"],
                "observedMemoryMiB": host["report"]["memoryMiB"], "redemptionRevision": redeemed["mod_revision"],
                "certificateSHA256": hashlib.sha256(base64.b64decode(host["certificate"])).hexdigest()}
    if check_restarts:
        evidence.update(verify_restarts(state, name, registered["mod_revision"]))
    (state / "evidence").mkdir(mode=0o700, exist_ok=True)
    (state / "evidence" / f"host-first-boot-{name}.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"{name} enrolled from its NoCloud seed and confirmed its certificate before readiness.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--check-restarts", action="store_true")
    args = parser.parse_args()
    bootstrap(args.state.resolve(), args.profile.resolve(), args.package.resolve(strict=True), args.node, args.check_restarts)


if __name__ == "__main__":
    main()
