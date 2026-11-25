#!/usr/bin/env python3
"""Expand a prepared base farm to sixteen real enrolled KVM nodes and exercise workloads."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from enrollment import approval, publish
from prepare_application_gateway import prepare as prepare_gateway
from prepare_container_groups import NETWORK, SERVICE, prepare as prepare_compute
from prepare_functions import prepare as prepare_functions
from prepare_storage_provider import prepare as prepare_storage_provider
from region import ARM, NODES, OPERATOR, ROOT, etcdctl, eventually, run, ssh, upload
from storage import prepare as prepare_ceph
from verify_container_groups import verify as verify_containers
from verify_egress_hosts import status
from verify_functions import verify as verify_functions
from verify_lab_topology import verify as verify_topology
from verify_storage_mounts import verify as verify_storage

LAB = ROOT / "bin/ocean-lab"
PROFILE = ROOT / "lab/profiles/scale-16.yaml"
REGION = "/ocean/v1/regions/farm-1/hosts"
BASE = set(NODES)


def records(state, collection):
    data = ssh(state, OPERATOR, etcdctl(f"get {REGION}/{collection}/ --prefix -w json"))
    result = {}
    for item in json.loads(data).get("kvs", []):
        host = json.loads(base64.b64decode(item["value"]))
        result[host["hostId"]] = host
    return result


def certificates(state, wanted, *, network=False):
    registered = records(state, "registered")
    active = records(state, "live")
    result = []
    for guest in wanted:
        name = guest["name"]
        if name not in registered or name not in active:
            raise RuntimeError(f"{name} has not joined the active host inventory")
        host = registered[name]
        report = host["report"]
        mgmt = next(link for link in guest["interfaces"] if link["name"] == "mgmt0")
        if host.get("revokedAt") or report["mac"] != mgmt["mac"] or report["address"] != mgmt["address"].split("/")[0] or (
                report["cpu"] != guest["resources"]["vcpus"] or active[name]["capacity"]["memoryMiB"] <= 0):
            raise RuntimeError(f"{name} did not advertise its approved identity and capacity")
        if network and not active[name].get("containerNetwork"):
            raise RuntimeError(f"{name} has not qualified its workload network")
        fingerprint = hashlib.sha256(base64.b64decode(host["certificate"])).hexdigest()
        result.append({"hostId": name, "certificateSHA256": fingerprint, "capacity": active[name]["capacity"],
                       "managementMAC": mgmt["mac"], "pool": active[name]["pool"], "cell": active[name]["cell"]})
    if len({row["certificateSHA256"] for row in result}) != len(result):
        raise RuntimeError("two lab workers shared one certificate")
    return result


def prepare_manifests(state, nodes, package):
    paths = []
    for guest in nodes:
        interface = next(link for link in guest["interfaces"] if link["name"] == "mgmt0")
        name = guest["name"]
        directory, token, inventory = approval(state, name, mac=interface["mac"], address=interface["address"].split("/")[0],
                                                   profile="lab-kvm")
        config = json.loads(inventory.read_text())["hosts"][0]
        if config["mac"] != interface["mac"] or config["address"] != interface["address"].split("/")[0]:
            raise RuntimeError(f"{name} has a different approved network identity")
        manifest = directory / f"{name}-bootstrap.json"
        fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"hostId": name, "origin": f"https://{ARM}", "caFile": str(state / "region-pki/ingress-ca.pem"),
                       "tokenFile": str(token), "packageFile": str(package)}, stream)
        paths.extend(("-enrollment-file", manifest))
    return paths


def verify(state, package, registry_port, java_cache):
    plan = json.loads(run([LAB, "plan", "-profile", PROFILE]))["guests"]
    desired = [guest for guest in plan if "-node-" in guest["name"]]
    original = [guest for guest in desired if guest["name"] in BASE]
    added = [guest for guest in desired if guest["name"] not in BASE]
    if len(desired) != 16 or any(guest["resources"]["memoryMiB"] != 1024 for guest in desired):
        raise RuntimeError("scale acceptance requires sixteen 1 GiB ocean nodes")
    before = status(state)
    if any(not before.get(node) for node in BASE) or any(before.get(guest["name"]) for guest in added):
        raise RuntimeError("start with the three prepared management voters and stop additional guests before this run")
    certificates(state, original)
    manifests = prepare_manifests(state, added, package)
    publish(state)
    try:
        run([LAB, "up", "-state", state, "-profile", PROFILE, *manifests])
        print("All additional guests have been started with approved cloud-init seeds.", flush=True)
        enrolled = eventually(lambda: certificates(state, desired), 420)
        topology = verify_topology(state, "scale-16")
        prepare_compute(state, package, ("farm-1-node-05", "farm-1-node-06"))

        def enable_workload_link(guest):
            host = guest["name"]
            upload(state, host, {"workload-network.json": json.dumps(NETWORK).encode()}, "/etc/ocean-agent")
            ssh(state, host, f"sudo systemctl enable --now {SERVICE}")

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(enable_workload_link, desired))
        eventually(lambda: certificates(state, desired, network=True), 60)
        prepare_gateway(state, package)
        prepare_ceph(state, install=not (state / "storage-pki/cluster-id").exists())
        prepare_storage_provider(state, package)
        prepare_functions(state, package, java_cache, registry_port)
        print("Running the pinned container, persistent writer drain, and native Functions fixtures.", flush=True)
        containers = verify_containers(state, "farm-1-node-06")
        storage = verify_storage(state, "farm-1-node-04", False, drain_writer=True)
        functions = verify_functions(state)
        if not storage["persistentDataMatched"] or storage["drainedWriterHost"] == storage["replacementHost"]:
            raise RuntimeError("the live writer checkpoint did not survive drain onto another permitted host")
        peers = verify_topology(state, "scale-16")["quorumVoters"]
        if peers != topology["quorumVoters"]:
            raise RuntimeError("the management quorum changed while expanding compute hosts")
        result = {"enrolledNodes": enrolled, "topology": topology, "container": containers, "drain": storage,
                  "functions": functions, "votersAfterWorkloads": peers}
    finally:
        for guest in reversed(added):
            node = guest["name"]
            if status(state).get(node):
                run([LAB, "stop", "-state", state, node])
    if any(status(state).get(guest["name"]) for guest in added):
        raise RuntimeError("one or more added compute guests remained active after cleanup")
    result["additionalGuestsStopped"] = len(added)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--registry-port", type=int, default=5444)
    parser.add_argument("--java-cache", type=Path)
    args = parser.parse_args()
    state = args.state.resolve()
    result = verify(state, args.package.resolve(strict=True), args.registry_port, args.java_cache)
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "scale-16.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Sixteen enrolled KVM guests preserved the three-voter quorum and served the container, storage drain, and Function checks.")


if __name__ == "__main__":
    main()
