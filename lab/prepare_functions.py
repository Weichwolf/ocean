#!/usr/bin/env python3
"""Stage pinned Function fixtures in a TLS registry on the local lab host."""

import argparse
import json
import shlex
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from build_functions_java import build
from enrollment import publish
from prepare_storage_provider import WORKERS
from region import DEST as REGION, DOMAIN, OPERATOR, VIP, ca, eventually, leaf, ssh, upload
from verify_agent_package import INSTALL
from verify_function_fixtures import build_fixture
from verify_enrollment import agent_command, wait_ready

REGISTRY_IMAGE = "docker.io/library/registry@sha256:52b489ad8e6f40d1a676702e3ce398ec796ce38f08fbb786e1f324baa12d84b8"
REGISTRY_NAME = "registry." + DOMAIN
FUNCTION_DOMAIN = "functions." + DOMAIN
SCM_DOMAIN = "scm." + DOMAIN
ZIP_RUNTIME = "mcr.microsoft.com/azure-functions/node@sha256:76b0a2318403992100bdc72f2698e9d938e1a3b1e210c28c11aaaeb57221a6c1"
AZURITE = "mcr.microsoft.com/azure-storage/azurite@sha256:dae2a5f96553962901304b94e72ef87e299d0825e4b679673bcc527a25076fe4"


def podman(*args):
    result = subprocess.run(["nice", "-n", "10", "podman", *map(str, args)], check=True, stdout=subprocess.PIPE, text=True)
    return result.stdout.strip()


def registry_name(state):
    return "ocean-functions-registry-" + state.name.rsplit(".", 1)[-1]


def ensure_boot_capacity(state, node):
    directory = state / "nodes" / node
    wanted = 8 * 1024**3
    with socket.socket(socket.AF_UNIX) as monitor:
        monitor.settimeout(8)
        monitor.connect(str(directory / "qmp"))
        with monitor.makefile("rwb") as stream:
            stream.readline()

            def execute(command, **arguments):
                stream.write(json.dumps({"execute": command, "arguments": arguments}).encode() + b"\n")
                stream.flush()
                while line := stream.readline():
                    reply = json.loads(line)
                    if "error" in reply:
                        raise RuntimeError(f"QEMU cannot run {command} for {node}")
                    if "return" in reply:
                        return reply["return"]
                raise RuntimeError(f"QEMU closed its monitor for {node}")

            execute("qmp_capabilities")
            drives = [drive for drive in execute("query-block") if drive.get("inserted", {}).get("file") == str(directory / "disk.qcow2")]
            if len(drives) != 1:
                raise RuntimeError(f"cannot identify the Debian boot disk on {node}")
            drive = drives[0]
            if drive["inserted"]["image"]["virtual-size"] < wanted:
                execute("block_resize", device=drive["device"], size=wanted)
    ssh(state, node, """set -eu
if [ "$(df -P -B1 / | awk 'NR == 2 {print $2}')" -lt 7000000000 ]; then
    test "$(findmnt -n -o SOURCE /)" = /dev/vda1
    sudo growpart /dev/vda 1
    sudo resize2fs /dev/vda1
fi
""")


def prepare(state, package, cache, registry_port):
    certs = state / "functions-registry"
    certs.mkdir(mode=0o700, exist_ok=True)
    store = certs / "store"
    store.mkdir(mode=0o700, exist_ok=True)
    authority = ca(certs, "registry-ca")
    leaf(certs, "registry", authority, "serverAuth", f"DNS:{REGISTRY_NAME},IP:127.0.0.1", "rsa:2048")
    service = registry_name(state)
    port = int(registry_port)
    registry = f"{REGISTRY_NAME}:{port}"
    local_registry = f"127.0.0.1:{port}"
    podman("image", "pull", "--quiet", REGISTRY_IMAGE)
    podman("run", "--detach", "--replace", "--name", service, "--memory", "128m",
           "--security-opt=no-new-privileges", "--cap-drop=ALL", "--publish", f"127.0.0.1:{port}:5000",
           "--volume", f"{store}:/var/lib/registry",
           "--volume", f"{certs}/registry.pem:/registry.pem:ro", "--volume", f"{certs}/registry.key:/registry.key:ro",
           "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/registry.pem", "--env", "REGISTRY_HTTP_TLS_KEY=/registry.key", REGISTRY_IMAGE)
    images = {version: details["image"] for version, details in build(cache).items()}
    images["node"] = build_fixture("node")
    refs = {}
    with tempfile.TemporaryDirectory(prefix="ocean-function-registry-") as folder:
        trust = Path(folder) / "certs"
        trust.mkdir()
        (trust / "ca.crt").write_bytes(authority[0].read_bytes())
        digest = Path(folder) / "digest"
        for version, image in images.items():
            runtime = "node" if version == "node" else "java"
            podman("push", "--cert-dir", trust, "--digestfile", digest,
                   image, f"docker://{local_registry}/ocean-fixtures/{runtime}:{version}")
            refs[version] = f"{registry}/ocean-fixtures/{runtime}@{digest.read_text().strip()}"
    if len(set(refs.values())) != len(refs):
        raise RuntimeError("Function image revisions did not produce different manifests")

    def provision(node):
        ensure_boot_capacity(state, node)
        location = "/etc/containers/certs.d/" + registry
        upload(state, node, {"ca.crt": authority[0].read_bytes()}, location, owner="root")
        # The bootstrap slirp path can reach this host's loopback registry.
        entry = shlex.quote(f"10.0.2.2 {REGISTRY_NAME}")
        ssh(state, node, f"grep -qx {entry} /etc/hosts || echo {entry} | sudo tee -a /etc/hosts >/dev/null")
        ssh(state, node, INSTALL, package.read_bytes())
        ssh(state, node, "sudo systemctl restart ocean-container-network.service")
        wait_ready(state, node)
        for ref in (*refs.values(), AZURITE):
            agent_command(state, node, "nice", "-n", "10", "podman", "pull", "--quiet", ref)

    with ThreadPoolExecutor(max_workers=len(WORKERS)) as pool:
        list(pool.map(provision, WORKERS))
    publish(state, function_plans=True, function_domain=FUNCTION_DOMAIN, function_registry=registry)
    (certs / "images.json").write_text(json.dumps(refs, indent=2) + "\n")
    print("Staged digest-pinned Java and Node.js Function images on both storage-capable workers.", flush=True)


def prepare_zip_slots(state, package):
    payload = package.read_bytes()

    def provision(node):
        ensure_boot_capacity(state, node)
        ssh(state, node, INSTALL, payload)
        ssh(state, node, "sudo systemctl restart ocean-container-network.service ocean-storage-agent.service")
        wait_ready(state, node)
        for image in (ZIP_RUNTIME, AZURITE):
            agent_command(state, node, "sh", "-ec",
                          'podman image exists "$1" || exec nice -n 10 podman pull --quiet "$1"', "sh", image)

    with ThreadPoolExecutor(max_workers=len(WORKERS)) as pool:
        list(pool.map(provision, WORKERS))
    publish(state, function_plans=True, function_domain=FUNCTION_DOMAIN, function_scm_domain=SCM_DOMAIN)
    host = f"fixture.{SCM_DOMAIN}"
    eventually(lambda: ssh(state, OPERATOR, f"curl -fsS --max-time 4 --cacert {REGION}/pki/ingress-ca.pem "
                           f"--resolve {host}:443:{VIP} https://{host}/readyz"))
    print("Both enrolled storage workers have the native ZIP runtime and the SCM certificate is trusted by the CLI guest.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--registry-port", type=int, default=5443)
    parser.add_argument("--zip-slots", action="store_true", help="prepare the pinned Node.js ZIP runtime and regional SCM/slot endpoints")
    args = parser.parse_args()
    if args.zip_slots:
        prepare_zip_slots(args.state.resolve(), args.package.resolve())
    else:
        prepare(args.state.resolve(), args.package.resolve(), args.cache, args.registry_port)


if __name__ == "__main__":
    main()
