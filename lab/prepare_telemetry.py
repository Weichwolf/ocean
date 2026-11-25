#!/usr/bin/env python3
"""Deploy an independent telemetry etcd cluster and bounded worker buffers."""

import argparse
import base64
import json
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.dont_write_bytecode = True
from enrollment import publish
from region import DEST, NODES, OPERATOR, ca, etcdctl, eventually, leaf, ssh, unit, upload
from verify_agent_package import INSTALL
from verify_enrollment import CONFIG_DIR, agent_command, wait_ready

SERVICE = "ocean-telemetry-etcd.service"
CLIENT_PORT = 2391
PEER_PORT = 2392
DATA_DIRECTORY = DEST + "/telemetry-data"


def deploy_store(state):
    directory = state / "telemetry-pki"
    directory.mkdir(mode=0o700, exist_ok=True)
    client_ca = ca(directory, "telemetry-client")
    peer_ca = ca(directory, "telemetry-peer")
    client_urls = {name: f"https://{address}:{CLIENT_PORT}" for name, address in NODES.items()}
    peer_urls = {name: f"https://{address}:{PEER_PORT}" for name, address in NODES.items()}
    initial_cluster = ",".join(f"{name}={endpoint}" for name, endpoint in peer_urls.items())
    config = {}
    for name, address in NODES.items():
        peer = f"{name}-telemetry-peer"
        server = f"{name}-telemetry-gateway"
        client = f"{name}-telemetry-client"
        files = {"pki/telemetry-client-ca.pem": client_ca[0].read_bytes(), "pki/telemetry-peer-ca.pem": peer_ca[0].read_bytes()}
        files.update(leaf(directory, peer, peer_ca, "clientAuth,serverAuth", f"IP:{address}"))
        files.update(leaf(directory, server, client_ca, "clientAuth,serverAuth", f"IP:{address}"))
        files.update(leaf(directory, client, client_ca, "clientAuth"))
        arguments = [
            f"--name={name}", f"--data-dir={DATA_DIRECTORY}", "--initial-cluster-token=ocean-farm-1-telemetry",
            f"--initial-cluster={initial_cluster}", f"--listen-client-urls={client_urls[name]}",
            f"--advertise-client-urls={client_urls[name]}", f"--listen-peer-urls={peer_urls[name]}",
            f"--initial-advertise-peer-urls={peer_urls[name]}", f"--cert-file={DEST}/pki/{server}.pem",
            f"--key-file={DEST}/pki/{server}.key", f"--trusted-ca-file={DEST}/pki/telemetry-client-ca.pem",
            "--client-cert-auth", f"--peer-cert-file={DEST}/pki/{peer}.pem", f"--peer-key-file={DEST}/pki/{peer}.key",
            f"--peer-trusted-ca-file={DEST}/pki/telemetry-peer-ca.pem", "--peer-client-cert-auth",
            "--quota-backend-bytes=67108864", "--auto-compaction-mode=periodic", "--auto-compaction-retention=5m",
        ]
        definition = unit(shlex.join([f"{DEST}/bin/etcd", *arguments]), "ocean")
        files[f"units/{SERVICE}"] = definition.replace(b"User=ocean\n", b"User=ocean\nNice=10\nMemoryMax=128M\n")
        upload(state, name, files)
        ssh(state, name, f"sudo install -d -m 0700 -o ocean {DATA_DIRECTORY} && "
                         f"sudo install -m 0644 {DEST}/units/{SERVICE} /etc/systemd/system/ && "
                         f"sudo systemctl daemon-reload && sudo systemctl enable --now --no-block {SERVICE}")
        config[name] = ({"etcd": {"endpoints": list(client_urls.values()), "caFile": f"{DEST}/pki/telemetry-client-ca.pem",
                                 "certificateFile": f"{DEST}/pki/{client}.pem", "keyFile": f"{DEST}/pki/{client}.key"},
                         "retentionSeconds": 3600}, {})
    for name in NODES:
        eventually(lambda: ssh(state, name, shlex.join([
            "sudo", "-u", "ocean", f"{DEST}/bin/etcdctl", f"--endpoints={client_urls[name]}",
            f"--cacert={DEST}/pki/telemetry-client-ca.pem", f"--cert={DEST}/pki/{name}-telemetry-client.pem",
            f"--key={DEST}/pki/{name}-telemetry-client.key", "endpoint", "health",
        ])))
    publish(state, telemetry=config)


def live_compute_hosts(state):
    prefix = "/ocean/v1/regions/farm-1/hosts/live/"
    active = json.loads(ssh(state, OPERATOR, etcdctl(f"get {prefix} --prefix --keys-only --write-out=json")))
    names = {base64.b64decode(record["key"]).decode().removeprefix(prefix) for record in active.get("kvs", [])}
    approvals = state / "enrollment-pki"
    return sorted({host["hostId"] for inventory in approvals.glob("*-inventory.json")
                   for host in json.loads(inventory.read_text())["hosts"]
                   if host["hostId"] in names and "compute" in host["roles"]})


def configure_worker(state, node, package, budget):
    ssh(state, node, INSTALL, package)
    config = json.loads(ssh(state, node, f"cat {CONFIG_DIR}/config.json"))
    config["enrollment"]["telemetryBufferBytes"] = budget
    upload(state, node, {"config.json": json.dumps(config).encode()}, CONFIG_DIR, "ocean-agent")
    agent_command(state, node, "systemctl", "--user", "restart", "ocean-agent.service")
    wait_ready(state, node)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--buffer-bytes", type=int, default=64 << 10)
    args = parser.parse_args()
    if not 4096 <= args.buffer_bytes <= 4 << 20:
        parser.error("--buffer-bytes must be between 4096 and 4194304")
    state, package = args.state.resolve(), args.package.read_bytes()
    deploy_store(state)
    hosts = live_compute_hosts(state)
    if not hosts:
        raise RuntimeError("there are no live compute hosts to configure")
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda name: configure_worker(state, name, package, args.buffer_bytes), hosts))
    print(f"Ready: independent three-member telemetry store and {args.buffer_bytes}-byte buffers on {', '.join(hosts)}.")


if __name__ == "__main__":
    main()
