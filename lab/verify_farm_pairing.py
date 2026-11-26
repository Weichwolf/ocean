#!/usr/bin/env python3
"""Exercise four farm quorums over two real WireGuard paths in a private network namespace."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FARMS = tuple(range(1, 5))
PATHS = ("wan-a", "wan-b")
PAIR_PORT = 9443


def run(*command, data=None):
    return subprocess.run(command, input=data, capture_output=True, text=True, check=True, timeout=8).stdout.strip()


def wait(check, timeout=25):
    start = time.monotonic()
    last = None
    while time.monotonic() - start < timeout:
        try:
            if check():
                return round((time.monotonic() - start) * 1000)
        except (subprocess.SubprocessError, OSError) as err:
            last = err
        time.sleep(0.3)
    detail = last.stdout if isinstance(last, subprocess.CalledProcessError) else last
    raise RuntimeError(f"timed out waiting for {check.__name__}: {detail}")


def farm_name(index):
    return f"farm-{index}"


def hostname(index):
    return f"{farm_name(index)}.ocean.test"


def mgmt(index):
    return f"10.231.{index}.254"


def overlay(path, farm):
    return f"10.245.{PATHS.index(path) + 1}.{farm}"


def underlay(path, farm):
    return f"10.244.{PATHS.index(path) + 1}.{farm}"


def exports(farm):
    return f"10.246.{farm}.0/24"


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class Lab:
    def __init__(self, args, directory, cleanup):
        self.args = args
        self.directory = directory
        self.cleanup = cleanup
        self.processes = {}
        self.gateways = {}

    def start(self, name, *command):
        with (self.directory / f"{name}.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log,
                                       env={**os.environ, "GOMAXPROCS": "2"})
        self.cleanup.callback(stop, process)
        self.processes[name] = process
        return process

    def gateway(self, path, farm, *command):
        return run("nsenter", "-t", str(self.gateways[path, farm]), "-n", "--", *command)

    def bridge(self, name, address=None):
        run("ip", "link", "add", name, "type", "bridge")
        if address:
            run("ip", "addr", "add", address, "dev", name)
        run("ip", "link", "set", name, "up")

    def attach(self, path, farm, device, bridge, address):
        peer = f"ovs{PATHS.index(path)}{farm}{device[0]}"
        run("ip", "link", "add", peer, "type", "veth", "peer", "name", device, "netns",
            str(self.gateways[path, farm]))
        run("ip", "link", "set", peer, "master", bridge)
        run("ip", "link", "set", peer, "up")
        self.gateway(path, farm, "ip", "addr", "add", address, "dev", device)
        self.gateway(path, farm, "ip", "link", "set", device, "up")

    def mesh(self):
        run("ip", "link", "set", "lo", "up")
        for farm in FARMS:
            self.bridge(f"mgmt{farm}", mgmt(farm) + "/24")
        for path in PATHS:
            self.bridge(path)
        keys = {}
        for path in PATHS:
            for farm in FARMS:
                guest = self.start(f"namespace-{path}-{farm}", "unshare", "--net", "sleep", "infinity")
                own = os.stat("/proc/self/ns/net").st_ino
                wait(lambda: os.stat(f"/proc/{guest.pid}/ns/net").st_ino != own, 3)
                self.gateways[path, farm] = guest.pid
                self.gateway(path, farm, "ip", "link", "set", "lo", "up")
                self.attach(path, farm, "wan0", path, underlay(path, farm) + "/24")
                self.attach(path, farm, "mgmt0", f"mgmt{farm}", f"10.231.{farm}.{11 + PATHS.index(path)}/24")
                private = self.directory / f"wg-{path}-{farm}.key"
                private.touch(mode=0o600)
                private.write_text(run(self.args.wg, "genkey") + "\n")
                keys[path, farm] = (private, run(self.args.wg, "pubkey", data=private.read_text()))
        for path in PATHS:
            for farm in FARMS:
                self.gateway(path, farm, "ip", "link", "add", "mesh0", "type", "wireguard")
                self.gateway(path, farm, "ip", "addr", "add", overlay(path, farm) + "/32", "dev", "mesh0")
                self.gateway(path, farm, "ip", "addr", "add", f"10.246.{farm}.{11 + PATHS.index(path)}/32", "dev", "lo")
                fields = ["listen-port", "51820", "private-key", str(keys[path, farm][0])]
                routes = []
                for peer in FARMS:
                    if peer == farm:
                        continue
                    targets = [overlay(path, peer) + "/32", exports(peer)]
                    routes.extend(targets)
                    fields.extend(["peer", keys[path, peer][1], "endpoint", underlay(path, peer) + ":51820",
                                   "allowed-ips", ",".join(targets)])
                self.gateway(path, farm, self.args.wg, "set", "mesh0", *fields)
                self.gateway(path, farm, "ip", "link", "set", "mesh0", "up")
                for route in routes:
                    self.gateway(path, farm, "ip", "route", "add", route, "dev", "mesh0")

    def ca(self, name):
        key, pem = self.directory / (name + ".key"), self.directory / (name + ".pem")
        run("openssl", "req", "-x509", "-newkey", "ed25519", "-noenc", "-days", "1", "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:true", "-keyout", key, "-out", pem)
        return name

    def certificate(self, name, authority, san):
        base = self.directory / name
        conf = base.with_suffix(".ext")
        conf.write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth,clientAuth\n")
        run("openssl", "req", "-new", "-newkey", "ed25519", "-noenc", "-subj", f"/CN={name}",
            "-keyout", base.with_suffix(".key"), "-out", base.with_suffix(".csr"))
        run("openssl", "x509", "-req", "-in", base.with_suffix(".csr"), "-CA", self.directory / (authority + ".pem"),
            "-CAkey", self.directory / (authority + ".key"), "-days", "1", "-extfile", conf, "-out", base.with_suffix(".pem"))
        return base

    def tls(self, cert, ca):
        return {"certificateFile": str(cert.with_suffix(".pem")), "keyFile": str(cert.with_suffix(".key")),
                "clientCAFile": str(self.directory / (ca + ".pem"))}

    def local_cluster(self, farm, authority):
        ca = self.directory / (authority + ".pem")
        server = self.certificate(f"store-{farm}", authority, f"IP:{mgmt(farm)}")
        tls = ("--trusted-ca-file", ca, "--cert-file", server.with_suffix(".pem"), "--key-file", server.with_suffix(".key"))
        names = [f"voter-{i}" for i in range(1, 4)]
        endpoints = [f"https://{mgmt(farm)}:{2378 + i}" for i in range(1, 4)]
        peers = [f"http://{mgmt(farm)}:{2388 + i}" for i in range(1, 4)]
        cluster = ",".join(f"{name}={peer}" for name, peer in zip(names, peers, strict=True))
        for name, endpoint, peer in zip(names, endpoints, peers, strict=True):
            self.start(f"store-{farm}-{name}", self.args.etcd, "--name", name, "--data-dir", self.directory / f"store-{farm}-{name}",
                       "--listen-client-urls", endpoint, "--advertise-client-urls", endpoint, "--client-cert-auth=true", *tls,
                       "--listen-peer-urls", peer, "--initial-advertise-peer-urls", peer, "--initial-cluster", cluster,
                       "--initial-cluster-token", farm_name(farm))
        store = {"endpoints": endpoints, "caFile": str(ca), "certificateFile": str(server.with_suffix(".pem")),
                 "keyFile": str(server.with_suffix(".key"))}
        def ready():
            return self.etcdctl(store, "endpoint", "health")
        wait(ready)
        cfg = self.directory / f"management-{farm}.json"
        cfg.write_text(json.dumps({"listenAddress": f"{mgmt(farm)}:8080", "tls": self.tls(server, authority),
                                   "region": {"name": farm_name(farm), "initialCell": "cell-1", "etcd": store}}))
        self.start(f"management-{farm}", ROOT / "bin/ocean-control-plane", "-config", cfg)
        wait(lambda: self.management_ready(farm, store))
        return store

    def management_ready(self, farm, store):
        return run("curl", "--silent", "--fail", "--max-time", "3", "--cacert", store["caFile"],
                   "--cert", store["certificateFile"], "--key", store["keyFile"],
                   "--write-out", "%{http_code}", f"https://{mgmt(farm)}:8080/readyz") == "204"

    def etcdctl(self, store, *args):
        return run(self.args.etcdctl, "--endpoints", ",".join(store["endpoints"]), "--cacert", store["caFile"],
                   "--cert", store["certificateFile"], "--key", store["keyFile"], "--command-timeout=3s", *args)

    def dns(self, port):
        records = [f"--host-record={hostname(farm)},{overlay(path, farm)}" for farm in FARMS for path in PATHS]
        self.start(f"dns-{port}", self.args.dnsmasq, "--no-daemon", "--bind-interfaces",
                   "--conf-file=/dev/null", "--log-facility=-", "--no-resolv", "--no-hosts", "--cache-size=0", f"--port={port}",
                   *(f"--listen-address={mgmt(farm)}" for farm in FARMS), *records)
        def resolved():
            answers = self.gateway(PATHS[0], 1, "dig", "+short", "+tries=1", "+time=1", f"@{mgmt(1)}", "-p", str(port), hostname(2))
            return set(answers.splitlines()) == {overlay(path, 2) for path in PATHS}
        wait(resolved, 5)

    def federation(self, path, farm, store, certificate):
        config = self.directory / f"federation-{path}-{farm}.json"
        config.write_text(json.dumps({
            "listenAddress": f"{overlay(path, farm)}:{PAIR_PORT}", "logLevel": "DEBUG", "tls": self.tls(certificate, "federation-ca"),
            "path": path, "dnsServers": [f"{mgmt(farm)}:{port}" for port in (5353, 5354)], "etcd": store,
            "policy": {
                "farm": farm_name(farm), "dnsName": hostname(farm), "exports": [exports(farm)],
                "localPaths": {name: f"{overlay(name, farm)}:{PAIR_PORT}" for name in PATHS},
                "peers": {farm_name(peer): {"dnsName": hostname(peer), "imports": [exports(peer)],
                                            "paths": {name: f"{overlay(name, peer)}:{PAIR_PORT}" for name in PATHS}}
                          for peer in FARMS if farm != peer}
            }
        }))
        pid = self.gateways[path, farm]
        self.start(f"federation-{path}-{farm}", "nsenter", "-t", str(pid), "-n", "--", "nice", "-n", "10",
                   ROOT / "bin/ocean-federation", "-config", config)

    def records(self, farm, store, kind):
        root = f"/ocean/v1/regions/{farm_name(farm)}/federation/{kind}/"
        records = json.loads(self.etcdctl(store, "get", "--prefix", "--write-out=json", root))
        return {base64.b64decode(row["key"]).decode()[len(root):]: row for row in records.get("kvs", [])}

    def rejected(self, certificate, routes):
        offer = json.dumps({"farm": "farm-1", "pairId": pair_id(1, 2), "path": PATHS[0], "routes": routes})
        reply = self.gateway(PATHS[0], 1, "curl", "--silent", "--max-time", "5", "--output", "/dev/null",
                             "--interface", overlay(PATHS[0], 1), "--cacert", self.directory / "federation-ca.pem",
                             "--cert", certificate.with_suffix(".pem"), "--key", certificate.with_suffix(".key"),
                             "--resolve", f"{hostname(2)}:{PAIR_PORT}:{overlay(PATHS[0], 2)}", "--write-out", "%{http_code}",
                             "--header", "Content-Type: application/json", "--data", offer,
                             f"https://{hostname(2)}:{PAIR_PORT}/ocean/federation/v1/pairings/farm-1")
        if reply != "403":
            raise RuntimeError(f"unexpected authorization response {reply}")


def pair_id(a, b):
    first, second = sorted((farm_name(a), farm_name(b)))
    return hashlib.sha256(f"ocean/farm-pair/v1\0{first}\0{second}".encode()).hexdigest()[:32]


def probe(lab, output):
    lab.mesh()
    for path in PATHS:
        lab.gateway(path, 1, "ping", "-q", "-c", "1", "-W", "2", "-I", overlay(path, 1), overlay(path, 2))
    for port in (5353, 5354):
        lab.dns(port)
    store_ca, _ = lab.ca("storage-ca"), lab.ca("federation-ca")
    stores = {farm: lab.local_cluster(farm, store_ca) for farm in FARMS}
    certificates = {}
    for farm in FARMS:
        for path in PATHS:
            certificates[path, farm] = lab.certificate(f"{farm_name(farm)}-{path}", "federation-ca",
                                                       f"DNS:{hostname(farm)},URI:spiffe://ocean/farms/{farm_name(farm)}")
            lab.federation(path, farm, stores[farm], certificates[path, farm])

    def all_live():
        return all(len(lab.records(farm, stores[farm], "paths")) == 6 for farm in FARMS)

    first_ms = wait(all_live)
    if any(lab.processes[f"dns-{port}"].poll() is not None for port in (5353, 5354)):
        raise RuntimeError("both DNS processes must be serving before the fault probes")
    originals = {farm: lab.records(farm, stores[farm], "pairs") for farm in FARMS}
    for farm, records in originals.items():
        if len(records) != 3:
            raise RuntimeError(f"unexpected pairing count in {farm_name(farm)}")
        for peer in FARMS:
            if peer == farm:
                continue
            value = json.loads(base64.b64decode(records[farm_name(peer)]["value"]))
            if value["id"] != pair_id(farm, peer) or value["routes"] != [exports(peer)]:
                raise RuntimeError("the paired route differs from the configured policy")
    for path in PATHS:
        mark = PATHS.index(path) + 11
        lab.gateway(path, 1, "ping", "-q", "-c", "1", "-W", "2", "-I", f"10.246.1.{mark}", f"10.246.2.{mark}")
    lab.rejected(certificates[PATHS[0], 1], ["10.250.99.0/24"])
    lab.gateway(PATHS[0], 1, "ip", "route", "add", "10.250.99.1/32", "dev", "mesh0")
    try:
        lab.gateway(PATHS[0], 1, "ping", "-q", "-c", "1", "-W", "2", "10.250.99.1")
    except subprocess.CalledProcessError:
        pass
    else:
        raise RuntimeError("an unapproved prefix was routed through WireGuard")
    intruder = lab.certificate("unapproved", "federation-ca", "DNS:unapproved.ocean.test,URI:spiffe://ocean/farms/unapproved")
    lab.rejected(intruder, [exports(1)])
    stop(lab.processes["dns-5353"])
    path_loss = time.monotonic()
    run("ip", "link", "set", PATHS[0], "down")

    def backup_only():
        return all(set(lab.records(farm, stores[farm], "paths")) ==
                   {f"{farm_name(peer)}/{PATHS[1]}" for peer in FARMS if peer != farm} for farm in FARMS)

    wait(backup_only)
    loss_ms = round((time.monotonic() - path_loss) * 1000)
    for farm in FARMS:
        if not lab.management_ready(farm, stores[farm]):
            raise RuntimeError("local management lost readiness during WAN failure")
    run("ip", "link", "set", PATHS[0], "up")
    restore_ms = wait(all_live)
    for farm, records in originals.items():
        if lab.records(farm, stores[farm], "pairs") != records:
            raise RuntimeError("reconnecting a path replaced a durable pairing")

    failed = 4
    site_loss = time.monotonic()
    for path in PATHS:
        stop(lab.processes[f"federation-{path}-{failed}"])
    for voter in range(1, 4):
        stop(lab.processes[f"store-{failed}-voter-{voter}"])

    def survivors():
        active = [farm for farm in FARMS if farm != failed]
        for farm in active:
            try:
                ready = lab.management_ready(farm, stores[farm])
            except subprocess.SubprocessError as err:
                raise RuntimeError(f"could not reach surviving management for {farm_name(farm)}") from err
            if not ready:
                raise RuntimeError("surviving management endpoint lost readiness")
        return all(set(lab.records(farm, stores[farm], "paths")) ==
                   {f"{farm_name(peer)}/{path}" for peer in active if peer != farm for path in PATHS} for farm in active)

    wait(survivors)
    site_loss_ms = round((time.monotonic() - site_loss) * 1000)
    for farm in (farm for farm in FARMS if farm != failed):
        if lab.records(farm, stores[farm], "pairs") != originals[farm]:
            raise RuntimeError("the site outage changed surviving durable pair records")
    output.write_text(json.dumps({"farms": 4, "votersPerFarm": 3, "pairedFarmPairs": 6, "durablePairRecords": 12,
                                  "initialPathRecords": 24, "backupDNSAvailable": True, "unapprovedOfferHTTP": 403,
                                  "unapprovedIdentityHTTP": 403, "approvedPrefixPingBothPaths": True, "unapprovedPrefixPingRejected": True,
                                  "firstAllPathsMilliseconds": first_ms, "pathWithdrawalMilliseconds": loss_ms,
                                  "pathRecoveryMilliseconds": restore_ms, "farmWithdrawalMilliseconds": site_loss_ms,
                                  "localManagementReadyAfterFarmLoss": True, "pairingRecordsUnchanged": True}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("etcd", "etcdctl", "wg", "dnsmasq"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[2] != "1":
        raise SystemExit("run the probe in a new user and network namespace")
    with tempfile.TemporaryDirectory(prefix="ocean-mesh-") as work, ExitStack() as cleanup:
        directory = Path(work)
        try:
            probe(Lab(args, directory, cleanup), args.output)
        except Exception as err:
            if isinstance(err, subprocess.CalledProcessError) and err.stderr:
                print(err.stderr, flush=True)
            for log in directory.glob("*.log"):
                text = log.read_text(errors="replace")
                if text and not log.name.startswith("store-"):
                    print(f"--- {log.name} ---\n{text[-1500:]}", flush=True)
            raise


if __name__ == "__main__":
    main()
