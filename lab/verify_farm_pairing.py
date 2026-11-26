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


def fabric(farm, host):
    return f"10.247.{farm}.{host}"


def farm_policy(farm):
    return {
        "farm": farm_name(farm), "dnsName": hostname(farm), "exports": [exports(farm)],
        "localPaths": {path: f"{overlay(path, farm)}:{PAIR_PORT}" for path in PATHS},
        "peers": {farm_name(peer): {"dnsName": hostname(peer), "imports": [exports(peer)],
                                    "paths": {path: f"{overlay(path, peer)}:{PAIR_PORT}" for path in PATHS}}
                  for peer in FARMS if farm != peer},
    }


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
        self.routers = {}
        self.clients = {}

    def start(self, name, *command):
        with (self.directory / f"{name}.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log,
                                       env={**os.environ, "GOMAXPROCS": "2"})
        self.cleanup.callback(stop, process)
        self.processes[name] = process
        return process

    def gateway(self, path, farm, *command):
        return self.in_namespace(self.gateways[path, farm], *command)

    @staticmethod
    def in_namespace(pid, *command):
        return run("nsenter", "-t", str(pid), "-n", "--", *command)

    def namespace(self, name):
        guest = self.start(name, "unshare", "--net", "sleep", "infinity")
        own = os.stat("/proc/self/ns/net").st_ino
        wait(lambda: os.stat(f"/proc/{guest.pid}/ns/net").st_ino != own, 3)
        self.in_namespace(guest.pid, "ip", "link", "set", "lo", "up")
        return guest.pid

    def bridge(self, name, address=None):
        run("ip", "link", "add", name, "type", "bridge")
        if address:
            run("ip", "addr", "add", address, "dev", name)
        run("ip", "link", "set", name, "up")

    def attach(self, path, farm, device, bridge, address):
        peer = f"ovs{PATHS.index(path)}{farm}{device[0]}"
        self.attach_network(self.gateways[path, farm], peer, device, bridge, address)

    def attach_network(self, pid, peer, device, bridge, address):
        run("ip", "link", "add", peer, "type", "veth", "peer", "name", device, "netns", str(pid))
        run("ip", "link", "set", peer, "master", bridge)
        run("ip", "link", "set", peer, "up")
        self.in_namespace(pid, "ip", "addr", "add", address, "dev", device)
        self.in_namespace(pid, "ip", "link", "set", device, "up")

    def mesh(self):
        run("ip", "link", "set", "lo", "up")
        for farm in FARMS:
            self.bridge(f"mgmt{farm}", mgmt(farm) + "/24")
        for path in PATHS:
            self.bridge(path)
        keys = {}
        for path in PATHS:
            for farm in FARMS:
                self.gateways[path, farm] = self.namespace(f"namespace-{path}-{farm}")
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
                if not self.args.bird:
                    self.gateway(path, farm, "ip", "addr", "add", f"10.246.{farm}.{11 + PATHS.index(path)}/32", "dev", "lo")
                fields = ["listen-port", "51820", "private-key", str(keys[path, farm][0])]
                routes = []
                for peer in FARMS:
                    if peer == farm:
                        continue
                    targets = [overlay(path, peer) + "/32", exports(peer)]
                    routes.extend(targets[:1] if self.args.bird else targets)
                    fields.extend(["peer", keys[path, peer][1], "endpoint", underlay(path, peer) + ":51820",
                                   "allowed-ips", ",".join(targets)])
                self.gateway(path, farm, self.args.wg, "set", "mesh0", *fields)
                self.gateway(path, farm, "ip", "link", "set", "mesh0", "up")
                for route in routes:
                    self.gateway(path, farm, "ip", "route", "add", route, "dev", "mesh0")

    def start_bird(self, name, pid, site, *selection):
        config = self.directory / f"{name}.conf"
        config.write_text(run(ROOT / "bin/ocean-federation-routes", "-config", site, *selection) + "\n")
        run(self.args.bird, "-p", "-c", config)
        self.start(name, "nsenter", "-t", str(pid), "-n", "--", "nice", "-n", "10", self.args.bird,
                   "-f", "-c", config, "-s", self.directory / f"{name}.ctl", "-P", self.directory / f"{name}.pid")

    def routed_farms(self):
        for farm in FARMS:
            self.bridge(f"fabric{farm}")
            self.bridge(f"work{farm}")
            site = self.directory / f"routing-{farm}.json"
            site.write_text(json.dumps({
                "policy": farm_policy(farm), "farmAS": 64512 + farm, "fabricAS": 64700 + farm,
                "peerAS": {farm_name(peer): 64512 + peer for peer in FARMS if peer != farm},
                "fabricNetwork": fabric(farm, 0) + "/24", "fabricLink": "fabric0", "exportLinks": ["work0"],
                "routers": [fabric(farm, 20)], "preferredPath": PATHS[0],
                "gateways": {path: {"fabricAddress": fabric(farm, 11 + index), "wireGuardLink": "mesh0"}
                             for index, path in enumerate(PATHS)},
            }))
            router = self.namespace(f"router-{farm}")
            client = self.namespace(f"workload-{farm}")
            self.routers[farm], self.clients[farm] = router, client
            self.attach_network(router, f"lanr{farm}", "fabric0", f"fabric{farm}", fabric(farm, 20) + "/24")
            self.attach_network(router, f"workr{farm}", "work0", f"work{farm}", f"10.246.{farm}.1/24")
            self.attach_network(client, f"workc{farm}", "work0", f"work{farm}", f"10.246.{farm}.100/24")
            self.in_namespace(client, "ip", "route", "add", "default", "via", f"10.246.{farm}.1")
            self.in_namespace(router, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            self.start_bird(f"bird-router-{farm}", router, site, "-router", fabric(farm, 20))
            webroot = self.directory / f"http-{farm}"
            webroot.mkdir()
            (webroot / "index.html").write_text(farm_name(farm))
            self.start(f"http-{farm}", "nsenter", "-t", str(client), "-n", "--", "nice", "-n", "10",
                       "python3", "-B", "-m", "http.server", "8080", "--bind", f"10.246.{farm}.100", "--directory", webroot)
            for index, path in enumerate(PATHS):
                self.attach(path, farm, "fabric0", f"fabric{farm}", fabric(farm, 11 + index) + "/24")
                self.gateway(path, farm, "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
                self.start_bird(f"bird-{path}-{farm}", self.gateways[path, farm], site, "-path", path)

    def next_hop(self, farm, peer):
        routes = json.loads(self.in_namespace(self.routers[farm], "ip", "-4", "-j", "route", "get", f"10.246.{peer}.100"))
        return routes[0].get("gateway")

    def routed_http(self, source, target):
        return self.in_namespace(self.clients[source], "curl", "--noproxy", "*", "--silent", "--show-error", "--fail",
                                 "--max-time", "0.6", f"http://10.246.{target}.100:8080/")

    def http_uses_gateway(self, source, target, next_hop):
        return self.next_hop(source, target) == next_hop and self.routed_http(source, target) == farm_name(target)

    def unreachable(self, farm, peer):
        routes = json.loads(self.in_namespace(self.routers[farm], "ip", "-4", "-j", "route", "show", "exact", exports(peer)))
        return len(routes) == 1 and routes[0].get("type") == "unreachable"

    def reject_route_leak(self):
        unapproved = "10.250.99.0/24"
        sender, receiver = "bird-wan-a-2", "bird-wan-a-1"
        original = self.directory / f"{sender}.conf"
        text = original.read_text()
        permitted = f"net ~ [{exports(2)}] && source != RTS_STATIC"
        changed = text.replace(f"if {permitted} then accept;", f"if ({permitted}) || net = {unapproved} then accept;")
        if changed == text:
            raise RuntimeError("could not prepare the unapproved advertisement")
        leak = self.directory / "unapproved-export.conf"
        leak.write_text(changed + f'\nprotocol static lab_leak {{ ipv4; route {unapproved} blackhole; }}\n')

        def control(host, command):
            return run(self.args.birdc, "-s", self.directory / f"{host}.ctl", command)

        def filtered_updates():
            status = control(receiver, "show protocols all peer_0")
            line = next(row for row in status.splitlines() if row.strip().startswith("Import updates:"))
            return int(line.split(":", 1)[1].split()[2])

        baseline = filtered_updates()
        run(self.args.bird, "-p", "-c", leak)
        control(sender, f'configure "{leak}"')
        try:
            wait(lambda: unapproved in control(sender, "show route export peer_0") and filtered_updates() > baseline, 6)
            gateway = self.gateway(PATHS[0], 1, "ip", "-4", "route", "show", "exact", unapproved)
            router = self.in_namespace(self.routers[1], "ip", "-4", "route", "show", "exact", unapproved)
            if gateway or router:
                raise RuntimeError("the unapproved BGP advertisement reached the Linux FIB")
        finally:
            control(sender, f'configure "{original}"')

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
            "policy": farm_policy(farm),
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


def http_recovery(lab, start, path):
    attempts, failures = 0, 0
    def working():
        nonlocal attempts, failures
        attempts += 1
        try:
            response = lab.routed_http(1, 2)
        except subprocess.CalledProcessError:
            failures += 1
            return False
        return response == "farm-2" and lab.next_hop(1, 2) == fabric(1, 11 + PATHS.index(path))
    wait(working, 6 - (time.monotonic() - start))
    elapsed = time.monotonic() - start
    if elapsed > 6:
        raise RuntimeError(f"HTTP on {path} exceeded the six-second convergence deadline")
    return {"milliseconds": round(elapsed * 1000), "attempts": attempts, "failedRequests": failures}


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
    route_measurements = None
    if lab.args.bird:
        lab.routed_farms()
        def primary_routes():
            return all(lab.http_uses_gateway(farm, peer, fabric(farm, 11))
                       for farm in FARMS for peer in FARMS if farm != peer)
        warmup_ms = wait(primary_routes)
        lab.reject_route_leak()
        gateway_loss = time.monotonic()
        stop(lab.processes["bird-wan-a-1"])
        gateway_recovery = http_recovery(lab, gateway_loss, PATHS[1])
        site = lab.directory / "routing-1.json"
        lab.start_bird("bird-wan-a-1", lab.gateways[PATHS[0], 1], site, "-path", PATHS[0])
        gateway_failback = http_recovery(lab, time.monotonic(), PATHS[0])
        route_measurements = {"routedPairs": 12, "unapprovedBGPAdvertisementFiltered": True, "primaryPathsReadyMilliseconds": warmup_ms,
                              "gatewayFailover": gateway_recovery, "gatewayFailback": gateway_failback}
    else:
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
    if route_measurements is not None:
        route_measurements["wanFailover"] = http_recovery(lab, path_loss, PATHS[1])

    def backup_only():
        return all(set(lab.records(farm, stores[farm], "paths")) ==
                   {f"{farm_name(peer)}/{PATHS[1]}" for peer in FARMS if peer != farm} for farm in FARMS)

    wait(backup_only)
    loss_ms = round((time.monotonic() - path_loss) * 1000)
    for farm in FARMS:
        if not lab.management_ready(farm, stores[farm]):
            raise RuntimeError("local management lost readiness during WAN failure")
    run("ip", "link", "set", PATHS[0], "up")
    if route_measurements is not None:
        route_measurements["wanFailback"] = http_recovery(lab, time.monotonic(), PATHS[0])
    restore_ms = wait(all_live)
    for farm, records in originals.items():
        if lab.records(farm, stores[farm], "pairs") != records:
            raise RuntimeError("reconnecting a path replaced a durable pairing")

    failed = 4
    site_loss = time.monotonic()
    if route_measurements is not None:
        for path in PATHS:
            lab.gateway(path, failed, "ip", "link", "set", "wan0", "down")
        def no_site_route():
            if lab.routed_http(1, 2) != "farm-2":
                raise RuntimeError("the independent workload stopped serving during a peer farm outage")
            return all(lab.unreachable(farm, failed) for farm in FARMS if farm != failed)
        wait(no_site_route, 6)
        route_measurements["failedFarmRoutesUnreachableMilliseconds"] = round((time.monotonic() - site_loss) * 1000)
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
    proof = {"farms": 4, "votersPerFarm": 3, "pairedFarmPairs": 6, "durablePairRecords": 12,
                                  "initialPathRecords": 24, "backupDNSAvailable": True, "unapprovedOfferHTTP": 403,
                                  "unapprovedIdentityHTTP": 403, "unapprovedPrefixPingRejected": True,
                                  "firstAllPathsMilliseconds": first_ms, "pathWithdrawalMilliseconds": loss_ms,
                                  "pathRecoveryMilliseconds": restore_ms, "farmWithdrawalMilliseconds": site_loss_ms,
                                  "localManagementReadyAfterFarmLoss": True, "pairingRecordsUnchanged": True}
    if route_measurements is None:
        proof["approvedPrefixPingBothPaths"] = True
    else:
        proof["routing"] = route_measurements
    output.write_text(json.dumps(proof, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("etcd", "etcdctl", "wg", "dnsmasq"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bird", type=Path)
    parser.add_argument("--birdc", type=Path)
    args = parser.parse_args()
    if bool(args.bird) != bool(args.birdc):
        parser.error("the routing probe requires both bird and birdc")
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
