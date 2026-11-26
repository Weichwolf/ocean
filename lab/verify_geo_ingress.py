#!/usr/bin/env python3
"""Exercise two public HTTPS edges over the routed four-farm WireGuard lab."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from verify_farm_pairing import PATHS, ROOT, Lab, farm_name, farm_policy, run, stop, wait


HOST = "app.geo.ocean.test"
ZONE = "geo.ocean.test"
PORT = 8443
ORIGIN_PORT = 9443
WORKLOAD_MTU = "1420"
EDGES = {3: "192.0.2.13", 4: "192.0.2.14"}
DNS = {1: "192.0.2.53", 2: "192.0.2.54"}

ORIGIN = """
import http.server, ssl, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        valid = self.headers.get('Host', '').split(':', 1)[0] == sys.argv[5]
        if self.path == '/readyz':
            status, body = (200 if valid else 421), b''
        elif self.path == '/payload?lab=geo':
            valid = (valid and self.headers.get('X-Forwarded-For') == '192.0.2.100'
                     and self.headers.get('X-Forwarded-Proto') == 'https'
                     and self.headers.get('X-Forwarded-Host') == sys.argv[5]
                     and self.headers.get('Forwarded') is None)
            status, body = (200 if valid else 421), sys.argv[4].encode()
        else:
            status, body = 404, b''
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

server = http.server.ThreadingHTTPServer((sys.argv[1], 9443), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"""


def launch_in(lab, pid, name, *command):
    return lab.start(name, "nsenter", "-t", str(pid), "-n", "--", "nice", "-n", "10", *command)


def origin(lab, farm, cert):
    pid = lab.clients[farm]
    lab.in_namespace(pid, "ip", "link", "set", "dev", "work0", "mtu", WORKLOAD_MTU)
    return launch_in(lab, pid, f"tls-origin-{farm}", "python3", "-B", "-c", ORIGIN,
                     origin_ip(farm), cert.with_suffix(".pem"), cert.with_suffix(".key"), farm_name(farm), HOST)


def origin_ip(farm):
    return f"10.246.{farm}.100"


def start_authority(lab, farm, address):
    pid = lab.namespace(f"authority-{farm}")
    lab.attach_network(pid, f"pubdns{farm}", "public0", "public", f"{address}/24")
    return launch_in(lab, pid, f"dns-geo-{farm}", lab.args.dnsmasq, "--no-daemon", "--bind-interfaces",
                     "--conf-file=/dev/null", "--no-resolv", "--no-hosts", "--port=5353", "--log-facility=-",
                     f"--auth-server=ns{farm}.{ZONE},public0", f"--auth-zone={ZONE},192.0.2.0/24", "--auth-ttl=60",
                     f"--auth-sec-servers=ns{3 - farm}.{ZONE}",
                     *(f"--host-record={HOST},{edge}" for edge in EDGES.values()),
                     *(f"--host-record=ns{site}.{ZONE},{ip}" for site, ip in DNS.items()))


def start_edge(lab, farm, address, origins, certificate):
    pid = lab.namespace(f"edge-{farm}")
    lab.attach_network(pid, f"pubedge{farm}", "public0", "public", f"{address}/24")
    lab.attach_network(pid, f"rteedge{farm}", "work0", f"work{farm}", f"10.246.{farm}.101/24")
    lab.in_namespace(pid, "ip", "link", "set", "dev", "work0", "mtu", WORKLOAD_MTU)
    for peer in origins:
        lab.in_namespace(pid, "ip", "route", "add", f"{origin_ip(peer)}/32", "via", f"10.246.{farm}.1")

    def origins_ready():
        return all(lab.in_namespace(pid, "curl", "--noproxy", "*", "--silent", "--show-error", "--fail", "--max-time", "1",
                                    "--cacert", ca, "--resolve", f"{HOST}:{ORIGIN_PORT}:{origin_ip(peer)}",
                                    "--write-out", "%{http_code}", f"https://{HOST}:{ORIGIN_PORT}/readyz") == "200"
                   for peer, ca in origins.items())

    wait(origins_ready, 10)
    config = {"policy": farm_policy(farm), "listen": f"{address}:{PORT}", "hostname": HOST,
              "certificateFile": str(certificate), "healthPath": "/readyz",
              "origins": {farm_name(peer): {"address": f"{origin_ip(peer)}:{ORIGIN_PORT}", "caFile": str(ca)}
                          for peer, ca in origins.items()}}
    spec = lab.directory / f"edge-{farm}.json"
    spec.write_text(json.dumps(config))
    renderer = ROOT / "bin/ocean-geo-ingress"
    rendered = lab.directory / f"edge-{farm}.conf"
    rendered.write_text(run(renderer, "-config", spec) + "\n")
    run(lab.args.haproxy, "-c", "-f", rendered)
    config["origins"]["farm-1"]["address"] = f"{origin_ip(3)}:{ORIGIN_PORT}"
    invalid_spec = lab.directory / f"edge-{farm}-invalid.json"
    invalid_spec.write_text(json.dumps(config))
    rejected = subprocess.run([renderer, "-config", invalid_spec], capture_output=True, text=True, check=False, timeout=5)
    if rejected.returncode != 1 or "outside its approved routes" not in rejected.stderr:
        raise RuntimeError("the geo ingress renderer accepted an origin outside its approved routing policy")
    launch_in(lab, pid, f"haproxy-{farm}", lab.args.haproxy, "-db", "-f", rendered)


def verify(lab):
    lab.mesh()
    lab.routed_farms()
    lab.bridge("public")
    client = lab.namespace("public-client")
    lab.attach_network(client, "pubclient", "public0", "public", "192.0.2.100/24")
    public_ca = lab.directory / (lab.ca("public-ca") + ".pem")
    origin_cas = {}
    for farm in (1, 2):
        ca_name = lab.ca(f"origin-ca-{farm}")
        origin_cas[farm] = lab.directory / (ca_name + ".pem")
        origin(lab, farm, lab.certificate(f"origin-{farm}", ca_name, f"DNS:{HOST}"))
    authorities = {farm: start_authority(lab, farm, address) for farm, address in DNS.items()}
    for farm, address in EDGES.items():
        cert = lab.certificate(f"edge-cert-{farm}", "public-ca", f"DNS:{HOST}")
        bundle = lab.directory / f"edge-{farm}-bundle.pem"
        bundle.write_bytes(cert.with_suffix(".pem").read_bytes() + cert.with_suffix(".key").read_bytes())
        bundle.chmod(0o600)
        start_edge(lab, farm, address, origin_cas, bundle)

    def answers(authority):
        response = lab.in_namespace(client, "dig", "+norecurse", "+noall", "+comments", "+answer", "+time=1", "+tries=1",
                                    "-p", "5353", f"@{authority}", HOST, "A")
        if ";; flags: qr aa;" not in response:
            raise RuntimeError(f"the DNS reply is not authoritative: {response}")
        records = {line.split()[4]: int(line.split()[1]) for line in response.splitlines()
                   if line.startswith(f"{HOST}.")}
        if records != dict.fromkeys(EDGES.values(), 60):
            raise RuntimeError(f"unexpected public DNS data: {records}")
        return records

    def https(address, *extra):
        reply = lab.in_namespace(client, "curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "2",
                                 "--write-out", "\n%{http_code}", "--cacert", public_ca,
                                 "--resolve", f"{HOST}:{PORT}:{address}", "-H", "X-Forwarded-For: 192.0.2.250",
                                 "-H", "Forwarded: for=192.0.2.250", *extra, f"https://{HOST}:{PORT}/payload?lab=geo")
        body, status = reply.rsplit("\n", 1)
        return body.strip(), int(status)

    def both_origins():
        return all({https(address) for _ in range(4)} == {("farm-1", 200), ("farm-2", 200)} for address in EDGES.values())

    cached = answers(DNS[1])
    answers(DNS[2])
    wait(both_origins, 12)
    if https(EDGES[3], "-H", "Host: unapproved.ocean.test")[1] != 421:
        raise RuntimeError("the ingress accepted an unapproved HTTP host")

    def observe(address, refresh):
        attempts, early_errors = 0, 0
        recovered_ms = None
        while time.monotonic() - failed_at < 6:
            attempts += 1
            try:
                if refresh:
                    answers(DNS[2])
                body, status = https(address)
            except subprocess.SubprocessError:
                body, status = "", 0
            if (body, status) == ("farm-2", 200):
                if recovered_ms is None:
                    recovered_ms = round((time.monotonic() - failed_at) * 1000)
            elif status in (0, 502, 503, 504) and recovered_ms is None:
                early_errors += 1
            else:
                raise RuntimeError(f"geo ingress {address} returned {status} {body!r} during farm loss")
            time.sleep(0.15)
        if recovered_ms is None or recovered_ms > 2_500 or attempts < 10:
            raise RuntimeError(f"geo ingress {address} did not recover in the lab window")
        return {"address": address, "lookup": "fresh" if refresh else "cached", "requests": attempts,
                "failedBeforeRecovery": early_errors, "firstSurvivingResponseMilliseconds": recovered_ms}

    failed_at = time.monotonic()
    for path in PATHS:
        lab.gateway(path, 1, "ip", "link", "set", "wan0", "down")
    stop(lab.processes["tls-origin-1"])
    stop(lab.processes["http-1"])
    stop(authorities[1])
    with ThreadPoolExecutor(max_workers=4) as probes:
        results = [probes.submit(observe, address, fresh) for address in cached for fresh in (False, True)]
        measurements = [result.result() for result in results]
    if not all(lab.unreachable(farm, 1) for farm in EDGES):
        raise RuntimeError("the failed farm's route is still reachable from the ingress fabrics")

    stop(lab.processes["tls-origin-2"])
    wrong_hostname = "unapproved.ocean.test"
    untrusted = lab.certificate("wrong-origin-2", "origin-ca-2", f"DNS:{wrong_hostname}")
    origin(lab, 2, untrusted)

    def wrong_origin_live():
        return lab.in_namespace(lab.clients[2], "curl", "--noproxy", "*", "--silent", "--show-error", "--fail",
                                "--max-time", "1", "--cacert", origin_cas[2], "-H", f"Host: {HOST}",
                                "--resolve", f"{wrong_hostname}:{ORIGIN_PORT}:{origin_ip(2)}", "--write-out", "%{http_code}",
                                f"https://{wrong_hostname}:{ORIGIN_PORT}/readyz") == "200"

    wait(wrong_origin_live, 6)

    def rejected_wrong_origin():
        return all(https(address)[1] == 503 for address in EDGES.values())

    wait(rejected_wrong_origin, 6)
    time.sleep(1.2)
    if not (wrong_origin_live() and rejected_wrong_origin()):
        raise RuntimeError("the edges did not sustain rejection of the live origin with a different TLS name")
    return {"failedFarm": "farm-1", "cacheTTLSeconds": 60, "unchangedPublicAddresses": list(cached),
            "authoritativeDNS": list(DNS.values()), "survivingAuthority": DNS[2], "survivingOrigin": "farm-2",
            "clients": measurements, "wrongOriginCertificateRejected": True, "unapprovedOriginRouteRejected": True,
            "unapprovedHTTPHostRejected": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wg", "bird", "birdc", "dnsmasq", "haproxy", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[2] != "1":
        raise SystemExit("run the probe in a new user and network namespace")
    with tempfile.TemporaryDirectory(prefix="ocean-geo-ingress-") as work, ExitStack() as cleanup:
        directory = Path(work)
        try:
            result = verify(Lab(args, directory, cleanup))
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        except Exception as err:
            if isinstance(err, subprocess.CalledProcessError) and err.stderr:
                print(err.stderr, flush=True)
            for log in directory.glob("*.log"):
                message = log.read_text(errors="replace")
                if message:
                    print(f"--- {log.name} ---\n{message[-1000:]}", flush=True)
            raise


if __name__ == "__main__":
    main()
