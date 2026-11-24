#!/usr/bin/env python3
"""Exercise host credentials and agent recovery from the enrolling guest."""

import argparse
import base64
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=5).stdout


def request(config, method, body=None, token=None, identity=None, discard=False):
    origin = urlsplit(config["origin"])
    tls = ssl.create_default_context(cafile=config["caFile"])
    if identity is not None:
        tls.load_cert_chain(*identity)
    connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443, context=tls, timeout=6)
    route = "/ocean/hosts/" + config["hostId"]
    headers = {"Content-Type": "application/json", "Connection": "close"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if method == "POST":
        route += "/enrollment"
    try:
        connection.request(method, route, None if body is None else json.dumps(body).encode(), headers)
        with connection.getresponse() as response:
            return response.status, None if discard else json.load(response)
    finally:
        connection.close()


def invalid(response, status, code):
    if response[0] != status or response[1].get("error") != code:
        raise RuntimeError(f"the enrollment API did not return {status} {code}")


def csr(key):
    result = command("openssl", "req", "-new", "-key", str(key), "-keyform", "DER", "-subj", "/CN=ocean-host", "-outform", "DER")
    return base64.b64encode(result).decode()


def actual_report(interface):
    interfaces = json.loads(command("ip", "-4", "-j", "address", "show", "dev", interface))
    if len(interfaces) != 1 or len(interfaces[0]["addr_info"]) != 1:
        raise RuntimeError("the management interface did not have one assigned IPv4 address")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    meminfo = Path("/proc/meminfo").read_text().splitlines()
    memory = next(int(line.split()[1]) // 1024 for line in meminfo if line.startswith("MemTotal:"))
    mac = (Path("/sys/class/net") / interface / "address").read_text().strip()
    return {"mac": mac, "address": interfaces[0]["addr_info"][0]["local"], "cpu": os.cpu_count(),
            "memoryMiB": memory, "os": release["ID"].strip('"'), "osVersion": release["VERSION_ID"].strip('"'),
            "rootlessPodman": True, "kvm": os.access("/dev/kvm", os.R_OK | os.W_OK)}


def register(config, directory):
    token = Path(config["tokenFile"]).read_text().strip()
    key = Path(config["stateDirectory"]) / "identity.key"
    report = actual_report(config["managementInterface"])
    body = {"csr": csr(key), "report": report}
    invalid(request(config, "POST", body), 401, "InvalidEnrollmentCredential")
    invalid(request(config, "GET"), 401, "HostCertificateRequired")
    invalid(request(config, "POST", dict(body, csr="AQID"), token), 400, "InvalidHostKeyProof")
    invalid(request(config, "POST", dict(body, report=dict(report, memoryMiB=1)), token), 422, "HostQualificationFailed")
    if request(config, "POST", body, token, discard=True)[0] != 201:
        raise RuntimeError("the first valid enrollment did not create one regional host")
    alternative = Path(directory) / "alternative.key"
    command("openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(alternative))
    invalid(request(config, "POST", dict(body, csr=csr(alternative)), token), 403, "HostIdentityDenied")
    return {"hostId": config["hostId"], "initialResponseDiscarded": True, "macOnlyDenied": True,
            "wrongKeyDenied": True, "unqualifiedDenied": True, "invalidCSRDenied": True, "report": report}


def check(config, directory, revoked):
    state = Path(config["stateDirectory"])
    cert = Path(directory) / "identity.pem"
    key = Path(directory) / "key.pem"
    command("openssl", "x509", "-inform", "DER", "-in", str(state / "identity.crt"), "-out", str(cert))
    command("openssl", "pkey", "-inform", "DER", "-in", str(state / "identity.key"), "-out", str(key))
    response = request(config, "GET", identity=(cert, key))
    if revoked:
        invalid(response, 403, "HostIdentityDenied")
        return {"revokedCertificateDenied": True}
    if response[0] != 200 or response[1]["hostId"] != config["hostId"] or response[1]["roles"] != ["compute"]:
        raise RuntimeError("the agent certificate did not confirm the approved identity")
    stored = (state / "identity.crt").read_bytes()
    if base64.b64decode(response[1]["certificate"]) != stored:
        raise RuntimeError("the recovered certificate differs from the regional identity")
    return {"hostCertificateSHA256": hashlib.sha256(stored).hexdigest(), "mTLSConfirmed": True,
            "pool": response[1]["pool"], "cell": response[1]["cell"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("register", "verify", "revoked"))
    args = parser.parse_args()
    config = json.loads(Path("/etc/ocean-agent/config.json").read_text())["enrollment"]
    with tempfile.TemporaryDirectory(prefix="ocean-host-check-") as directory:
        result = register(config, directory) if args.stage == "register" else check(config, directory, args.stage == "revoked")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
