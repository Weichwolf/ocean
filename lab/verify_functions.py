#!/usr/bin/env python3
"""Verify Linux HTTP Functions on real lab guests through the pinned Azure CLI."""

import argparse
import json
import secrets
import shlex
import sys
import time
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from prepare_application_gateway import GATEWAYS, NAMESPACE as HTTPS
from region import OPERATOR, ROOT, etcdctl, eventually, ssh, upload
from verify_egress_hosts import SOURCE_SERVER, gateway_files, require
from verify_https_hosts import DEST as HTTPS_FILES, PROBE, cleanup_probe, configure_probe
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_operations import verify_workload_create
from verify_wireguard_hosts import macvlan

CUSTOMER = "farm-1-customer"
EGRESS_NS = "ocean-fx-nat"
EGRESS_UNIT = "ocean-function-egress.service"
EGRESS_FILES = "/opt/ocean-function-egress"
SOURCE_NS = "ocean-fx-source"
SOURCE_UNIT = "ocean-function-source.service"
DEADLINE_SECONDS = 8
NETWORK = "10.89.1.0/24"


def prepare_source(state):
    upload(state, CUSTOMER, {"source.py": SOURCE_SERVER.encode()}, EGRESS_FILES)
    ssh(state, CUSTOMER, f"""set -eu
sudo ip netns add {SOURCE_NS}
sudo ip -n {SOURCE_NS} link set lo up
{macvlan(SOURCE_NS, "customer0", "external0", "198.51.100.30/24", "02:fe:89:20:00:30")}
sudo systemd-run --unit={SOURCE_UNIT} /usr/bin/ip netns exec {SOURCE_NS} /usr/bin/python3 {EGRESS_FILES}/source.py
""")


def configure_egress(state, node, index, ip):
    files = gateway_files(index, ip)
    for name in ("gateway.json", "keepalived.conf", "ocean-fixed-egress.service"):
        files[name] = (files[name].decode()
                       .replace("/opt/ocean-egress-ha", EGRESS_FILES)
                       .replace("ocean-egress", EGRESS_NS)
                       .replace("work0", "fxin0")
                       .replace("external0", "fxout0")
                       .replace("10.84.1.2", "10.89.1.6")
                       .replace("10.84.1.3", "10.89.1.7")
                       .replace("10.84.1.0/24", NETWORK)
                       .replace("10.84.1.1/24", "10.89.1.1/24")).encode()
    files[EGRESS_UNIT] = files.pop("ocean-fixed-egress.service").replace(
        b"--log-console --use-file",
        b"--log-console --pid /run/ocean-fx-nat.pid --vrrp_pid /run/ocean-fx-nat-vrrp.pid --use-file",
    )
    upload(state, node, files, EGRESS_FILES)
    ssh(state, node, f"""set -eu
sudo ip netns add {EGRESS_NS}
sudo ip -n {EGRESS_NS} link set lo up
{macvlan(EGRESS_NS, "work0", "fxin0", f"10.89.1.{6 + index}/24", f"02:fe:89:20:01:0{index + 6}")}
{macvlan(EGRESS_NS, "customer0", "fxout0", f"198.51.100.{12 + index}/24", f"02:fe:89:20:02:{index + 12:02x}")}
sudo ip netns exec {EGRESS_NS} sysctl -q -w net.ipv4.ip_forward=1
sudo {EGRESS_FILES}/bin/ocean-gateway -config {EGRESS_FILES}/gateway.json
sudo install -m 0644 {EGRESS_FILES}/{EGRESS_UNIT} /run/systemd/system/{EGRESS_UNIT}
sudo systemctl daemon-reload
sudo systemctl start {EGRESS_UNIT}
""")


def egress_owns(state, node, ip):
    rows = json.loads(ssh(state, node, f"sudo ip -n {EGRESS_NS} -4 -j address show dev fxout0"))
    return any(address["local"] == ip for link in rows for address in link["addr_info"])


def restore_gateway(state):
    ssh(state, GATEWAYS[0], f"""set -eu
if sudo ip -n {HTTPS} -o -4 address show dev backend0 | grep -q '10.89.1.3/24'; then
    sudo ip -n {HTTPS} addr del 10.89.1.3/24 dev backend0
    sudo ip -n {HTTPS} addr add 10.89.1.1/24 dev backend0
fi
""")


def clean_egress(state):
    for node in GATEWAYS:
        ssh(state, node, f"""set -eu
if sudo test -e /run/systemd/system/{EGRESS_UNIT}; then
    sudo systemctl stop {EGRESS_UNIT}
    sudo unlink /run/systemd/system/{EGRESS_UNIT}
    sudo systemctl daemon-reload
fi
if sudo test -e /run/netns/{EGRESS_NS}; then sudo ip netns del {EGRESS_NS}; fi
""")
    ssh(state, CUSTOMER, f"""set -eu
if sudo test -e /run/netns/{SOURCE_NS}; then
    sudo systemctl stop {SOURCE_UNIT} || true
    sudo ip netns del {SOURCE_NS}
fi
""")
    restore_gateway(state)


def verify(state, parallel_create=False, *, smoke=False):
    source = state / "functions-registry/images.json"
    images = json.loads(source.read_text())
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "functions_cli.py", "application_gateway_cli.py",
                                    "testdata/arm-contract.tsv"))
    upload(state, OPERATOR, {"function-images.json": source.read_bytes()}, CLIENT)
    fixture = f"/tmp/ocean-functions-{uuid4().hex[:12]}.secret"

    def invoke(phase):
        print(f"Functions lab phase {phase}", file=sys.stderr, flush=True)
        cmd = ["python3", f"{CLIENT}/functions_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix",
               f"{CLIENT}/arm-contract.tsv", "--images", f"{CLIENT}/function-images.json", "--fixture", fixture, "--phase", phase]
        if parallel_create and phase == "setup":
            cmd.append("--parallel-create")
        return json.loads(ssh(state, OPERATOR, shlex.join(cmd)))

    probe = False
    restored = False
    egress_started = False

    def cleanup(setup):
        result = invoke("cleanup")
        usage = f"/ocean/v1/regions/farm-1/tenants/{setup['tenant']}/arm/{setup['subscription']}/placement-usage"
        require(json.loads(ssh(state, OPERATOR, etcdctl(f"get {usage} --print-value-only"))) == {"cpuMillis": 0, "memoryMiB": 0},
                "deleting the Functions fixture did not release its capacity")
        return {**result, "quotaReleased": True}

    try:
        setup = invoke("setup")
        retry = verify_workload_create(state, setup, 750, 416) if parallel_create else {}
        authorization = {} if smoke else invoke("authorize")
        integration = invoke("integrate")
        ingress = invoke("publish")
        host, address = setup["host"], ingress["httpsIPv4"]
        configure_probe(state, ingress["certificate"].encode(), CUSTOMER, "customer0", address)
        probe = True
        credential = ssh(state, OPERATOR, f"python3 -c 'import json; print(json.load(open(\"{fixture}\"))[\"key\"])'").strip()
        key_file = "function-key.secret"
        upload(state, CUSTOMER, {key_file: b'header = "x-functions-key: ' + credential + b'"\n'}, HTTPS_FILES)

        def resolve():
            rows = ssh(state, CUSTOMER, shlex.join(["sudo", "ip", "netns", "exec", PROBE, "getent", "ahostsv4", host]))
            require({line.split()[0] for line in rows.decode().splitlines()} == {address}, "the Functions domain did not resolve to the gateway")

        eventually(resolve, 12)

        def request(key=True, suffix="", allow_withdrawal=False):
            auth = ["--config", f"{HTTPS_FILES}/{key_file}"] if key is True else []
            if key is False:
                auth = ["--header", "x-functions-key: " + secrets.token_urlsafe(32)]
            timeout = "2" if allow_withdrawal else "5"
            try:
                result = ssh(state, CUSTOMER, shlex.join(["sudo", "ip", "netns", "exec", PROBE, "curl", "--noproxy", "*",
                    "--silent", "--show-error", "--max-time", timeout, "--cacert", f"{HTTPS_FILES}/ca.pem",
                    "--resolve", f"{host}:443:{address}", *auth, "-w", "\n%{http_code}", f"https://{host}/api/hello{suffix}"]))
            except RuntimeError as error:
                if allow_withdrawal and ("curl: (7)" in str(error) or "curl: (28)" in str(error)):
                    return 0, ""
                raise
            body, status = result.decode().rsplit("\n", 1)
            return int(status), body

        def expect(body, key=True, status=200, suffix=""):
            actual_status, actual_body = request(key, suffix)
            require(actual_status == status and (body is None or actual_body.strip() == body),
                    "the Function probe did not return the expected status and body")

        eventually(lambda: expect("java:v1:unset"), 15)
        expect(None, key=None, status=401)
        expect(None, key=False, status=401)
        https = {"httpsIPv4": address, "gatewayDNSVerified": True, "trustedHTTPS": True,
                 "missingKeyDenied": True, "invalidKeyDenied": True}
        if smoke:
            removed = cleanup(setup)
            restored = True
            return {**setup, **integration, **https, **removed, "fixtureImages": images, "httpsResponse": "java:v1:unset"}
        updates = invoke("update")
        eventually(lambda: expect("java:v2:configured"), 15)
        invoke("stop")

        def stopped():
            status, _ = request(allow_withdrawal=True)
            require(status in (0, 503), "the stopped Function remained reachable through the gateway")
            return "Withdrawn" if status == 0 else "ServiceUnavailable"

        stop_endpoint_state = eventually(stopped, 12)
        invoke("start")
        eventually(lambda: expect("java:v2:configured"), 12)
        invoke("restart")
        eventually(lambda: expect("java:v2:configured"), 12)
        expect(None, key=False, status=401)

        nat = invoke("egress")
        fixed = nat["fixedIPv4"]
        egress_started = True
        ssh(state, GATEWAYS[0], f"sudo ip -n {HTTPS} addr del 10.89.1.1/24 dev backend0 && "
                                f"sudo ip -n {HTTPS} addr add 10.89.1.3/24 dev backend0")
        prepare_source(state)
        for index, node in enumerate(GATEWAYS):
            configure_egress(state, node, index, fixed)
        eventually(lambda: expect(fixed, suffix="?mode=source"), 16)
        owners = [node for node in GATEWAYS if egress_owns(state, node, fixed)]
        require(len(owners) == 1, "the outbound address did not have a single gateway owner")
        survivor = next(node for node in GATEWAYS if node != owners[0])
        started = time.monotonic()
        ssh(state, owners[0], f"sudo systemctl stop {EGRESS_UNIT}")

        def recovered():
            require(egress_owns(state, survivor, fixed), "the standby has not acquired fixed egress")
            expect(fixed, suffix="?mode=source")

        eventually(recovered, DEADLINE_SECONDS)
        elapsed = round((time.monotonic() - started) * 1000)
        require(elapsed <= DEADLINE_SECONDS * 1000, "the Function egress recovery exceeded the lab deadline")
        removed = cleanup(setup)
        restored = True
        return {**setup, **retry, **authorization, **integration, **updates, **nat, **removed, **https, "fixtureImages": images,
                "lifecycleVerified": True, "stoppedEndpointState": stop_endpoint_state, "persistentKeyAfterRestart": True, "observedIPv4Before": fixed,
                "observedIPv4After": fixed, "recoveryMs": elapsed, "deadlineMs": DEADLINE_SECONDS * 1000}
    finally:
        if probe:
            ssh(state, CUSTOMER, f"if sudo test -e {HTTPS_FILES}/function-key.secret; then sudo unlink {HTTPS_FILES}/function-key.secret; fi")
            cleanup_probe(state, CUSTOMER)
        if egress_started:
            clean_egress(state)
        if not restored:
            print(f"The isolated Function fixture state is {fixture} in {OPERATOR}.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--parallel-create", action="store_true")
    args = parser.parse_args()
    state = args.state.resolve()
    result = verify(state, args.parallel_create)
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "http-functions.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Azure CLI and HTTPS verified the native Java Functions lifecycle and fixed egress failover.")


if __name__ == "__main__":
    main()
