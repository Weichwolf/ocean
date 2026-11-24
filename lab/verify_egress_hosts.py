#!/usr/bin/env python3
"""Verify fixed egress through gateway failure and recovery in separate KVM guests."""

import argparse
import ipaddress
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
from region import ROOT, eventually, ssh, upload

GATEWAYS = ("farm-1-node-01", "farm-1-node-02")
WORKER = "farm-1-node-03"
OBSERVER = "farm-1-observer"
OPERATOR = "farm-1-operator"
DEST = "/opt/ocean-egress-ha"
NAMESPACE = "ocean-egress"
PROFILE = ROOT / "lab/profiles/egress-ha.yaml"
LAB = ROOT / "bin/ocean-lab"
POD = "egress-http"
OBSERVER_URL = "http://198.51.100.30:8080/source"
MANAGEMENT_URL = "http://10.231.1.11:8090/"
RECOVERY_SECONDS = 8

SOURCE_SERVER = """from http.server import BaseHTTPRequestHandler, HTTPServer

class SourceObserver(BaseHTTPRequestHandler):
    def do_GET(self):
        address = self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(address)))
        self.end_headers()
        self.wfile.write(address)

HTTPServer(("198.51.100.30", 8080), SourceObserver).serve_forever()
"""


def lab(state, command, *args):
    return subprocess.check_output([LAB, command, "-state", state, *args], text=True, timeout=140)


def status(state):
    return {row["guest"]["name"]: row["running"] for row in json.loads(lab(state, "status"))}


def validate_profile(state):
    actual = json.loads(lab(state, "status"))
    expected = json.loads(subprocess.check_output([LAB, "plan", "-profile", PROFILE], text=True, timeout=10))["guests"]
    require([entry["guest"] for entry in actual] == expected, "use a disposable egress-ha lab for this verifier")


def reset_hosts(state):
    for guest in (*GATEWAYS, WORKER, OBSERVER):
        lab(state, "stop", guest)
    lab(state, "up", "-profile", str(PROFILE))
    for guest in (*GATEWAYS, WORKER, OBSERVER):
        eventually(lambda: ssh(state, guest, "true"), 65)


def gateway_files(index, address):
    peer, local = 3 - index, 2 + index
    config = {"namespace": NAMESPACE, "egress": {"inside": "work0", "outside": "external0", "address": str(address),
                                                 "tenantPrefixes": ["10.84.1.0/24"],
                                                 "protectedPrefixes": ["10.231.1.0/24"], "gateOnActivation": True}}
    cli = f"{DEST}/bin/ocean-gateway -config {DEST}/gateway.json -mode"
    keepalived = f"""global_defs {{
  router_id ocean_egress_{index}
  script_user root
  enable_script_security
}}
vrrp_instance EGRESS {{
  state BACKUP
  interface work0
  virtual_router_id 74
  priority {150 if index == 0 else 100}
  nopreempt
  advert_int 1
  unicast_src_ip 10.84.1.{local}
  unicast_peer {{
    10.84.1.{peer}
  }}
  track_interface {{
    external0
  }}
  garp_master_delay 0
  garp_master_repeat 3
  virtual_ipaddress {{
    10.84.1.1/24 dev work0
    {address}/24 dev external0
  }}
  notify_master "{cli} activate"
  notify_backup "{cli} deactivate"
  notify_fault "{cli} deactivate"
  notify_stop "{cli} deactivate"
}}
"""
    unit = f"""[Unit]
Description=ocean lab egress gateway

[Service]
ExecStart=/usr/bin/ip netns exec {NAMESPACE} /usr/sbin/keepalived --dont-fork --log-console --use-file {DEST}/keepalived.conf
ExecStopPost={cli} deactivate
"""
    return {"bin/ocean-gateway": (ROOT / "bin/ocean-gateway").read_bytes(),
            "gateway.json": json.dumps(config).encode(), "keepalived.conf": keepalived.encode(),
            "ocean-fixed-egress.service": unit.encode()}


def configure_gateway(state, index, address, install=True):
    guest = GATEWAYS[index]
    if install:
        upload(state, guest, gateway_files(index, address), DEST)
    local = 2 + index
    ssh(state, guest, f"""set -eu
sudo ip netns add {NAMESPACE}
sudo ip link set work0 netns {NAMESPACE}
sudo ip link set external0 netns {NAMESPACE}
sudo ip -n {NAMESPACE} addr flush dev work0
sudo ip -n {NAMESPACE} addr flush dev external0
sudo ip -n {NAMESPACE} addr add 10.84.1.{local}/24 dev work0
sudo ip -n {NAMESPACE} addr add 198.51.100.{local}/24 dev external0
sudo ip -n {NAMESPACE} link set work0 up
sudo ip -n {NAMESPACE} link set external0 up
sudo ip netns exec {NAMESPACE} sysctl -q -w net.ipv4.ip_forward=1
sudo {DEST}/bin/ocean-gateway -config {DEST}/gateway.json
sudo install -m 0644 {DEST}/ocean-fixed-egress.service /run/systemd/system/ocean-fixed-egress.service
sudo systemctl daemon-reload
sudo systemctl start ocean-fixed-egress.service
""")


def gateway_state(state, guest, address):
    devices = json.loads(ssh(state, guest, f"sudo ip -n {NAMESPACE} -4 -j address show dev external0"))
    vip = any(item["local"] == str(address) for device in devices for item in device["addr_info"])
    listing = json.loads(ssh(state, guest, f"sudo ip netns exec {NAMESPACE} /usr/sbin/nft -j list set inet ocean_fixed_egress active_tenant_networks"))
    active = any(record.get("set", {}).get("elem") for record in listing["nftables"])
    return vip, active


def translated_packets(state, guest):
    listing = json.loads(ssh(state, guest, f"sudo ip netns exec {NAMESPACE} /usr/sbin/nft -j list chain inet ocean_fixed_egress postrouting"))
    counters = [expression["counter"]["packets"] for entry in listing["nftables"] for expression in entry.get("rule", {}).get("expr", [])
                if "counter" in expression]
    require(len(counters) == 1, "the gateway is missing its source NAT counter")
    return counters[0]


def worker_command(state, command):
    prelude = """set -eu
cd /tmp
uid=$(id -u ocean-agent)
pod() { sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" nice -n 10 podman "$@"; }
"""
    return ssh(state, WORKER, prelude + command).decode().strip()


def configure_worker(state, image):
    result = worker_command(state, f"""pod rm -f --ignore --time=0 {POD} >/dev/null
pod run --pull=missing --detach --name {POD} --network none --memory 32m {shlex.quote(image)} sleep 900 >/dev/null
pid=$(pod inspect --format '{{{{.State.Pid}}}}' {POD})
sudo ip link set work0 netns "$pid"
sudo nsenter -t "$pid" -n ip addr flush dev work0
sudo nsenter -t "$pid" -n ip addr add 10.84.1.4/24 dev work0
sudo nsenter -t "$pid" -n ip link set work0 up
sudo nsenter -t "$pid" -n ip route replace default via 10.84.1.1
pod info --format '{{{{.Host.Security.Rootless}}}}'
ps -o ni= -p "$pid" | tr -d ' '
""")
    if result.splitlines() != ["true", "10"]:
        raise RuntimeError("the routed workload requires rootless Podman and nice 10")


def request(state, url):
    try:
        return worker_command(state, f"pod exec {POD} wget -q -O - -T 1 {shlex.quote(url)}")
    except RuntimeError:
        return None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify(state, address, image):
    ready = status(state)
    require(all(ready.get(guest) for guest in (*GATEWAYS, WORKER, OBSERVER, OPERATOR)), "the egress-ha profile must be running")
    ssh(state, OBSERVER, "ip -4 -o addr show dev external0")
    upload(state, OBSERVER, {"source-observer.py": SOURCE_SERVER.encode()}, DEST)
    ssh(state, OBSERVER, f"sudo systemd-run --quiet --unit ocean-source-observer /usr/bin/python3 -u {DEST}/source-observer.py")
    configure_gateway(state, 0, address)
    configure_worker(state, image)
    eventually(lambda: require(gateway_state(state, GATEWAYS[0], address) == (True, True) and
                               request(state, OBSERVER_URL) == str(address), "primary gateway has not started forwarding"), 15)

    configure_gateway(state, 1, address)
    eventually(lambda: require(gateway_state(state, GATEWAYS[1], address) == (False, False) and
                               b"Entering BACKUP STATE" in ssh(state, GATEWAYS[1],
                               "sudo journalctl -u ocean-fixed-egress.service -n 30 --no-pager"),
                               "standby gateway has not joined"), 12)
    activation = ssh(state, GATEWAYS[1], f"""if result=$(sudo {DEST}/bin/ocean-gateway -config {DEST}/gateway.json -mode activate 2>&1); then
  exit 1
fi
printf '%s\n' "$result"
""").decode()
    require("public IPv4 address has not been assigned" in activation, "standby activation did not report missing ownership")
    worker_command(state, f"""pid=$(pod inspect --format '{{{{.State.Pid}}}}' {POD})
sudo nsenter -t "$pid" -n ip route replace 198.51.100.30/32 via 10.84.1.3
""")
    nat_before = translated_packets(state, GATEWAYS[1])
    try:
        require(request(state, OBSERVER_URL) is None, "the standby forwarded traffic addressed directly to it")
        nat_after = translated_packets(state, GATEWAYS[1])
        require(nat_before == nat_after == 0, "the standby translated packets during the direct probe")
    finally:
        worker_command(state, f"""pid=$(pod inspect --format '{{{{.State.Pid}}}}' {POD})
sudo nsenter -t "$pid" -n ip route delete 198.51.100.30/32 via 10.84.1.3
""")

    ssh(state, GATEWAYS[0], "sudo systemd-run --quiet --unit ocean-management-probe /usr/bin/python3 -u -m http.server 8090 --bind 10.231.1.11")
    eventually(lambda: ssh(state, OPERATOR, f"curl --noproxy '*' --fail --silent --max-time 2 {MANAGEMENT_URL} -o /dev/null"))
    require(request(state, MANAGEMENT_URL) is None, "the workload reached the management segment")
    require(request(state, OBSERVER_URL) == str(address), "the workload lost its authorized egress")
    first_boot = ssh(state, GATEWAYS[0], "cat /proc/sys/kernel/random/boot_id").decode().strip()

    started = time.monotonic()
    lab(state, "stop", GATEWAYS[0])
    attempts = []
    recovered = None
    while time.monotonic() - started < RECOVERY_SECONDS:
        observed = request(state, OBSERVER_URL)
        elapsed = round((time.monotonic() - started) * 1000)
        attempts.append({"elapsedMs": elapsed, "observedAddress": observed})
        if observed is not None:
            require(observed == str(address), "a successful connection used a different source address")
            recovered = elapsed
            break
        time.sleep(0.1)
    require(recovered is not None and recovered <= RECOVERY_SECONDS * 1000, "egress missed the recovery deadline")
    require(not status(state)[GATEWAYS[0]], "the primary KVM guest is still running")
    require(gateway_state(state, GATEWAYS[1], address) == (True, True), "the standby never activated the reserved address")
    translated_after_failover = translated_packets(state, GATEWAYS[1])
    require(translated_after_failover > nat_after, "the surviving gateway did not translate the new connection")

    lab(state, "up", "-profile", str(PROFILE))
    eventually(lambda: ssh(state, GATEWAYS[0], "true"), 65)
    returned_boot = ssh(state, GATEWAYS[0], "cat /proc/sys/kernel/random/boot_id").decode().strip()
    require(returned_boot != first_boot, "the recovered guest retained its old kernel boot ID")
    configure_gateway(state, 0, address, install=False)
    eventually(lambda: require(gateway_state(state, GATEWAYS[0], address) == (False, False) and
                               gateway_state(state, GATEWAYS[1], address) == (True, True), "the returning gateway did not remain the standby"))
    require(request(state, OBSERVER_URL) == str(address), "the workload lost its reserved address after node recovery")

    return {"address": str(address), "gateways": list(GATEWAYS), "worker": WORKER, "observer": OBSERVER,
            "recoveryMs": recovered, "deadlineMs": RECOVERY_SECONDS * 1000, "attempts": attempts,
            "abruptGuestLossVerified": True, "differentBootIDAfterRestart": True, "standbyDeniedForwarding": True,
            "standbyNATPackets": nat_after, "activeNATPacketsAfterFailover": translated_after_failover, "standbyActivationRejected": True,
            "returningGatewayStayedStandby": True, "managementIsolationVerified": True, "rootless": True, "nice": 10, "image": image}


def main():
    import yaml

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--reservation", type=Path, required=True, help="public-ip-nat-arm.json from the ARM reservation verifier")
    parser.add_argument("--reset", action="store_true", help="restart this disposable lab's gateways, worker, and observer before a repeat run")
    args = parser.parse_args()
    state = args.state.resolve()
    reservation = json.loads(args.reservation.read_text())
    address = ipaddress.IPv4Address(reservation["allocatedAddresses"][0])
    if not reservation["subnetNATAssociationVerified"] or address not in ipaddress.IPv4Network("198.51.100.16/28"):
        raise RuntimeError("the packet test requires a verified reservation from the documentation address pool")
    lock = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())
    busybox = lock["images"]["busybox"]
    image = f"{busybox['repository']}@{busybox['digest']}"
    validate_profile(state)
    if args.reset:
        reset_hosts(state)
    result = verify(state, address, image)
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "fixed-egress-hosts.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"The observer saw {address} after primary KVM guest loss. Egress recovered in {result['recoveryMs']} ms and survived the guest's return.")


if __name__ == "__main__":
    main()
