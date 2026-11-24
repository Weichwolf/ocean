#!/usr/bin/env python3
"""Exercise redundant WireGuard paths and a private workload in the KVM lab."""

import argparse
import json
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
from region import ARM, DEST as REGION, OPERATOR, ROOT, eventually, ssh, upload

GATEWAYS = ("farm-1-node-02", "farm-1-node-01")
CUSTOMER = "farm-1-customer"
WORKER = "farm-1-node-05"
DEST = "/opt/ocean-vpn-ha"
KEYS = "/run/ocean-vpn-ha"
CLOUD = "ocean-cloud-vpn"
SITE = ("ocean-site-a", "ocean-site-b")
CLIENT = "ocean-vpn-probe"
BRIDGE = "ocean-vpn-lan"
POD = "ocean-vpn-fixture"
VRRP = "ocean-vpn-vrrp.service"
ROUTER = "ocean-vpn-route.service"
TENANT = "10.85.50.0/24"
CUSTOMER_LAN = "10.85.60.0/24"
VIP = "10.85.50.1"
DEADLINE = 8
WORKER_SHELL = """
cd /tmp
uid=$(id -u ocean-agent)
pod() { sudo runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" nice -n 10 podman "$@"; }
"""


def require(value, message):
    if not value:
        raise RuntimeError(message)


def lab(state, action, *options):
    return subprocess.check_output([ROOT / "bin/ocean-lab", action, "-state", state, *options], timeout=180)


def gateway_address(index):
    return f"10.85.50.{index + 2}"


def gateway_mac(index):
    return f"02:fe:8a:31:00:0{index + 1}"


def customer_router(index):
    return f"10.85.60.{index + 2}"


def role_path(namespace):
    return f"{DEST}/{namespace}.json"


def gateway_command(namespace, mode):
    return f"{DEST}/bin/ocean-gateway -config {role_path(namespace)} -mode {mode}"


def make_key(state, node, namespace):
    return ssh(state, node, f"""set -eu
sudo install -d -m 0700 {KEYS}
sudo sh -c 'umask 077; wg genkey > "$1"; wg pubkey < "$1"' sh {KEYS}/{namespace}.key
""").decode().strip()


def role(index, cloud_side, public):
    namespace = CLOUD if cloud_side else SITE[index]
    cloud_tunnel = f"10.85.99.{2 * index}"
    remote_tunnel = f"10.85.99.{2 * index + 1}"
    cloud_underlay = f"10.233.1.{181 + index}"
    remote_underlay = f"10.233.1.{201 + index}"
    config = {"tunnel": "wg0", "underlay": "wan0", "inside": "lan0", "listenPort": 51820,
              "localTunnel": (cloud_tunnel if cloud_side else remote_tunnel) + "/31",
              "peerTunnel": remote_tunnel if cloud_side else cloud_tunnel,
              "peerEndpoint": (remote_underlay if cloud_side else cloud_underlay) + ":51820",
              "peerPublicKey": public, "privateKeyFile": f"{KEYS}/{namespace}.key",
              "localPrefixes": [TENANT if cloud_side else CUSTOMER_LAN],
              "remotePrefixes": [CUSTOMER_LAN if cloud_side else TENANT],
              "protectedPrefixes": ["10.231.1.0/24"]}
    if cloud_side:
        peer = 1 - index
        config["redundancy"] = {"address": gateway_address(index), "peer": gateway_address(peer),
                                "peerMac": gateway_mac(peer)}
    return namespace, json.dumps({"namespace": namespace, "wireguard": config}).encode()


def systemd_unit(description, command):
    return f"[Unit]\nDescription={description}\n\n[Service]\nExecStart={command}\n".encode()


def install_unit(name):
    return (f"sudo install -m 0644 {DEST}/{name} /run/systemd/system/{name}\n"
            f"sudo systemctl daemon-reload\nsudo systemctl start {name}\n")


def gateway_files(index, public):
    namespace, config = role(index, True, public)
    keepalived = f"""global_defs {{
  router_id ocean_vpn_{index}
  script_user root
  enable_script_security
}}
vrrp_script wg_path {{
  script "{gateway_command(namespace, "probe")}"
  interval 1
  timeout 2
  fall 2
  rise 1
  init_fail
}}
vrrp_instance OCEAN_VPN {{
  state BACKUP
  interface lan0
  virtual_router_id 97
  priority {150 if index == 0 else 100}
  nopreempt
  advert_int 1
  unicast_src_ip {gateway_address(index)}
  unicast_peer {{
    {gateway_address(1 - index)} min_ttl 255 max_ttl 255
  }}
  garp_master_delay 0
  track_script {{
    wg_path
  }}
  virtual_ipaddress {{
    {VIP}/24 dev lan0
  }}
}}
"""
    return {f"{namespace}.json": config, "vrrp.conf": keepalived.encode(),
            VRRP: systemd_unit("ocean lab VPN active route", f"/usr/bin/ip netns exec {CLOUD} "
                               f"/usr/sbin/keepalived --vrrp --dont-fork --log-console --use-file {DEST}/vrrp.conf "
                               f"--pid {KEYS}/vpn-keepalived.pid --vrrp_pid {KEYS}/vpn-vrrp.pid")}


def macvlan(namespace, parent, name, address, mac=None):
    mac_argument = f" address {mac}" if mac else ""
    return (f"sudo ip link add link {parent} name {name}{mac_argument} netns {namespace} type macvlan mode bridge\n"
            f"sudo ip -n {namespace} addr add {address} dev {name}\n"
            f"sudo ip -n {namespace} link set {name} up\n")


def configure_gateway(state, index, public, binary):
    host = GATEWAYS[index]
    upload(state, host, {**gateway_files(index, public), "bin/ocean-gateway": binary}, DEST)
    attach_gateway_links(state, index)
    ssh(state, host, f"""set -eu
sudo {gateway_command(CLOUD, "apply")}
{install_unit(VRRP)}
""")


def attach_gateway_links(state, index):
    host = GATEWAYS[index]
    ssh(state, host, f"""set -eu
sudo ip netns add {CLOUD}
sudo ip -n {CLOUD} link set lo up
{macvlan(CLOUD, "customer0", "wan0", f"10.233.1.{181 + index}/24")}
{macvlan(CLOUD, "work0", "lan0", gateway_address(index) + "/24", gateway_mac(index))}
""")


def configure_customer(state, publics, binary):
    routes = f"""#!/bin/sh
set -eu
active=
while :; do
    next=
    case "$active" in
        {SITE[1]}) set -- {SITE[1]} {SITE[0]} ;;
        *) set -- {SITE[0]} {SITE[1]} ;;
    esac
    for name do
        if {DEST}/bin/ocean-gateway -config "{DEST}/$name.json" -mode probe; then
            next=$name
            break
        fi
    done
    if [ "$next" != "$active" ]; then
        case "$next" in
            {SITE[0]}) ip -n {CLIENT} route replace {TENANT} via {customer_router(0)} ;;
            {SITE[1]}) ip -n {CLIENT} route replace {TENANT} via {customer_router(1)} ;;
            "") ip -n {CLIENT} route del {TENANT} 2>/dev/null || true ;;
        esac
        active=$next
    fi
    sleep 0.25
done
"""
    files = {namespace + ".json": config for index, public in enumerate(publics)
             for namespace, config in [role(index, False, public)]}
    files.update({"bin/ocean-gateway": binary, "bin/select-route": routes.encode(),
                  ROUTER: systemd_unit("ocean lab customer route selection", f"{DEST}/bin/select-route")})
    upload(state, CUSTOMER, files, DEST)
    ssh(state, CUSTOMER, f"""set -eu
sudo ip link add {BRIDGE} type bridge
sudo ip link set {BRIDGE} up
sudo ip netns add {CLIENT}
sudo ip -n {CLIENT} link set lo up
sudo ip link add ovp-client type veth peer name eth0 netns {CLIENT}
sudo ip link set ovp-client master {BRIDGE}
sudo ip link set ovp-client up
sudo ip -n {CLIENT} addr add 10.85.60.4/24 dev eth0
sudo ip -n {CLIENT} link set eth0 up
sudo ip -n {CLIENT} route add default via {customer_router(0)}
""")
    for index, namespace in enumerate(SITE):
        ssh(state, CUSTOMER, f"""set -eu
sudo ip netns add {namespace}
sudo ip -n {namespace} link set lo up
{macvlan(namespace, "customer0", "wan0", f"10.233.1.{201 + index}/24")}
sudo ip link add ovp-site-{index} type veth peer name lan0 netns {namespace}
sudo ip link set ovp-site-{index} master {BRIDGE}
sudo ip link set ovp-site-{index} up
sudo ip -n {namespace} addr add {customer_router(index)}/24 dev lan0
sudo ip -n {namespace} link set lan0 up
sudo {gateway_command(namespace, "apply")}
""")
    ssh(state, CUSTOMER, install_unit(ROUTER))


def configure_workload(state):
    busybox = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())["images"]["busybox"]
    image = f"{busybox['repository']}@{busybox['digest']}"
    details = ssh(state, WORKER, f"""set -eu
{WORKER_SHELL}
pod run --pull=missing --detach --name {POD} --network none --memory 32m {shlex.quote(image)} \
    sh -ec 'mkdir /www; printf ocean-vpn >/www/index.html; exec httpd -f -p 8080 -h /www' >/dev/null
pid=$(pod inspect --format '{{{{.State.Pid}}}}' {POD})
sudo ip link add link work0 name vpn0 netns "$pid" type macvlan mode bridge
sudo nsenter -t "$pid" -n ip addr add 10.85.50.4/24 dev vpn0
sudo nsenter -t "$pid" -n ip link set vpn0 up
sudo nsenter -t "$pid" -n ip route add default via {VIP}
pod info --format '{{{{.Host.Security.Rootless}}}}'
ps -o ni= -p "$pid" | tr -d ' '
""").splitlines()
    require(details == [b"true", b"10"], "the test workload is not running rootless at nice 10")
    return image


def customer_http(state, destination):
    return ssh(state, CUSTOMER, f"""
status=0
body=$(sudo ip netns exec {CLIENT} curl --noproxy '*' -ks --fail --connect-timeout 1 --max-time 1 {shlex.quote(destination)}) || status=$?
printf '%s:%s' "$status" "$body"
""")


def management_ready(state):
    reply = ssh(state, OPERATOR, f"curl -fsS --cacert {REGION}/pki/ingress-ca.pem "
                f"--max-time 1 -o /dev/null -w '%{{http_code}}' https://{ARM}/readyz")
    require(reply == b"204", "the independent management endpoint did not return readiness")


def measure_management(state, start):
    attempts = []
    while time.monotonic() - start < DEADLINE:
        try:
            management_ready(state)
        except RuntimeError:
            attempts.append({"elapsedMs": round((time.monotonic() - start) * 1000), "ready": False})
            time.sleep(0.25)
            continue
        elapsed = round((time.monotonic() - start) * 1000)
        require(elapsed <= DEADLINE * 1000, "the management network exceeded its recovery deadline")
        attempts.append({"elapsedMs": elapsed, "ready": True})
        return attempts
    raise RuntimeError("the management endpoint did not recover during the gateway fault")


def selected(state):
    output = ssh(state, CUSTOMER, f"sudo ip -n {CLIENT} -j route show {TENANT}")
    return [row.get("gateway") for row in json.loads(output)]


def owner(state, index):
    output = ssh(state, GATEWAYS[index], f"sudo ip -n {CLOUD} -4 -j address show dev lan0")
    return any(address["local"] == VIP for row in json.loads(output) for address in row["addr_info"])


def probe_workload(state):
    require(customer_http(state, "http://10.85.50.4:8080/") == b"0:ocean-vpn", "private workload is unreachable")


def recover(state, index, start):
    def ready():
        require(selected(state) == [customer_router(index)], "the customer has not switched to the surviving tunnel")
        require(owner(state, index), "the surviving gateway does not own the tenant-side route")
        probe_workload(state)

    eventually(ready, DEADLINE)
    elapsed = round((time.monotonic() - start) * 1000)
    require(elapsed <= DEADLINE * 1000, f"the VPN route exceeded its recovery deadline: {elapsed} ms")
    return elapsed


def available(state):
    for host in GATEWAYS:
        ssh(state, host, f"sudo test ! -e /run/netns/{CLOUD} && sudo test ! -e /run/systemd/system/{VRRP} && "
            f"sudo test ! -e {KEYS}/{CLOUD}.key")
    ssh(state, CUSTOMER, f"""set -eu
sudo test ! -e /run/systemd/system/{ROUTER}
for namespace in {CLIENT} {" ".join(SITE)}; do
    sudo test ! -e "/run/netns/$namespace"
    sudo test ! -e "{KEYS}/$namespace.key"
done
if ip link show dev {BRIDGE} >/dev/null 2>&1; then exit 1; fi
""")
    ssh(state, WORKER, f"set -eu\n{WORKER_SHELL}\nif pod container exists {POD}; then exit 1; fi")


def cleanup(state):
    for host in GATEWAYS:
        ssh(state, host, f"""set -eu
if sudo test -e /run/systemd/system/{VRRP}; then
    sudo systemctl stop {VRRP}
    sudo unlink /run/systemd/system/{VRRP}
    sudo systemctl daemon-reload
fi
if sudo test -e /run/netns/{CLOUD}; then sudo ip netns delete {CLOUD}; fi
if sudo test -e {KEYS}/{CLOUD}.key; then sudo unlink {KEYS}/{CLOUD}.key; fi
""")
    ssh(state, CUSTOMER, f"""set -eu
if sudo test -e /run/systemd/system/{ROUTER}; then
    sudo systemctl stop {ROUTER}
    sudo unlink /run/systemd/system/{ROUTER}
    sudo systemctl daemon-reload
fi
for namespace in {CLIENT} {" ".join(SITE)}; do
    if sudo test -e "/run/netns/$namespace"; then sudo ip netns delete "$namespace"; fi
    if sudo test -e "{KEYS}/$namespace.key"; then sudo unlink "{KEYS}/$namespace.key"; fi
done
if ip link show dev {BRIDGE} >/dev/null 2>&1; then sudo ip link delete dev {BRIDGE}; fi
""")
    ssh(state, WORKER, f"set -eu\n{WORKER_SHELL}\npod rm -f --ignore --time=0 {POD} >/dev/null")


def verify(state, profile):
    binary = (ROOT / "bin/ocean-gateway").read_bytes()
    guests = {row["guest"]["name"]: row["guest"] for row in json.loads(lab(state, "status"))}
    plan = json.loads(subprocess.check_output([ROOT / "bin/ocean-lab", "plan", "-profile", profile], timeout=10))
    require(guests == {guest["name"]: guest for guest in plan["guests"]}, "use the exact profile of the running KVM lab")
    available(state)
    management_ready(state)
    stopped = None
    try:
        cloud_public = [make_key(state, host, CLOUD) for host in GATEWAYS]
        site_public = [make_key(state, CUSTOMER, namespace) for namespace in SITE]
        configure_customer(state, cloud_public, binary)
        configure_gateway(state, 0, site_public[0], binary)
        eventually(lambda: require(owner(state, 0), "first gateway did not activate"))
        configure_gateway(state, 1, site_public[1], binary)
        eventually(lambda: ssh(state, GATEWAYS[1], f"sudo {gateway_command(CLOUD, 'probe')}"))
        require(not owner(state, 1), "both cloud gateways own the tenant-side route")
        image = configure_workload(state)
        eventually(lambda: probe_workload(state))
        for url in ("https://10.231.1.10/readyz", "http://10.85.51.4:8080/"):
            require(customer_http(state, url).split(b":", 1)[0] in {b"7", b"28"}, "an unapproved network was reachable")

        print("Both WireGuard paths are healthy. Injecting an underlay outage.", flush=True)
        started = time.monotonic()
        ssh(state, GATEWAYS[0], f"sudo ip -n {CLOUD} link set wan0 down")
        tunnel_ms = recover(state, 1, started)
        require(not owner(state, 0), "the disconnected gateway retained its tenant-side route")
        management_ready(state)
        ssh(state, GATEWAYS[0], f"sudo ip -n {CLOUD} link set wan0 up")
        eventually(lambda: ssh(state, GATEWAYS[0], f"sudo {gateway_command(CLOUD, 'probe')}"))
        require(not owner(state, 0), "repair displaced the healthy active gateway")

        print("The surviving tunnel restored traffic. Powering off its gateway VM.", flush=True)
        stopped = GATEWAYS[1]
        lab(state, "stop", stopped)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=1) as executor:
            management = executor.submit(measure_management, state, started)
            guest_ms = recover(state, 0, started)
            management_attempts = management.result()
        require(not next(row["running"] for row in json.loads(lab(state, "status")) if row["guest"]["name"] == stopped),
                "the failed gateway VM was still running")
        return {"gateways": list(GATEWAYS), "worker": WORKER, "customer": CUSTOMER, "rootless": True, "nice": 10,
                "image": image, "tunnelLossRecoveryMs": tunnel_ms, "gatewayLossRecoveryMs": guest_ms,
                "deadlineMs": DEADLINE * 1000, "protectedManagementBlocked": True, "unapprovedPrefixBlocked": True,
                "managementReadyAfterTunnelLoss": True, "managementGatewayLossProbes": management_attempts}
    finally:
        if stopped:
            lab(state, "up", "-profile", profile)
            eventually(lambda: ssh(state, stopped, "true"), 65)
        cleanup(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state, args.profile.resolve())
    target = state / "evidence"
    target.mkdir(mode=0o700, exist_ok=True)
    (target / "wireguard-hosts.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"WireGuard route recovered after tunnel loss in {evidence['tunnelLossRecoveryMs']} ms "
          f"and after gateway loss in {evidence['gatewayLossRecoveryMs']} ms.")


if __name__ == "__main__":
    main()
