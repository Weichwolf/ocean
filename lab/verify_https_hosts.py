#!/usr/bin/env python3
"""Exercise redundant DNS and HTTPS ingress in separate KVM gateway guests."""

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

sys.dont_write_bytecode = True
from region import ROOT, eventually, ssh, upload
from verify_egress_hosts import GATEWAYS, OBSERVER, PROFILE, WORKER, lab, require, status, validate_profile, worker_command
from verify_wireguard_hosts import macvlan, systemd_unit

DEST = "/opt/ocean-https-ha"
KEYS = "/run/ocean-https-ha"
GATE = "ocean-https-gw"
PROBE = "ocean-https-probe"
POD = "ocean-https-nginx"
HOST = "ingress.ocean.test"
ADDRESS = "198.51.100.20"
BACKEND = "10.89.1.4"
UNITS = ("ocean-https-proxy.service", "ocean-https-dns.service", "ocean-https-vrrp.service")
DEADLINE = 8


def public(index):
    return f"198.51.100.{42 + index}"


def external_mac(index):
    return f"02:fe:89:11:00:0{index + 1}"


def certificates():
    with tempfile.TemporaryDirectory(prefix="ocean-https-ha-") as folder:
        key, cert = Path(folder) / "key.pem", Path(folder) / "certificate.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-noenc", "-days", "1",
                        "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
                        "-keyout", key, "-out", cert], capture_output=True, check=True, timeout=10)
        public_cert = cert.read_bytes()
        return public_cert, public_cert + key.read_bytes()


def configure_gateway(state, index, keypair, binary):
    active_ip, peer_ip = public(index), public(1 - index)
    configuration = {"https": {"publicIPv4": ADDRESS, "hostname": HOST, "certificateFile": f"{KEYS}/ingress.key",
                               "backend": BACKEND + ":80", "backendSubnet": "10.89.1.0/24"}}
    keepalived = f"""global_defs {{
  router_id ocean_https_{index}
  script_user root
  enable_script_security
}}
vrrp_script https_backend {{
  script "{DEST}/bin/ready"
  interval 1
  timeout 2
  rise 1
  fall 2
  init_fail
}}
vrrp_instance PUBLIC_HTTPS {{
  state BACKUP
  interface public0
  virtual_router_id 98
  priority {150 if index == 0 else 100}
  nopreempt
  advert_int 1
  unicast_src_ip {active_ip}
  unicast_peer {{
    {peer_ip} min_ttl 255 max_ttl 255
  }}
  garp_master_delay 0
  virtual_ipaddress {{
    {ADDRESS}/24 dev public0
  }}
  track_script {{
    https_backend
  }}
}}
"""
    rules = f"""table inet ocean_https {{
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    iifname "public0" ip daddr {ADDRESS} tcp dport 443 accept
    iifname "public0" ip daddr {active_ip} meta l4proto {{ tcp, udp }} th dport 53 accept
    iifname "public0" ether saddr {external_mac(1 - index)} ip saddr {peer_ip} ip daddr {active_ip} ip ttl 255 ip protocol vrrp accept
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
  }}
}}
"""
    start = f"/usr/bin/ip netns exec {GATE}"
    ready = ("#!/bin/sh\nset -eu\n"
             "test -n \"$(ss -H -lnt 'sport = :443')\"\n"
             f"curl --noproxy '*' -fs --max-time 1 http://{BACKEND}/ >/dev/null\n")
    files = {
        "bin/ocean-gateway": binary, "bin/ready": ready.encode(), "https.json": json.dumps(configuration).encode(),
        "keepalived.conf": keepalived.encode(), "guard.nft": rules.encode(),
        UNITS[0]: systemd_unit("ocean lab public HTTPS", f"{start} /usr/sbin/haproxy -db -f {KEYS}/haproxy.conf"),
        UNITS[1]: systemd_unit("ocean lab public DNS", f"{start} /usr/sbin/dnsmasq --keep-in-foreground "
                               f"--conf-file=/dev/null --no-resolv --no-hosts --listen-address={active_ip} "
                               f"--bind-interfaces --local-ttl=30 --address=/{HOST}/{ADDRESS}"),
        UNITS[2]: systemd_unit("ocean lab HTTPS active address", f"{start} /usr/sbin/keepalived --vrrp --dont-fork "
                               f"--log-console --use-file {DEST}/keepalived.conf --pid {KEYS}/parent.pid --vrrp_pid {KEYS}/vrrp.pid"),
    }
    node = GATEWAYS[index]
    upload(state, node, files, DEST)
    upload(state, node, {"ingress.key": keypair}, KEYS, owner="root")
    ssh(state, node, f"""set -eu
sudo ip netns add {GATE}
sudo ip -n {GATE} link set lo up
{macvlan(GATE, "external0", "public0", active_ip + "/24", external_mac(index))}
{macvlan(GATE, "work0", "backend0", f"10.89.1.{1 + index}/24")}
sudo ip netns exec {GATE} /usr/sbin/nft -f {DEST}/guard.nft
sudo sh -c '{DEST}/bin/ocean-gateway -config {DEST}/https.json -mode render-https > {KEYS}/haproxy.conf'
sudo ip netns exec {GATE} /usr/sbin/haproxy -c -f {KEYS}/haproxy.conf
for unit in {" ".join(UNITS)}; do sudo install -m 0644 "{DEST}/$unit" "/run/systemd/system/$unit"; done
sudo systemctl daemon-reload
for unit in {" ".join(UNITS)}; do sudo systemctl start "$unit"; done
""")


def configure_worker(state):
    nginx = yaml.safe_load((ROOT / "tests/e2e/testdata/images.lock.yaml").read_text())["images"]["nginx"]
    image = f"{nginx['repository']}@{nginx['digest']}"
    reply = worker_command(state, f"""
pod run --pull=missing --detach --name {POD} --network none --memory 48m {shlex.quote(image)} \
    sh -ec 'printf ocean-https-nginx >/usr/share/nginx/html/index.html; exec nginx -g "daemon off;"' >/dev/null
pid=$(pod inspect --format '{{{{.State.Pid}}}}' {POD})
sudo ip link add link work0 name https0 netns "$pid" type macvlan mode bridge
sudo nsenter -t "$pid" -n ip addr add {BACKEND}/24 dev https0
sudo nsenter -t "$pid" -n ip link set https0 up
pod info --format '{{{{.Host.Security.Rootless}}}}'
ps -o ni= -p "$pid" | tr -d ' '
""")
    require(reply.splitlines() == ["true", "10"], "the NGINX fixture must run rootless at nice 10")
    return image


def configure_probe(state, certificate):
    resolver = f"nameserver {public(0)}\nnameserver {public(1)}\noptions timeout:1 attempts:1\n"
    upload(state, OBSERVER, {"ca.pem": certificate, "resolv.conf": resolver.encode()}, DEST)
    ssh(state, OBSERVER, f"""set -eu
sudo ip netns add {PROBE}
sudo ip -n {PROBE} link set lo up
{macvlan(PROBE, "external0", "ext0", "198.51.100.31/24")}
sudo install -D -m 0644 {DEST}/resolv.conf /etc/netns/{PROBE}/resolv.conf
sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf | sudo tee /etc/netns/{PROBE}/nsswitch.conf >/dev/null
sudo ip -n {PROBE} route add 10.89.1.0/24 via {ADDRESS}
""")


def owner(state, index):
    response = json.loads(ssh(state, GATEWAYS[index], f"sudo ip -n {GATE} -4 -j address show dev public0"))
    return any(item["local"] == ADDRESS for link in response for item in link["addr_info"])


def outside(state, *args):
    return ssh(state, OBSERVER, shlex.join(["sudo", "ip", "netns", "exec", PROBE, "curl", "--noproxy", "*",
                                           "-fsS", "--max-time", "3", *args])).decode()


def request(state, *resolution):
    out = outside(state, *resolution, "--cacert", f"{DEST}/ca.pem", "-w", ":%{remote_ip}", f"https://{HOST}/")
    require(out == f"ocean-https-nginx:{ADDRESS}", "the outside client lost the HTTPS fixture or received a different address")


def cleanup(state):
    for node in GATEWAYS:
        ssh(state, node, f"""set -eu
for unit in {" ".join(reversed(UNITS))}; do
    if sudo test -e "/run/systemd/system/$unit"; then
        sudo systemctl stop "$unit"
        sudo unlink "/run/systemd/system/$unit"
    fi
done
sudo systemctl daemon-reload
if sudo test -e /run/netns/{GATE}; then sudo ip netns delete {GATE}; fi
if sudo test -e {KEYS}/ingress.key; then sudo unlink {KEYS}/ingress.key; fi
""")
    ssh(state, OBSERVER, f"""set -eu
if sudo test -e /run/netns/{PROBE}; then sudo ip netns delete {PROBE}; fi
if sudo test -d /etc/netns/{PROBE}; then
    for file in resolv.conf nsswitch.conf; do
        if sudo test -e "/etc/netns/{PROBE}/$file"; then sudo unlink "/etc/netns/{PROBE}/$file"; fi
    done
    sudo rmdir /etc/netns/{PROBE}
fi
""")
    worker_command(state, f"pod rm -f --ignore --time=0 {POD} >/dev/null")


def verify(state):
    validate_profile(state)
    require(all(status(state).values()), "start the complete, disposable egress-ha lab")
    for node in GATEWAYS:
        ssh(state, node, f"sudo test ! -e /run/netns/{GATE} && sudo test ! -e {KEYS}/ingress.key")
    ssh(state, OBSERVER, f"sudo test ! -e /run/netns/{PROBE} && sudo test ! -e /etc/netns/{PROBE}")
    worker_command(state, f"if pod container exists {POD}; then exit 1; fi")
    binary = (ROOT / "bin/ocean-gateway").read_bytes()
    certificate, keypair = certificates()
    stopped = False
    try:
        image = configure_worker(state)
        configure_probe(state, certificate)
        configure_gateway(state, 0, keypair, binary)
        eventually(lambda: require(owner(state, 0), "the initial HTTPS gateway did not acquire the public address"))
        configure_gateway(state, 1, keypair, binary)
        eventually(lambda: request(state))
        require(not owner(state, 1), "both HTTPS gateways own the same address")
        wrong_host = ssh(state, OBSERVER,
                         f"sudo ip netns exec {PROBE} curl --noproxy '*' -sS --max-time 3 "
                         f"--cacert {DEST}/ca.pem -H 'Host: unapproved.ocean.test' -o /dev/null "
                         f"-w '%{{http_code}}' https://{HOST}/")
        require(wrong_host == b"421", "the gateway admitted an unapproved HTTP hostname")
        direct = ssh(state, OBSERVER, f"sudo ip netns exec {PROBE} curl --noproxy '*' --max-time 1 "
                     f"-s -o /dev/null http://{BACKEND}/ >/dev/null; printf '%s' \"$?\"")
        require(direct in {b"7", b"28"}, "the public client reached the private backend directly")
        print("The external client resolved and reached the private NGINX fixture over HTTPS.", flush=True)

        stopped = True
        lab(state, "stop", GATEWAYS[0])
        started = time.monotonic()

        def recovered():
            require(owner(state, 1), "the remaining HTTPS gateway has not acquired the address")
            request(state)

        eventually(recovered, DEADLINE)
        elapsed = round((time.monotonic() - started) * 1000)
        require(elapsed <= DEADLINE * 1000 and not status(state)[GATEWAYS[0]], "HTTPS missed its gateway loss recovery limit")
        request(state, "--resolve", f"{HOST}:443:{ADDRESS}")
        return {"hostname": HOST, "address": ADDRESS, "gateways": list(GATEWAYS), "worker": WORKER, "image": image,
                "rootless": True, "nice": 10, "trustedCertificateVerified": True, "unknownHostRejected": True,
                "directWorkloadAccessBlocked": True, "dnsAndHTTPSRecoveredMs": elapsed, "deadlineMs": DEADLINE * 1000,
                "cachedAddressWorkedAfterFailover": True}
    finally:
        if stopped:
            lab(state, "up", "-profile", str(PROFILE))
            eventually(lambda: ssh(state, GATEWAYS[0], "true"), 65)
        cleanup(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    report = verify(state)
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "https-gateway-hosts.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"The external client resolved the same public address and recovered HTTPS in {report['dnsAndHTTPSRecoveredMs']} ms.")


if __name__ == "__main__":
    main()
