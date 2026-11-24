#!/usr/bin/env python3
"""Verify the regional management stack in a dedicated local KVM lab."""

import argparse
import json
import shlex
import sys
import time
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
from region import ARM, DEST, DOMAIN, NODES, OPERATOR, ROOT, VIP, etcdctl, eventually, run, ssh


def service(state, node, action, *names):
    return ssh(state, node, shlex.join(["sudo", "systemctl", action, *names]))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def expect_failure(check, description):
    try:
        check()
    except RuntimeError:
        return
    raise RuntimeError(f"expected failure: {description}")


def ready(state):
    return ssh(state, OPERATOR, f"curl --fail --silent --show-error --max-time 3 --cacert {DEST}/pki/ingress-ca.pem https://{ARM}/readyz")


def verify_dns(state, server):
    probe = '''import secrets, socket, struct, sys
server, domain, vip = sys.argv[1:]
for name in ('arm.', 'id.'):
    labels = (name + domain).split('.')
    transaction = secrets.randbelow(65536)
    request = struct.pack('!6H', transaction, 0, 1, 0, 0, 0)
    request += b''.join(bytes([len(label)]) + label.encode() for label in labels) + b'\\x00' + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(2)
        connection.connect((server, 53))
        connection.send(request)
        reply = connection.recv(1024)
    code, flags, _, answers, *_ = struct.unpack('!6H', reply[:12])
    offset = len(request)
    if reply[offset] & 0xc0 == 0xc0:
        offset += 2
    else:
        while reply[offset]:
            offset += reply[offset] + 1
        offset += 1
    kind, record_class, _, count = struct.unpack('!HHIH', reply[offset:offset+10])
    if code != transaction or flags & 0x860f != 0x8400 or answers != 1 or (kind, record_class, count) != (1, 1, 4) or reply[offset+10:offset+14] != socket.inet_aton(vip):
        raise SystemExit('expected an authoritative management A record from ' + server)
'''
    ssh(state, OPERATOR, shlex.join(["python3", "-c", probe, server, DOMAIN, VIP]))


def active_gateway(state):
    active = [node for node in list(NODES)[:2] if VIP.encode() in ssh(state, node, "ip -4 -o address show dev mgmt0")]
    require(len(active) == 1, f"expected one VIP owner, found {active}")
    return active[0]


def lab(state, command, *options):
    return run([ROOT / "bin/ocean-lab", command, "-state", state, *options])


def powered_on(state, node):
    return next(machine["running"] for machine in json.loads(lab(state, "status")) if machine["guest"]["name"] == node)


def verify(state):
    ready(state)
    for address in list(NODES.values())[:2]:
        verify_dns(state, address)
    print("Both DNS servers returned authoritative ARM and identity records.", flush=True)
    expect_failure(lambda: ssh(state, OPERATOR, f"curl --fail --silent --show-error --max-time 3 --cacert {DEST}/pki/storage-ca.pem https://10.231.1.11:2379/health"), "etcd access without a client certificate")

    owner = active_gateway(state)
    start = time.monotonic()
    try:
        service(state, owner, "stop", "ocean-gateway.service", "ocean-dns.service")
        eventually(lambda: require(active_gateway(state) != owner, "VIP has not moved"), 10)
        ssh(state, OPERATOR, "sudo resolvectl flush-caches")
        eventually(lambda: ready(state), 12)
        print(f"Gateway and DNS failover restored the same verified HTTPS endpoint in {time.monotonic() - start:.2f}s.", flush=True)
    finally:
        service(state, owner, "start", "ocean-gateway.service", "ocean-dns.service")

    replica = list(NODES)[2]
    try:
        service(state, replica, "stop", "ocean-api.service")
        eventually(lambda: ready(state), 10)
        for _ in range(5):
            ready(state)
        print("The HTTPS endpoint continued serving after an API replica stopped.", flush=True)
    finally:
        service(state, replica, "start", "ocean-api.service")

    prefix = "/ocean/v1/regions/farm-1/operations/local-verification-" + uuid.uuid4().hex
    key = prefix + "/acknowledged"
    pending = prefix + "/unacknowledged"
    try:
        ssh(state, OPERATOR, etcdctl(f"put {key} committed"))
        endpoints = json.loads(ssh(state, OPERATOR, etcdctl("endpoint status --cluster -w json")))
        leader = next(item for item in endpoints if item["Status"]["header"]["member_id"] == item["Status"]["leader"])
        node = next(name for name, address in NODES.items() if leader["Endpoint"] == f"https://{address}:2379")
        try:
            ssh(state, node, "sudo systemctl poweroff --no-block")
            eventually(lambda: require(not powered_on(state, node), "leader guest is still running"), 15)
            eventually(lambda: ready(state), 10)
            require(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only")).strip() == b"committed", "acknowledged value changed after leader failure")
            ssh(state, OPERATOR, etcdctl(f"put {key} committed-after-election"))
            print(f"After loss of leader {node}, the remaining quorum preserved the value and accepted a new write.", flush=True)
        finally:
            lab(state, "up", "-profile", ROOT / "lab/profiles/single-farm-3.yaml")
        eventually(lambda: ssh(state, OPERATOR, etcdctl("endpoint health --cluster")))
        member = NODES[node]
        eventually(lambda: require(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only --consistency=s", [member])).strip()
                                   == b"committed-after-election", "rejoined member lost acknowledged state"))

        stopped = list(NODES)[:2]
        survivor = [list(NODES.values())[2]]
        try:
            for node in stopped:
                service(state, node, "stop", "ocean-etcd.service")
            ssh(state, OPERATOR, etcdctl("endpoint status", survivor))
            expect_failure(lambda: ssh(state, OPERATOR, etcdctl(f"put {pending} pending", survivor)), "write without quorum")
            expect_failure(lambda: ready(state), "API readiness without quorum")
            value = ssh(state, OPERATOR, etcdctl(f"get {pending} --print-value-only --consistency=s", survivor)).strip()
            require(not value, "write committed on the surviving voter during quorum loss")
        finally:
            for node in stopped:
                service(state, node, "start", "ocean-etcd.service")
        eventually(lambda: ready(state), 10)
        recovered = ssh(state, OPERATOR, etcdctl(f"get {pending} --print-value-only")).strip()
        require(recovered in (b"", b"pending"), "unexpected value after quorum recovery")
        require(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only")).strip() == b"committed-after-election", "quorum recovery changed acknowledged data")
        print(f"No commitment or ready API during quorum loss. After recovery the timed-out write was {'present' if recovered else 'absent'} and acknowledged data survived.", flush=True)
    finally:
        ssh(state, OPERATOR, etcdctl(f"del {prefix}/ --prefix"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    verify(args.state.resolve())


if __name__ == "__main__":
    main()
