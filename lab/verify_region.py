#!/usr/bin/env python3
"""Verify the regional management stack in a dedicated local KVM lab."""

import argparse
import contextlib
import json
import shlex
import subprocess
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


@contextlib.contextmanager
def management_probe(state, enabled):
    if not enabled:
        yield None, None, {}
        return
    from verify_container_groups import pinned_image
    from verify_identity import CLIENT
    from verify_onboarding import prepare_operator_client

    prepare_operator_client(state, ("arm_cli.py", "arm_operations_cli.py", "region_cli.py", "testdata/arm-contract.tsv"))
    directory = ssh(state, OPERATOR, "mktemp -d /tmp/ocean-region-cli.XXXXXXXX").decode().strip()
    if not directory.startswith("/tmp/ocean-region-cli.") or not directory.rsplit(".", 1)[1].isalnum():
        raise RuntimeError("the operator guest created an unexpected session path")

    def command(stage):
        return shlex.join(["python3", f"{CLIENT}/region_cli.py", stage, "--settings", f"{CLIENT}/operator.secret",
                           "--matrix", f"{CLIENT}/arm-contract.tsv", "--session", directory, "--image",
                           pinned_image("nginx"), "--vip", VIP])

    def stage(name):
        response = ssh(state, OPERATOR, command(name))
        return json.loads(response) if response.strip() else None

    def phase(name):
        ssh(state, OPERATOR, f"cd {shlex.quote(directory)} && echo {shlex.quote(name)} > phase.next && mv phase.next phase")

    evidence = {"phaseLimitSeconds": 60, "logicalReadLimitSeconds": 12, "azureCLI": "2.93.0",
                "managementName": ARM, "virtualIP": VIP}
    observer = None
    try:
        stage("setup")
        phase("before")
        observer = subprocess.Popen([ROOT / "bin/ocean-lab", "ssh", "-state", state, OPERATOR, "--", command("observe")],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        eventually(lambda: ssh(state, OPERATOR, f"test -s {directory}/observations.jsonl"), 10)

        def fault(label, started):
            outcome = stage(label)
            seconds = time.monotonic() - started
            require(seconds <= evidence["phaseLimitSeconds"], f"the {label} recovery exceeded its acceptance limit")
            evidence[label] = dict(outcome, elapsedSeconds=round(seconds, 3))

        yield phase, fault, evidence
        phase("after")
        pattern = shlex.quote(json.dumps('phase') + ': ' + json.dumps('after'))
        eventually(lambda: ssh(state, OPERATOR, f"grep -F -q {pattern} {directory}/observations.jsonl"), 10)
        ssh(state, OPERATOR, f"touch {directory}/stop-observer")
        _, fault_output = observer.communicate(timeout=18)
        require(observer.returncode == 0, "the authenticated client failed: " + fault_output.decode(errors="replace"))
        reads = [json.loads(line) for line in ssh(state, OPERATOR, f"cat {directory}/observations.jsonl").splitlines()]
        require({row["phase"] for row in reads} == {"before", "gateway", "api", "leader", "after"},
                "the authenticated client did not sample all phases")
        require(all(row["acknowledged"] and row["durationMs"] <= 12000 for row in reads),
                "an authenticated client request exceeded its continuity limit")
        evidence["externalRequests"] = reads
    finally:
        try:
            if observer is not None and observer.poll() is None:
                ssh(state, OPERATOR, f"touch {directory}/stop-observer")
                try:
                    observer.communicate(timeout=18)
                except subprocess.TimeoutExpired:
                    observer.kill()
                    observer.communicate()
            eventually(lambda: stage("cleanup"), 55)
        except RuntimeError:
            print(f"The private operator session remains at {directory} for cleanup.", file=sys.stderr)
            raise
        else:
            ssh(state, OPERATOR, shlex.join(["rm", "-rf", "--", directory]))


def verify(state, profile, phase=None, fault=None, evidence=None):
    ready(state)
    for address in list(NODES.values())[:2]:
        verify_dns(state, address)
    print("Both DNS servers returned authoritative ARM and identity records.", flush=True)
    expect_failure(lambda: ssh(state, OPERATOR, f"curl --fail --silent --show-error --max-time 3 --cacert {DEST}/pki/storage-ca.pem https://10.231.1.11:2379/health"), "etcd access without a client certificate")

    owner = active_gateway(state)
    if phase:
        phase("gateway")
    start = time.monotonic()
    try:
        service(state, owner, "stop", "ocean-gateway.service", "ocean-dns.service")
        eventually(lambda: require(active_gateway(state) != owner, "VIP has not moved"), 10)
        ssh(state, OPERATOR, "sudo resolvectl flush-caches")
        eventually(lambda: ready(state), 12)
        if fault:
            verify_dns(state, NODES[active_gateway(state)])
            fault("gateway", start)
        print(f"Gateway and DNS failover restored the same verified HTTPS endpoint in {time.monotonic() - start:.2f}s.", flush=True)
    finally:
        service(state, owner, "start", "ocean-gateway.service", "ocean-dns.service")

    replica = list(NODES)[2]
    if phase:
        phase("api")
    start = time.monotonic()
    try:
        service(state, replica, "stop", "ocean-api.service")
        eventually(lambda: ready(state), 10)
        for _ in range(5):
            ready(state)
        if fault:
            fault("api", start)
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
            if phase:
                phase("leader")
            start = time.monotonic()
            ssh(state, node, "sudo systemctl poweroff --no-block")
            eventually(lambda: require(not powered_on(state, node), "leader guest is still running"), 15)
            eventually(lambda: ready(state), 10)
            require(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only")).strip() == b"committed", "acknowledged value changed after leader failure")
            ssh(state, OPERATOR, etcdctl(f"put {key} committed-after-election"))
            if fault:
                remaining = [address for name, address in NODES.items() if name != node]
                after = json.loads(ssh(state, OPERATOR, etcdctl("endpoint status -w json", remaining)))
                leader_ids = {item["Status"]["leader"] for item in after}
                require(len(leader_ids) == 1 and leader["Status"]["leader"] not in leader_ids,
                        "the surviving voters did not agree on a new leader")
                fault("leader", start)
                evidence["leader"].update({"lostNode": node, "formerMemberId": leader["Status"]["leader"],
                                           "newMemberId": leader_ids.pop(), "survivingVoters": remaining})
            print(f"After loss of leader {node}, the remaining quorum preserved the value and accepted a new write.", flush=True)
        finally:
            lab(state, "up", "-profile", profile)
        eventually(lambda: ssh(state, OPERATOR, etcdctl("endpoint health --cluster")))
        member = NODES[node]
        eventually(lambda: require(ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only --consistency=s", [member])).strip()
                                   == b"committed-after-election", "rejoined member lost acknowledged state"))
        if fault:
            evidence["leader"]["rejoinedMemberObservedWrite"] = True
            return

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
    parser.add_argument("--cli", action="store_true", help="verify the authenticated CLI and external HTTPS continuity")
    parser.add_argument("--profile", type=Path, default=ROOT / "lab/profiles/single-farm-3.yaml")
    args = parser.parse_args()
    state = args.state.resolve()
    with management_probe(state, args.cli) as (phase, fault, evidence):
        verify(state, args.profile.resolve(), phase, fault, evidence)
    if args.cli:
        directory = state / "evidence"
        directory.mkdir(mode=0o700, exist_ok=True)
        (directory / "region-failover.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
