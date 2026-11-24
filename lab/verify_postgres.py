#!/usr/bin/env python3
"""Verify watchdog fencing and PostgreSQL recovery in the local KVM lab."""

import argparse
import json
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
from postgres import SERVICE, cluster_health, primary, sql
from region import NODES, eventually, ssh


def watch_qemu(path, ready, evidence):
    """Observe the watchdog and reset from the host, including while SSH is down."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as socket_:
            socket_.settimeout(45)
            socket_.connect(str(path))
            with socket_.makefile("rb") as messages:
                greeting = json.loads(messages.readline())
                if "QMP" not in greeting:
                    raise RuntimeError("unexpected QMP greeting")
                socket_.sendall(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
                while packet := messages.readline():
                    message = json.loads(packet)
                    if message.get("id") == "capabilities":
                        if "return" not in message:
                            raise RuntimeError("QMP capability negotiation failed")
                        ready.set()
                    if message.get("event") == "WATCHDOG":
                        evidence["watchdog"] = time.monotonic()
                        evidence["action"] = message.get("data", {}).get("action")
                    if message.get("event") == "RESET" and "watchdog" in evidence:
                        evidence["reset"] = time.monotonic()
                        return
                raise RuntimeError("QMP disconnected before the watchdog reset")
    except (RuntimeError, OSError, ValueError) as error:
        evidence["error"] = str(error)
        ready.set()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify(state, after_promotion=None):
    leader = primary(state, next(iter(NODES)))
    observer = next(node for node in NODES if node != leader)
    table = "ocean_fence_" + uuid.uuid4().hex
    boot_id = ssh(state, leader, "cat /proc/sys/kernel/random/boot_id").strip()
    # Make sure the commit will require an available synchronous replica.
    eventually(lambda: require(
        int(sql(state, leader, "SELECT count(*) FROM pg_stat_replication WHERE sync_state = 'sync';")) >= 1,
        "no synchronous member is streaming",
    ), 25)
    sql(state, leader,
        f"SET statement_timeout='10s'; CREATE TABLE {table} (value text PRIMARY KEY); "
        f"INSERT INTO {table} VALUES ('acknowledged');", "keycloak")
    deadline = 45
    ready = threading.Event()
    evidence = {}
    listener = threading.Thread(target=watch_qemu, args=(state / "nodes" / leader / "qmp", ready, evidence), daemon=True)
    listener.start()
    try:
        require(ready.wait(5) and "error" not in evidence, f"cannot observe QMP: {evidence}")
        # Keep the failed database member out after a fast guest reboot until
        # the remaining members have had a chance to promote a replacement.
        ssh(state, leader, f"sudo systemctl disable {SERVICE}")
        start = time.monotonic()
        ssh(state, leader, f"sudo systemctl kill --kill-whom=main --signal=STOP {SERVICE}")

        def replacement():
            candidate = primary(state, observer)
            require(candidate != leader, "previous member still holds the leader lock")
            return candidate

        new = eventually(replacement, deadline)
        promotion = time.monotonic()
        require(evidence.get("action") == "reset" and evidence.get("reset", float("inf")) <= promotion,
                f"replacement was observed before a watchdog reset: {evidence}")
        require(sql(state, new, "SELECT pg_is_in_recovery();").strip() == b"f", "replacement does not serve writes")
        require(sql(state, new, f"SELECT value FROM {table};", "keycloak").strip() == b"acknowledged",
                "replacement lost an acknowledged commit")
        print(f"Watchdog reset {leader} after {evidence['reset'] - start:.2f}s. "
              f"{new} became the only observed primary after {promotion - start:.2f}s.", flush=True)

        if after_promotion is not None:
            after_promotion(leader, new, start)
        eventually(lambda: ssh(state, leader, f"sudo systemctl enable --now --no-block {SERVICE}"), 45)
        eventually(lambda: cluster_health(state, observer, leader, "replica"), 70)
        require(ssh(state, leader, "cat /proc/sys/kernel/random/boot_id").strip() != boot_id,
                "the fenced guest did not reboot")
        require(sql(state, leader, "SELECT pg_is_in_recovery();").strip() == b"t",
                "the previous writer did not rejoin as a standby")
        sql(state, new, f"SET statement_timeout='10s'; INSERT INTO {table} VALUES ('after-failover');", "keycloak")
        eventually(lambda: require(sql(state, leader, f"SELECT count(*) FROM {table};", "keycloak").strip() == b"2",
                                   "rejoined standby has not replayed the new writer's commit"), 20)
        print("The replacement retained the acknowledged commit and the fenced member replayed a new write as a standby.",
              flush=True)
    finally:
        try:
            ssh(state, leader, f"sudo systemctl kill --kill-whom=main --signal=CONT {SERVICE}")
        except RuntimeError:
            pass
        eventually(lambda: ssh(state, leader, f"sudo systemctl enable --now --no-block {SERVICE}"), 45)
        active = eventually(lambda: primary(state, observer), 45)
        sql(state, active, f"SET statement_timeout='10s'; DROP TABLE IF EXISTS {table};", "keycloak")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    verify(args.state.resolve())


if __name__ == "__main__":
    main()
