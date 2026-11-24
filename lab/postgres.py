#!/usr/bin/env python3
"""Deploy the PostgreSQL identity database on three local KVM guests."""

import argparse
import concurrent.futures
import json
import secrets
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from region import DEST as REGION, NODES, ca, eventually, leaf, ssh, unit, upload

DEST = "/opt/ocean-postgres"
SERVICE = "ocean-postgres.service"
WATCHDOG = "/dev/ocean-watchdog"


def credential(pki, label):
    path = pki / (label + ".secret")
    try:
        with path.open("x") as file:
            file.write(secrets.token_urlsafe(36))
            path.chmod(0o600)
    except FileExistsError:
        pass
    return path.read_text()


def node_config(name, address, passwords):
    certificate = f"{DEST}/pki/{name}-database.pem"
    key = f"{DEST}/pki/{name}-database.key"
    authority = f"{DEST}/pki/postgres-ca.pem"
    tls = {"sslmode": "verify-full", "sslrootcert": authority}
    hba = ["local all postgres peer", "local all all reject"]
    for member in (*NODES.values(), "127.0.0.1"):
        hba.extend([
            f"hostssl replication replicator {member}/32 scram-sha-256",
            f"hostssl all postgres {member}/32 scram-sha-256",
            f"hostssl postgres rewinder {member}/32 scram-sha-256",
            f"hostssl keycloak keycloak {member}/32 scram-sha-256",
        ])
    return {
        "name": name,
        "scope": "identity",
        "namespace": "/ocean/v1/regions/farm-1/postgres",
        "restapi": {
            "listen": f"{address}:8008", "connect_address": f"{address}:8008",
            "certfile": certificate, "keyfile": key,
            "authentication": {"username": "patroni", "password": passwords["rest"]},
        },
        "ctl": {"cacert": authority},
        "etcd3": {
            "hosts": [f"{member}:2379" for member in NODES.values()],
            "protocol": "https", "cacert": f"{REGION}/pki/storage-ca.pem",
            "cert": f"{DEST}/pki/{name}-patroni.pem", "key": f"{DEST}/pki/{name}-patroni.key",
        },
        "bootstrap": {
            "initdb": ["data-checksums", {"encoding": "UTF8"}],
            "dcs": {
                "ttl": 20, "loop_wait": 2, "retry_timeout": 5,
                "synchronous_mode": True, "synchronous_mode_strict": True, "synchronous_node_count": 1,
                "maximum_lag_on_failover": 1048576, "check_timeline": True, "failsafe_mode": False,
                "postgresql": {"use_pg_rewind": True, "use_slots": True},
            },
            "pg_hba": hba,
        },
        "postgresql": {
            "listen": f"127.0.0.1,{address}:5432", "connect_address": f"{address}:5432",
            "bin_dir": "/usr/lib/postgresql/17/bin", "data_dir": f"{DEST}/data",
            "pgpass": f"{DEST}/state/patroni.pgpass", "use_unix_socket": True,
            "authentication": {
                "superuser": {"username": "postgres", "password": passwords["superuser"], **tls},
                "replication": {"username": "replicator", "password": passwords["replication"], **tls},
                "rewind": {"username": "rewinder", "password": passwords["rewind"], **tls},
            },
            "parameters": {
                "ssl": "on", "ssl_cert_file": certificate, "ssl_key_file": key, "ssl_min_protocol_version": "TLSv1.2",
                "password_encryption": "scram-sha-256", "max_connections": 80, "shared_buffers": "96MB",
                "unix_socket_directories": "/var/run/postgresql",
            },
            "pg_hba": hba,
        },
        "watchdog": {"mode": "required", "device": WATCHDOG, "safety_margin": 5},
    }


def cluster_health(state, observer, member, path):
    address = NODES[member]
    return ssh(state, observer, f"curl --fail --silent --show-error --max-time 2 "
               f"--cacert {DEST}/pki/postgres-ca.pem https://{address}:8008/{path}")


def primary(state, observer):
    writable = []
    for node in NODES:
        try:
            cluster_health(state, observer, node, "primary")
        except RuntimeError:
            continue
        writable.append(node)
    if len(writable) > 1:
        raise ValueError(f"multiple PostgreSQL members are writable: {writable}")
    if not writable:
        raise RuntimeError("no writable PostgreSQL member is reachable")
    return writable[0]


def sql(state, node, statements, database="postgres"):
    command = shlex.join(["sudo", "-u", "postgres", "env", "PGCONNECT_TIMEOUT=2", "psql", "--no-psqlrc",
                          "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--dbname", database])
    return ssh(state, node, command, statements.encode())


def deploy(state):
    for node in NODES:
        ssh(state, node, "sudo systemctl is-active --quiet ocean-etcd.service")
    pki = state / "postgres-pki"
    pki.mkdir(mode=0o700, exist_ok=True)
    # PostgreSQL 17's SCRAM channel binding needs a certificate with a digest
    # algorithm it recognizes. The RSA CA signs server certificates with SHA-256.
    database_ca = ca(pki, "postgres-rsa-ca", "rsa:3072")
    dcs_ca = state / "region-pki/storage-ca.pem", state / "region-pki/storage-ca.key"
    passwords = {name: credential(pki, name) for name in ("superuser", "replication", "rewind", "rest", "keycloak")}

    def install(item):
        name, address = item
        ssh(state, name, "if ! test -x /usr/bin/patroni || ! test -x /usr/lib/postgresql/17/bin/postgres || "
            "! /usr/bin/python3 -c 'import etcd' 2>/dev/null; then "
            "sudo apt-get -qq update && sudo env DEBIAN_FRONTEND=noninteractive apt-get -yqq --no-install-recommends "
            "install patroni postgresql-17 python3-etcd; fi")
        ssh(state, name, "sudo systemctl disable --now patroni.service postgresql.service")
        files = {
            "pki/postgres-ca.pem": database_ca[0].read_bytes(),
            "patroni.secret": json.dumps(node_config(name, address, passwords)).encode(),
            "units/" + SERVICE: unit(f"/usr/bin/patroni {DEST}/patroni.secret", "postgres"),
            "99-ocean-watchdog.rules": (
                'SUBSYSTEM=="watchdog", ATTR{identity}=="i6300ESB timer", '
                'SYMLINK+="ocean-watchdog", OWNER="postgres", MODE="0600"\n'
            ).encode(),
        }
        files.update(leaf(pki, name+"-database", database_ca, "serverAuth",
                          f"IP:{address},IP:127.0.0.1,DNS:localhost", "rsa:3072"))
        files.update(leaf(pki, name+"-patroni", dcs_ca, "clientAuth"))
        upload(state, name, files, DEST, "postgres")
        ssh(state, name, f"sudo install -m 0700 -d -o postgres {DEST}/data {DEST}/state && "
            f"sudo install -m 0644 {DEST}/99-ocean-watchdog.rules /etc/udev/rules.d/ && "
            "sudo udevadm control --reload && sudo udevadm trigger --action=add --subsystem-match=watchdog && "
            f"sudo udevadm settle && sudo -u postgres test -w {WATCHDOG} && "
            f"sudo install -m 0644 {DEST}/units/{SERVICE} /etc/systemd/system/ && "
            f"sudo systemctl daemon-reload && if sudo systemctl is-active --quiet {SERVICE}; then "
            f"sudo systemctl kill --kill-whom=main --signal=HUP {SERVICE}; "
            f"else sudo systemctl enable --now --no-block {SERVICE}; fi")

    # Issue certificates sequentially because openssl updates the CA serial files.
    for name, address in NODES.items():
        leaf(pki, name+"-database", database_ca, "serverAuth", f"IP:{address},IP:127.0.0.1,DNS:localhost", "rsa:3072")
        leaf(pki, name+"-patroni", dcs_ca, "clientAuth")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(NODES)) as pool:
        list(pool.map(install, NODES.items()))
    observer = next(iter(NODES))
    leader = eventually(lambda: primary(state, observer), 90)
    for node in NODES:
        if node != leader:
            eventually(lambda node=node: cluster_health(state, observer, node, "replica"), 90)
    psql = rf"""
SELECT format('CREATE ROLE keycloak LOGIN PASSWORD %L', '{passwords["keycloak"]}')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'keycloak') \gexec
SELECT 'CREATE DATABASE keycloak OWNER keycloak'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'keycloak') \gexec
"""
    sql(state, leader, psql)
    print(f"PostgreSQL is writable on {leader}. Both standby members are streaming.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    deploy(args.state.resolve())


if __name__ == "__main__":
    main()
