#!/usr/bin/env python3
"""Exercise Azure CLI identity sign-in through two separate local faults."""

import argparse
import hashlib
import json
import shlex
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
from keycloak import APP, DISABLED_APP, REPLICAS, SERVICE, TENANT, USER, provider_health
from region import ARM, DEST as REGION, GRAPH, IDENTITY, OAUTH, OPERATOR, ROOT, etcdctl, eventually, ssh, upload
from verify_postgres import verify as verify_database

CLIENT = "/opt/ocean-identity-check"
AZURE_CLI_SHA = "2ec5ed9e36f998752ea02c9a85a0e0c1cb215a8effb8c5da75d4d8dd00b7c57b"
SUBSCRIPTION = "02dc534c-e5d8-451d-a364-a5b03b170462"


def prepare_client(state, azure_cli_package=None, subscription=False):
    if azure_cli_package is not None:
        with azure_cli_package.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != AZURE_CLI_SHA:
                raise RuntimeError("Azure CLI package does not match the pinned Microsoft release")
        ssh(state, OPERATOR, 'set -eu; umask 077; archive="$(mktemp /tmp/azure-cli.XXXXXX.deb)"; '
            'trap \'rm -f -- "$archive"\' EXIT; cat > "$archive"; sudo dpkg -i "$archive"', azure_cli_package.read_bytes())
    ssh(state, OPERATOR, "command -v az")
    pki = state / "identity-pki"
    config = {
        "ca": f"{REGION}/pki/ingress-ca.pem",
        "arm": f"https://{ARM}", "graph": f"https://{GRAPH}", "provider": f"https://{OAUTH}", "authority": f"https://{IDENTITY}",
        "tenant": TENANT, "user": USER, "password": (pki / "user.secret").read_text(),
        "app": APP, "secret": (pki / "app.secret").read_text(),
        "disabledApp": DISABLED_APP, "disabledSecret": (pki / "disabled-app.secret").read_text(),
    }
    if subscription:
        config.update({"subscription": SUBSCRIPTION, "location": "farm-1"})
    upload(state, OPERATOR, {
        "settings.secret": json.dumps(config).encode(),
        "identity_cli.py": (ROOT / "tests/e2e/identity_cli.py").read_bytes(),
    }, CLIENT)


def login(state):
    payload = ssh(state, OPERATOR, f"python3 {CLIENT}/identity_cli.py --settings {CLIENT}/settings.secret")
    return json.loads(payload)


def check_ingress(state):
    ssh(state, OPERATOR, f"test \"$(curl -sS --max-time 4 --cacert {REGION}/pki/ingress-ca.pem "
        f"-o /dev/null -w '%{{http_code}}' https://{OAUTH}/admin/realms)\" = 403")
    ssh(state, OPERATOR, f"test \"$(curl -sS --max-time 4 --cacert {REGION}/pki/ingress-ca.pem "
        f"-o /dev/null -w '%{{http_code}}' https://{OAUTH}/health/ready)\" = 403")


def prepare_subscription(state):
    key = f"/ocean/v1/regions/farm-1/tenants/{TENANT}/subscription"
    existing = ssh(state, OPERATOR, etcdctl(f"get {key} --print-value-only")).strip()
    if existing:
        if json.loads(existing).get("subscriptionId") != SUBSCRIPTION:
            raise RuntimeError("the fixture tenant already uses a different subscription")
    else:
        # This disposable realm predates the operator onboarding API. Obtain
        # the real, signed subjects before assigning the lab subscription.
        subjects = login(state)
        data = json.dumps({"tenantId": TENANT, "subscriptionId": SUBSCRIPTION,
                           "displayName": "Ocean identity lab", "members": [subjects["user"], subjects["application"]]})
        ssh(state, OPERATOR, etcdctl(f"put {key} {shlex.quote(data)}"))
    prepare_client(state, subscription=True)


def verify(state, azure_cli_package=None):
    prepare_client(state, azure_cli_package)
    check_ingress(state)
    prepare_subscription(state)
    begin = time.monotonic()
    baseline = login(state)
    print(f"Fresh user and application sign-ins passed in {time.monotonic() - begin:.2f}s.", flush=True)
    evidence = {"baseline": baseline}

    def verify_login(label, started, limit):
        observed = eventually(lambda: login(state), limit)
        seconds = time.monotonic() - started
        if observed != baseline or seconds > limit:
            raise RuntimeError(f"{label} failed the {limit}s recovery or principal consistency check")
        evidence[label] = {"durationSeconds": round(seconds, 2), **observed}
        print(f"{label}: fresh sign-ins and credential denials passed within {seconds:.2f}s.", flush=True)

    failed = next(iter(REPLICAS))
    try:
        start = time.monotonic()
        ssh(state, failed, f"sudo systemctl stop {SERVICE}")
        verify_login("Keycloak instance failure", start, 75)
    finally:
        ssh(state, failed, f"sudo systemctl start --no-block {SERVICE}")
        eventually(lambda: provider_health(state, failed), 100)
    verify_database(state, lambda _old, _new, started: verify_login("PostgreSQL primary failure", started, 120))
    directory = state / "evidence"
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "identity-failover.json").write_text(json.dumps(evidence, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--azure-cli-package", type=Path)
    args = parser.parse_args()
    verify(args.state.resolve(), args.azure_cli_package)


if __name__ == "__main__":
    main()
