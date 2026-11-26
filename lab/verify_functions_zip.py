#!/usr/bin/env python3
"""Verify production and staging ZIP releases from outside the Function workers."""

import argparse
import io
import ipaddress
import json
import re
import shlex
import sys
import time
import zipfile
from pathlib import Path
from uuid import UUID, uuid4

sys.dont_write_bytecode = True
from prepare_functions import SCM_DOMAIN, ZIP_RUNTIME
from region import DEST, OPERATOR, ROOT, VIP, etcdctl, eventually, ssh, upload
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client
from verify_wireguard_hosts import macvlan

OBSERVER = "farm-1-node-03"
SOURCES = ROOT / "tests/e2e/testdata/workloads/functions-zip"


def archive(release):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr("host.json", (SOURCES / "host.json").read_bytes())
        if release != "unindexed":
            for name in ("hello/function.json", "hello/index.js"):
                package.writestr(name, (SOURCES / name).read_bytes())
            package.writestr("hello/package-version.js", "module.exports = " + json.dumps(release) + ";\n")
    return data.getvalue()


def placement_scope(tenant, subscription):
    return f"/ocean/v1/regions/farm-1/tenants/{UUID(tenant)}/arm/{UUID(subscription)}"


def configure_scm_dns(state, app, enabled):
    if not re.fullmatch(r"fxzip[0-9a-f]{10}", app):
        raise RuntimeError("the SCM probe requires a disposable Functions App name")
    hosts = [f"{app}.{SCM_DOMAIN}", f"{app}-staging.{SCM_DOMAIN}"]
    record = "host-record=" + ",".join([*hosts, VIP])
    for node in ("farm-1-node-01", "farm-1-node-02"):
        filename = f"{DEST}/dnsmasq.conf"
        existing = ssh(state, node, f"cat {filename}").decode().splitlines()
        wanted = [line for line in existing if line != record]
        if enabled:
            wanted.append(record)
        if wanted != existing:
            upload(state, node, {"dnsmasq.conf": ("\n".join(wanted) + "\n").encode()})
            ssh(state, node, f"sudo dnsmasq --test --conf-file={filename} && sudo systemctl restart ocean-dns.service")
    if enabled:
        for host in hosts:
            eventually(lambda: ssh(state, OPERATOR,
                                   f'test "$(getent ahostsv4 {host} | awk \'NR==1 {{ print $1 }}\')" = {VIP}'))


def endpoint(state, resource_id, tenant):
    _, _, subscription, _, group, _, path = resource_id.split("/", 6)
    record = f"{placement_scope(tenant, subscription)}/containers/{group.lower()}/{path.lower()}"
    # Only the assigned private destination and host are returned from the regional lab store.
    program = "import json,sys; r=json.load(sys.stdin)['reservation']; print(r['privateIPv4'], r['hostId'])"
    response = ssh(state, OPERATOR, etcdctl(f"get {record} --print-value-only") + " | " + shlex.join(["python3", "-c", program]))
    address, host = response.decode().split()
    ip = ipaddress.IPv4Address(address)
    if ip not in ipaddress.IPv4Network("10.89.1.0/24") or host == OBSERVER:
        raise RuntimeError("the probe requires an independent host on the workload subnet")
    return address, host


def verify(state):
    prepare_operator_client(state, ("arm_cli.py", "functions_cli.py", "functions_zip_cli.py", "application_gateway_cli.py",
                                    "arm_rbac_cli.py", "testdata/arm-contract.tsv"))
    folder = ssh(state, OPERATOR, "mktemp -d /tmp/ocean-functions-zip.XXXXXXXX").decode().strip()
    if not folder.startswith("/tmp/ocean-functions-zip.") or Path(folder).parent != Path("/tmp"):
        raise RuntimeError("the operator did not allocate a disposable Functions test directory")
    namespace = "ocean-fxzip-" + uuid4().hex[:8]
    packages = {release + ".zip": archive(release) for release in ("first", "second", "unindexed")}
    upload(state, OPERATOR, packages, folder)
    observing = False
    cleaned = False
    scope = None
    app = None

    def cli(phase):
        print(f"Functions ZIP phase {phase}", flush=True)
        return json.loads(ssh(state, OPERATOR, shlex.join(["python3", "-B", f"{CLIENT}/functions_zip_cli.py",
            "--settings", f"{CLIENT}/operator.secret", "--matrix", f"{CLIENT}/arm-contract.tsv", "--folder", folder,
            "--image", ZIP_RUNTIME, "--scm", SCM_DOMAIN, "--phase", phase]), timeout=420))

    def call(address, key=None):
        config = (f'header = "x-functions-key: {key}"\n' if key else "").encode()
        result = ssh(state, OBSERVER, shlex.join(["sudo", "ip", "netns", "exec", namespace, "curl", "--noproxy", "*", "-sS",
            "--config", "-", "--max-time", "4", "--write-out", "\n%{http_code}", f"http://{address}/api/hello"]), config)
        body, status = result.decode().rsplit("\n", 1)
        return int(status), body.strip()

    def assert_releases(releases, endpoints, keys):
        checked = {}
        for label, expected in releases.items():
            address = endpoints[label][0]

            def check():
                if call(address, keys[label]) != (200, expected):
                    raise RuntimeError(f"{label} did not execute the expected package and app settings")

            eventually(check, 25)
            foreign = next(value for name, value in keys.items() if name != label)
            if call(address)[0] != 401 or call(address, foreign)[0] != 401:
                raise RuntimeError(f"{label} accepted a missing or foreign Function key")
            checked[label] = {"version": expected.split(":")[1], "response": expected, "missingAndForeignKeysRejected": True}
        return checked

    try:
        customer = cli("tenant")
        scope = placement_scope(customer["tenant"], customer["subscription"])
        policy = json.dumps({"pools": ["lab-default"], "quota": {"cpuMillis": 1500, "memoryMiB": 832}})
        ssh(state, OPERATOR, etcdctl(shlex.join(["put", scope + "/placement-policy", policy])))
        app = customer["app"]
        configure_scm_dns(state, app, True)
        setup = cli("create")
        keys = setup.pop("probeKeys")
        endpoints = {"production": endpoint(state, setup["productionId"], setup["tenant"]),
                     "staging": endpoint(state, setup["slotId"], setup["tenant"])}
        if endpoints["production"][0] == endpoints["staging"][0]:
            raise RuntimeError("production and staging share a private endpoint")
        ssh(state, OBSERVER, f"sudo ip netns add {namespace}")
        observing = True
        ssh(state, OBSERVER, f"set -eu\nsudo ip -n {namespace} link set lo up\n" +
            macvlan(namespace, "work0", "probe0", "10.89.1.3/24"))
        initial = {"production": "zip:first:production:production", "staging": "zip:second:staging:staging"}
        before = assert_releases(initial, endpoints, keys)
        failed = cli("reject")
        recovered = assert_releases(initial, endpoints, keys)
        started = time.monotonic()
        swap = cli("swap")
        after = assert_releases({"production": "zip:second:staging:production", "staging": "zip:first:production:staging"}, endpoints, keys)
        swap["verifiedEndToEndMs"] = round((time.monotonic() - started) * 1000)
        if any(endpoint(state, setup[field], setup["tenant"]) != endpoints[label]
               for label, field in (("production", "productionId"), ("staging", "slotId"))):
            raise RuntimeError("the swap changed a slot's private endpoint or worker placement")
        evidence = setup | {"runtime": ZIP_RUNTIME, "scmDomain": SCM_DOMAIN, "workerBindings": endpoints, "before": before,
                            "failedDeployment": failed, "recovered": recovered, "swap": swap, "after": after}
    except Exception:
        try:
            cli("cleanup")
            cleaned = True
        except RuntimeError as error:
            print(f"Fixture cleanup failed. Its protected state is in {folder} on the operator guest. {error}", file=sys.stderr)
        raise
    else:
        evidence.update(cli("cleanup"))
        cleaned = True
        return evidence
    finally:
        if observing:
            ssh(state, OBSERVER, f"sudo ip netns delete {namespace}")
        if app:
            configure_scm_dns(state, app, False)
        if cleaned:
            if scope is not None:
                usage = ssh(state, OPERATOR, etcdctl("get " + scope + "/placement-usage --print-value-only"))
                if usage and json.loads(usage) != {"cpuMillis": 0, "memoryMiB": 0}:
                    raise RuntimeError("the acceptance run retained tenant placement quota")
                ssh(state, OPERATOR, etcdctl("del " + scope + "/placement-policy"))
            ssh(state, OPERATOR, shlex.join(["rm", "-r", "--", folder]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = verify(state)
    output = state / "evidence/functions-zip-slots.json"
    output.parent.mkdir(mode=0o700, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("Azure CLI verified authenticated ZIP deployment, failed activation and recovery, both slot responses, and cleanup.")


if __name__ == "__main__":
    main()
