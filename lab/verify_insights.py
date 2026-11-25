#!/usr/bin/env python3
"""Compare keyed HTTPS Function invocations and their scoped Application Insights rows."""

import argparse
import json
import math
import shlex
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

sys.dont_write_bytecode = True
from region import OPERATOR, eventually, ssh, upload
from verify_functions import CUSTOMER
from verify_https_hosts import DEST as HTTPS_FILES, PROBE, cleanup_probe, configure_probe
from verify_identity import CLIENT
from verify_onboarding import prepare_operator_client


def verify(state):
    source = state / "functions-registry/images.json"
    images = json.loads(source.read_text())
    prepare_operator_client(state, ("arm_cli.py", "arm_rbac_cli.py", "functions_cli.py", "application_gateway_cli.py",
                                    "insights_cli.py", "testdata/arm-contract.tsv"))
    upload(state, OPERATOR, {"function-images.json": source.read_bytes()}, CLIENT)
    fixture = f"/tmp/ocean-insights-{uuid4().hex[:12]}.secret"

    def invoke(phase):
        print(f"Insights lab phase {phase}", file=sys.stderr, flush=True)
        args = ["python3", f"{CLIENT}/functions_cli.py", "--settings", f"{CLIENT}/operator.secret", "--matrix",
                f"{CLIENT}/arm-contract.tsv", "--images", f"{CLIENT}/function-images.json", "--fixture", fixture, "--phase",
                phase, "--runtime", "node"]
        return json.loads(ssh(state, OPERATOR, shlex.join(args)))

    probe = False
    try:
        app = invoke("setup")
        invoke("integrate")
        ingress = invoke("publish")
        host, address = app["host"], ingress["httpsIPv4"]
        configure_probe(state, ingress["certificate"].encode(), CUSTOMER, "customer0", address)
        probe = True
        key = ssh(state, OPERATOR, f"python3 -c 'import json; print(json.load(open(\"{fixture}\"))[\"key\"])'").strip()
        upload(state, CUSTOMER, {"function-key.secret": b'header = "x-functions-key: ' + key + b'"\n'}, HTTPS_FILES)

        def request(mode):
            url = f"https://{host}/api/hello?mode={mode}&fixture=discard-this-query-parameter"
            args = ["sudo", "ip", "netns", "exec", PROBE, "curl", "--noproxy", "*", "--silent", "--show-error",
                    "--max-time", "8", "--cacert", f"{HTTPS_FILES}/ca.pem", "--resolve", f"{host}:443:{address}",
                    "--config", f"{HTTPS_FILES}/function-key.secret", "-o", "/dev/null", "-D", "-",
                    "-w", "%{http_code} %{time_total}\n", url]
            lines = ssh(state, CUSTOMER, shlex.join(args)).decode().splitlines()
            status, time_total = lines[-1].split()
            headers = {row.split(":", 1)[0].lower(): row.split(":", 1)[1].strip() for row in lines[:-1] if ":" in row}
            event = {"mode": mode, "code": int(status), "roundTripMs": float(time_total)*1000}
            if "x-ocean-fixture-duration-ms" in headers:
                event["appDurationMs"] = float(headers["x-ocean-fixture-duration-ms"])
            if "x-ocean-fixture-dependency-status" in headers:
                event["dependencyStatus"] = int(headers["x-ocean-fixture-dependency-status"])
            return event

        def ready():
            if request("warmup")["code"] != 200:
                raise RuntimeError("the keyed Node.js fixture is not reachable")
        eventually(ready, 15)
        # The warm-up request completes before this window begins.
        time.sleep(0.2)
        start = datetime.now(timezone.utc)
        modes = ("success", "error", "success", "dependency", "exception", "success")
        results = [request(mode) for mode in modes]
        if [row["code"] for row in results] != [200, 503, 200, 200, 500, 200]:
            raise RuntimeError(f"unexpected Function results: {results}")
        if "dependencyStatus" not in results[3] or any("appDurationMs" not in row for row in results):
            raise RuntimeError("the dependency HTTP response or measured application duration was missing")

        stop = datetime.now(timezone.utc) + timedelta(seconds=1)
        window = f"{start.isoformat()}/{stop.isoformat()}"
        started = time.monotonic()
        args = ["python3", f"{CLIENT}/insights_cli.py", "--fixture", fixture, "--matrix", f"{CLIENT}/arm-contract.tsv",
                "--timespan", window]
        deadline = 60

        def query():
            data = json.loads(ssh(state, OPERATOR, shlex.join(args)))
            if data["summary"][0]["Requests"] != len(results) or len(data["dependencies"]) != 1 or len(data["exceptions"]) != 1:
                raise RuntimeError(f"the controlled trace counts have not arrived: {data['summary']}, "
                                   f"{len(data['dependencies'])} dependencies, {len(data['exceptions'])} exceptions")
            return data

        insights = eventually(query, deadline)
        arrival = time.monotonic() - started
        if arrival > deadline:
            raise RuntimeError("Insights did not converge within the declared reporting delay")
        actual = insights["summary"][0]
        observed = sorted(row["appDurationMs"] for row in results)
        if actual["Errors"] != 2 or abs(actual["ErrorRate"] - 100/3) > 0.01:
            raise RuntimeError("request error count or error rate differs from the HTTPS observations")
        for field, fraction in (("P50", 0.50), ("P95", 0.95)):
            if abs(actual[field] - observed[math.ceil(len(observed)*fraction)-1]) > 10:
                raise RuntimeError(f"{field} differs from measured Function duration by more than 10 ms")
        if sorted(row["ResultCode"] for row in insights["requests"]) != sorted(str(row["code"]) for row in results):
            raise RuntimeError("stored request codes differ from the HTTPS responses")
        for request, sample in zip(results, insights["requests"], strict=True):
            if abs(sample["DurationMs"] - request["appDurationMs"]) > 10 or sample["DurationMs"] > request["roundTripMs"] + 2:
                raise RuntimeError("the stored trace duration did not match the measured invocation")
        dependency = insights["dependencies"][0]
        status = results[3]["dependencyStatus"]
        if dependency["ResultCode"] != str(status) or dependency["Success"] != (status < 400) or dependency["Target"] != "127.0.0.1":
            raise RuntimeError("the dependency row did not report the real storage HTTP response")
        if insights["exceptions"][0]["ExceptionType"] != "RangeError" or any(
                marker in json.dumps(insights) for marker in ("fixture message excluded", "discard-this-query-parameter")):
            raise RuntimeError("exception classification or telemetry field filtering failed")
        return {**insights, "case": "OBS-02", "image": images["node"], "httpsRequests": results,
                "timeUntilQueryMs": round(arrival*1000), "queryDeadlineMs": deadline*1000, "durationToleranceMs": 10}
    finally:
        try:
            if probe:
                ssh(state, CUSTOMER, f"if sudo test -e {HTTPS_FILES}/function-key.secret; then sudo unlink {HTTPS_FILES}/function-key.secret; fi")
                cleanup_probe(state, CUSTOMER)
        finally:
            invoke("cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    result = verify(state)
    output = state / "evidence"
    output.mkdir(mode=0o700, exist_ok=True)
    (output / "application-insights.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Azure CLI queried measured requests, latency, errors, exceptions, and storage dependencies.")


if __name__ == "__main__":
    main()
