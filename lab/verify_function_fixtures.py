#!/usr/bin/env python3
"""Build the Functions fixture images and verify their native runtime on rootless Podman."""

import argparse
import base64
import json
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from build_functions_java import ROOT, build

AZURITE = "mcr.microsoft.com/azure-storage/azurite@sha256:dae2a5f96553962901304b94e72ef87e299d0825e4b679673bcc527a25076fe4"
FIXTURES = ROOT / "tests/e2e/testdata/workloads"


def podman(*args, capture=False):
    reply = subprocess.run(["nice", "-n", "10", "podman", *map(str, args)], capture_output=capture, text=True, check=True, timeout=300)
    return reply.stdout.strip() if capture else None


def build_fixture(runtime):
    image = f"localhost/ocean-functions-{runtime}:fixture"
    podman("build", "--pull=missing", "--timestamp", "1704067200", "--tag", image, FIXTURES / f"functions-{runtime}")
    return image


def run_fixture(image, expected, package=None):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    name = "ocean-native-function-" + secrets.token_hex(6)
    app, storage = name + "-app", name + "-storage"
    master, function_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    account, key = "oceanfixture", base64.b64encode(secrets.token_bytes(64)).decode()
    connection = f"DefaultEndpointsProtocol=http;AccountName={account};AccountKey={key}"
    for service, endpoint in (("Blob", 10000), ("Queue", 10001), ("Table", 10002)):
        connection += f";{service}Endpoint=http://127.0.0.1:{endpoint}/{account}"
    with tempfile.TemporaryDirectory(prefix="ocean-native-function-") as folder:
        directory = Path(folder)
        keys = directory / "secrets"
        keys.mkdir(mode=0o700)
        (keys / "host.json").write_text(json.dumps(
            {"masterKey": {"name": "_master", "value": master, "encrypted": False}, "functionKeys": [], "systemKeys": []}))
        (directory / "storage.env").write_text(f"AZURITE_ACCOUNTS={account}:{key}\n")
        app_env = f"AzureWebJobsStorage={connection}\nAzureWebJobsSecretStorageType=files\nOCEAN_SETTING=fixture\n"
        package_mount = []
        if package is not None:
            app_env += "FUNCTIONS_WORKER_RUNTIME=node\n"
            package_mount = ["--mount", f"type=bind,source={package},target=/home/site/wwwroot,ro,nosuid,nodev"]
        (directory / "app.env").write_text(app_env)

        def request(path, credential=None, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                         method="PUT" if data is not None else "GET")
            if credential is not None:
                req.add_header("x-functions-key", credential)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=3) as result:
                    return result.status, result.read(65536)
            except urllib.error.HTTPError as error:
                return error.code, error.read(65536)

        try:
            podman("run", "--detach", "--name", storage, "--publish", f"127.0.0.1:{port}:80",
                   "--env-file", directory / "storage.env", AZURITE, "azurite", "--silent", "--location", "/data",
                   "--blobHost", "127.0.0.1", "--queueHost", "127.0.0.1", "--tableHost", "127.0.0.1", "--skipApiVersionCheck", capture=True)
            podman("run", "--detach", "--name", app, "--network", f"container:{storage}",
                   "--env-file", directory / "app.env", "--volume", f"{keys}:/azure-functions-host/Secrets",
                   *package_mount, image, capture=True)
            if package is not None:
                mounts = json.loads(podman("inspect", "--format", "{{json .Mounts}}", app, capture=True))
                if not any(item["Destination"] == "/home/site/wwwroot" and not item["RW"] for item in mounts):
                    raise RuntimeError("the deployed Functions code tree is not read-only")
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                try:
                    status, body = request("/admin/functions", master)
                    if status == 200 and any(row["name"] == "hello" for row in json.loads(body)):
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError(f"{image} did not index its HTTP Function")
            status, _ = request("/admin/functions/hello/keys/fixture", master, {"name": "fixture", "value": function_key})
            if status not in (200, 201):
                raise RuntimeError(f"{image} failed to store its Function key")
            if request("/api/hello", function_key) != (200, (expected + "\n").encode()):
                raise RuntimeError(f"{image} returned an unexpected invocation result")
            for credential in (None, secrets.token_urlsafe(32)):
                if request("/api/hello", credential)[0] != 401:
                    raise RuntimeError(f"{image} admitted an invalid invocation credential")
            return podman("image", "inspect", "--format", "{{.Digest}}", image, capture=True)
        finally:
            podman("rm", "--force", "--ignore", "--time", 1, app, capture=True)
            podman("rm", "--force", "--ignore", "--time", 1, storage, capture=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-cache", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if podman("info", "--format", "{{.Host.Security.Rootless}}", capture=True) != "true":
        raise RuntimeError("the fixture verifier requires rootless Podman")
    java = build(args.java_cache)
    fixtures = [(entry["image"], f"java:{version}:fixture") for version, entry in java.items()]
    fixtures.extend((build_fixture(runtime), runtime + ":fixture") for runtime in ("node", "dotnet", "go"))
    results = {image: {"digest": run_fixture(image, expected), "keyPolicyVerified": True} for image, expected in fixtures}
    args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
