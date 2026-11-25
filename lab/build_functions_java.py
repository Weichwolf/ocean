#!/usr/bin/env python3
"""Build two Java 21 Functions fixtures with rootless Podman and pinned dependencies."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/e2e/testdata/workloads/functions-java"
MAVEN = "https://repo.maven.apache.org/maven2/com/microsoft/azure/functions"
LIBRARIES = (
    ("azure-functions-java-library", "3.1.0", "b7af2c4aca4f506f957ea260c2884ac92557fdb5bf3f71eda9584e5eb1326093"),
    ("azure-functions-java-core-library", "1.2.0", "3271b9c138cbfddb5b3d9090ca8578eb95084423bf57dc6bd7b22492c60c2bbf"),
)


def build(cache=None):
    image_store = subprocess.check_output(["podman", "info", "--format", "{{.Host.Security.Rootless}}"], text=True)
    if image_store.strip() != "true":
        raise RuntimeError("Functions fixtures must use rootless Podman")
    with tempfile.TemporaryDirectory(prefix="ocean-java-fixtures-") as folder:
        stage = Path(folder) / "source"
        shutil.copytree(FIXTURE, stage)
        for artifact, version, digest in LIBRARIES:
            name = f"{artifact}-{version}.jar"
            if cache is None:
                with urllib.request.urlopen(f"{MAVEN}/{artifact}/{version}/{name}", timeout=25) as reply:
                    data = reply.read(1 << 20)
            else:
                data = (cache / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError(f"{name} differs from the fixture lock")
            (stage / name).write_bytes(data)
        result = {}
        for version in ("v1", "v2"):
            image = f"localhost/ocean-functions-java:{version}"
            subprocess.run(["nice", "-n", "10", "podman", "build", "--pull=missing", "--no-cache", "--timestamp", "1704067200",
                            "--build-arg", f"FIXTURE_VERSION={version}", "--tag", image, stage], cwd=ROOT, check=True)
            digest = subprocess.check_output(["podman", "image", "inspect", image, "--format", "{{.Digest}}"], text=True).strip()
            if len(digest) != 71 or not digest.startswith("sha256:"):
                raise RuntimeError("Podman did not report a fixture digest")
            result[version] = {"image": image, "digest": digest}
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, help="verify and use Java Functions libraries from this directory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.cache)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
        json.dump(result, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
