#!/usr/bin/env python3
"""Provide out-of-band power-off proof for the rootless KVM lab."""

import base64
import datetime
import json
import os
import select
import subprocess
import tempfile
from pathlib import Path

from region import ROOT, run


def create_authority(state):
    directory = state / "storage-pki"
    key = directory / "lab-fencer.key"
    public = directory / "lab-fencer.pub"
    if not key.exists():
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key], check=True, capture_output=True)
        key.chmod(0o600)
    if not public.exists():
        subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", public], check=True, capture_output=True)
    return public


def exact_qemu_process(state, host):
    control = f"unix:{state.resolve()}/nodes/{host}/qmp,server=on,wait=off".encode()
    identity = f"ocean-{host}".encode()
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if not (entry / "comm").read_bytes().startswith(b"qemu-system-x86"):
                continue
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            pairs = list(zip(arguments, arguments[1:]))
            if (b"-name", identity) in pairs and (b"-qmp", control) in pairs:
                matches.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if len(matches) != 1:
        raise RuntimeError("could not identify the single QEMU process to fence")
    return matches[0]


def sign_terminal_state(state, assignment):
    host = assignment["hostId"]
    pid = exact_qemu_process(state, host)
    fd = os.pidfd_open(pid)
    try:
        run([ROOT / "bin/ocean-lab", "stop", "-state", state, host])
        watch = select.poll()
        watch.register(fd, select.POLLIN)
        if not watch.poll(10000):
            raise RuntimeError("the fenced QEMU process is still alive")
    finally:
        os.close(fd)
    proof = {**assignment, "observation": "PoweredOff", "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    payload = json.dumps(proof, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory(prefix="ocean-fence-attestation-") as temp:
        path = Path(temp) / "attestation.json"
        path.write_bytes(payload)
        key = state / "storage-pki/lab-fencer.key"
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", path],
                                   check=True, capture_output=True).stdout
    return {"attestation": base64.b64encode(payload).decode(), "signature": base64.b64encode(signature).decode()}
