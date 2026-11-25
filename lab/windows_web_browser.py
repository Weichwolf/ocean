#!/usr/bin/env python3
"""Run the Edge Kerberos probe in an unlocked domain employee desktop."""

import argparse
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class Console:
    def __init__(self, endpoint):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(8)
        self.socket.connect(str(endpoint))
        self.stream = self.socket.makefile("rwb")
        if "QMP" not in json.loads(self.stream.readline()):
            raise RuntimeError("missing QMP greeting")
        self.command("qmp_capabilities")

    def close(self):
        self.stream.close()
        self.socket.close()

    def command(self, command, **params):
        self.stream.write(json.dumps({"execute": command, "arguments": params, "id": command}).encode() + b"\n")
        self.stream.flush()
        while True:
            reply = json.loads(self.stream.readline())
            if reply.get("id") != command:
                continue
            if "error" in reply:
                raise RuntimeError(f"Windows fixture console {command}: {reply['error']['desc']}")
            return reply["return"]

    def press(self, *keys):
        self.command("send-key", keys=[{"type": "qcode", "data": key} for key in keys], **{"hold-time": 30})
        time.sleep(0.045)

    def run_dialog(self, command):
        self.press("meta_l", "r")
        time.sleep(1)
        self.press("ctrl", "a")
        ordinary = {" ": "spc", "-": "minus", ".": "dot", "\\": "backslash", "'": "apostrophe"}
        shifted = {"(": "9", ")": "0", "$": "4", "+": "equal", ":": "semicolon", '"': "apostrophe",
                   "_": "minus", "&": "7"}
        for key in command:
            if key in shifted:
                self.press("shift", shifted[key])
            elif key.isupper():
                self.press("shift", key.lower())
            else:
                self.press(ordinary.get(key, key))
        self.press("ret")


def callback_forward(args):
    remote = ("printf 'ocean-relay-ready\\n'; exec timeout 115 socat "
              "TCP-LISTEN:18444,bind=10.232.1.11,reuseaddr,fork TCP:127.0.0.1:19444")
    return subprocess.Popen(["ssh", "-q", "-tt", "-p", str(args.primary_port), "-i", str(args.state / "ssh-key"),
                             "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                             "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=5", "-o", "HostKeyAlias=farm-1-node-01",
                             "-o", "UserKnownHostsFile=" + str(args.state / "known-hosts"),
                             "-R", "127.0.0.1:19444:" + args.callback, "ocean@127.0.0.1", remote],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)


def result(serial, run, forward):
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        if forward.poll() is not None:
            raise RuntimeError("the Windows fixture's callback forwarding process exited")
        position = serial.tell()
        line = serial.readline()
        if not line.endswith("\n"):
            serial.seek(position)
            time.sleep(0.15)
            continue
        if line.startswith("OCEAN-WEB-EDGE "):
            record = json.loads(line.removeprefix("OCEAN-WEB-EDGE "))
            if record.get("run") == run:
                return record
    raise TimeoutError("the Windows desktop did not return the Edge probe result")


def verify(args, config):
    fixture = args.state / "windows-11"
    console = Console(fixture / "qmp")
    try:
        cdrom = next(item for item in console.command("query-block") if item["device"] == "probe")
        previous = cdrom.get("inserted", {}).get("file")
        if not cdrom["removable"] or not previous:
            raise RuntimeError("the Windows fixture does not have its probe CD mounted")
        with tempfile.TemporaryDirectory(prefix="ocean-edge-probe-") as name:
            stage = Path(name)
            settings = stage / "browser.json"
            settings.write_text(json.dumps(config), encoding="utf-8")
            medium = stage / "browser.iso"
            script = Path(__file__).with_name("verify_windows_web_kerberos.ps1")
            subprocess.run(["genisoimage", "-quiet", "-J", "-V", "OCEAN_WEB_TEST", "-o", medium, script, settings], check=True)
            with callback_forward(args) as forward, (fixture / "guest-serial.log").open(encoding="utf-8", errors="replace") as serial:
                try:
                    ready, _, _ = select.select([forward.stdout], [], [], 10)
                    if not ready or forward.stdout.readline().strip() != "ocean-relay-ready":
                        raise RuntimeError("the Windows fixture's callback port was not forwarded")
                    serial.seek(0, os.SEEK_END)
                    console.command("blockdev-change-medium", device="probe", filename=str(medium), format="raw")
                    try:
                        console.run_dialog("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
                                           r'''"& ((Get-Volume -FileSystemLabel OCEAN_WEB_TEST).DriveLetter+':\verify_windows_web_kerberos.ps1')"''')
                        return result(serial, config["run"], forward)
                    finally:
                        console.command("blockdev-change-medium", device="probe", filename=previous, format="raw")
                finally:
                    if forward.poll() is None:
                        forward.terminate()
                        try:
                            forward.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            forward.kill()
                            forward.wait()
    finally:
        console.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--primary-port", type=int, required=True)
    parser.add_argument("--callback", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args, json.load(sys.stdin))))


if __name__ == "__main__":
    main()
