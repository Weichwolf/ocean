#!/usr/bin/env python3
"""Start a Windows domain-join fixture on the isolated ocean-lab workload segment."""

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path

PROFILES = {
    "server-core": ("10.232.1.20", "02:4f:00:e8:01:20"),
    "windows-11": ("10.232.1.21", "02:4f:00:e8:01:21"),
}
FIRMWARE = Path("/usr/share/OVMF")
HERE = Path(__file__).resolve().parent


def run(*args):
    subprocess.run(args, check=True)


def media_digest(image):
    with image.open("rb") as media:
        return hashlib.file_digest(media, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--iso", required=True, type=Path)
    parser.add_argument("--profile", required=True, choices=PROFILES)
    parser.add_argument("--answer-file", type=Path, help="optional private Autounattend.xml")
    parser.add_argument("--guest-file", action="append", default=[], type=Path,
                        help="optional file to attach to this fixture's private probe ISO")
    args = parser.parse_args()

    state = args.state.resolve()
    iso = args.iso.resolve(strict=True)
    switch = state / "networks/f1-workload/data"
    if not state.is_dir() or state.stat().st_mode & 0o077 or not switch.is_dir():
        parser.error("start the disposable domain-join lab before launching a Windows fixture")
    if not iso.is_file() or iso.suffix.lower() != ".iso":
        parser.error("--iso must identify an operator-supplied installation ISO")
    if args.answer_file and (args.answer_file.name.lower() != "autounattend.xml" or not args.answer_file.is_file()):
        parser.error("--answer-file must identify an Autounattend.xml file")
    if any(not path.is_file() for path in args.guest_file):
        parser.error("each --guest-file must identify a regular file")

    use_tpm = args.profile == "windows-11"
    if use_tpm and not shutil.which("swtpm"):
        parser.error("the Windows 11 Pro profile requires swtpm")
    firmware_code = "OVMF_CODE_4M.secboot.fd" if use_tpm else "OVMF_CODE_4M.fd"
    firmware_vars = "OVMF_VARS_4M.ms.fd" if use_tpm else "OVMF_VARS_4M.fd"

    fixture = state / args.profile
    fixture.mkdir(mode=0o700)
    disk = fixture / "disk.qcow2"
    variables = fixture / "OVMF_VARS.fd"
    probe_iso = fixture / "probe.iso"
    shutil.copyfile(FIRMWARE / firmware_vars, variables)
    run("qemu-img", "create", "-q", "-f", "qcow2", disk, "64G")
    probe_files = [HERE / "verify_windows_domain_join.ps1"]
    if args.answer_file:
        probe_files.append(args.answer_file.resolve())
    probe_files.extend(path.resolve() for path in args.guest_file)
    run("genisoimage", "-quiet", "-J", "-V", "OCEAN_PROBE", "-o", probe_iso, *probe_files)
    probe_iso.chmod(0o600)
    ip, mac = PROFILES[args.profile]
    (fixture / "media.json").write_text(json.dumps({
        "profile": args.profile,
        "installationMediaSHA256": media_digest(iso),
        "guestAddress": ip,
        "directoryDNS": "10.232.1.11",
    }, indent=2) + "\n")

    def qemu_path(path):
        return str(path).replace(",", ",,")

    command = [
        "nice", "-n", "10", "qemu-system-x86_64", "-accel", "kvm", "-cpu", "host",
        "-machine", "q35,smm=on", "-m", "4096", "-smp", "2", "-name", f"ocean-{args.profile}",
        "-display", "none", "-vnc", f"unix:{fixture / 'vnc'}", "-qmp",
        f"unix:{fixture / 'qmp'},server=on,wait=off", "-monitor", "none", "-boot", "once=d",
        "-serial", f"file:{fixture / 'guest-serial.log'}",
        "-drive", f"if=pflash,format=raw,readonly=on,file={qemu_path(FIRMWARE / firmware_code)}",
        "-drive", f"if=pflash,format=raw,file={qemu_path(variables)}",
        "-drive", f"if=none,id=disk,format=qcow2,file={qemu_path(disk)}",
        "-device", "ide-hd,drive=disk,bus=ide.0",
        "-drive", f"if=none,id=installer,format=raw,media=cdrom,readonly=on,file={qemu_path(iso)}",
        "-device", "ide-cd,drive=installer,bus=ide.1",
        "-drive", f"if=none,id=probe,format=raw,media=cdrom,readonly=on,file={qemu_path(probe_iso)}",
        "-device", "ide-cd,drive=probe,bus=ide.2",
        "-netdev", f"vde,id=tenant,sock={qemu_path(switch)}",
        "-device", f"e1000e,netdev=tenant,mac={mac}",
        "-device", "qemu-xhci", "-device", "usb-tablet",
    ]

    if use_tpm:
        tpm_state = fixture / "tpm"
        tpm_state.mkdir(mode=0o700)
        tpm_socket = fixture / "tpm.sock"
        command.extend([
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-chardev", f"socket,id=chrtpm,path={qemu_path(tpm_socket)}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis,tpmdev=tpm0",
        ])
        with subprocess.Popen([
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}",
            "--ctrl", f"type=unixio,path={tpm_socket}",
        ]) as tpm:
            try:
                deadline = time.monotonic() + 5
                while not tpm_socket.is_socket():
                    if tpm.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("the TPM emulator did not start")
                    time.sleep(0.05)
                run(*command)
            finally:
                if tpm.poll() is None:
                    tpm.terminate()
    else:
        run(*command)


if __name__ == "__main__":
    main()
