"""Build and run a primary Samba AD controller in a private Podman volume."""

import fcntl
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

STATE = Path("/var/lib/ocean-ad")
ADMIN_SECRET = Path("/run/secrets/ocean-directory-bootstrap")
SCRIPT = Path(__file__).resolve()
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NETBIOS = re.compile(r"[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?")
DIRECTORY_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def directory_settings():
    domain = os.environ["OCEAN_AD_DNS_NAME"]
    netbios = os.environ["OCEAN_AD_NETBIOS_NAME"]
    ident = os.environ["OCEAN_AD_DIRECTORY_ID"]
    address = ipaddress.IPv4Address(os.environ["OCEAN_AD_ADDRESS"])
    labels = domain.split(".")
    if (len(labels) < 2 or len(domain) > 253 or any(not DNS_LABEL.fullmatch(label) for label in labels)
            or not NETBIOS.fullmatch(netbios) or not DIRECTORY_ID.fullmatch(ident)
            or address.is_loopback or address.is_multicast or address.is_unspecified):
        raise ValueError("invalid directory configuration")
    return {"directoryId": ident, "domain": domain, "netbios": netbios, "address": str(address)}


def bootstrap_password():
    fd = os.open(ADMIN_SECRET, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("the bootstrap secret must be a private file")
        raw = stream.read(257).rstrip(b"\n")
    if not re.fullmatch(rb"[!-~]{24,128}", raw):
        raise ValueError("invalid bootstrap credential")
    return raw.decode("ascii")


def provision(root, settings):
    from samba.netcmd.main import samba_tool

    # Run the Samba CLI in-process so the bootstrap password never enters argv.
    code = samba_tool(
        "domain", "provision", "--realm=" + settings["domain"].upper(), "--domain=" + settings["netbios"],
        "--server-role=dc", "--dns-backend=SAMBA_INTERNAL", "--host-name=dc01",
        "--host-ip=" + settings["address"], "--targetdir=" + str(root),
        "--adminpass=" + bootstrap_password(), "--option=dns forwarder =",
        "--option=vfs objects = dfs_samba4 acl_xattr xattr_tdb",
        "--option=xattr_tdb:file = " + str(root / "private/sysvol-xattrs.tdb"),
    )
    if code:
        raise RuntimeError("Samba could not provision the primary controller")
    config = root / "etc/smb.conf"
    config_text = config.read_text()
    # The policy path must remain traversable by the authenticated SMB worker.
    # Move it on the same volume to preserve the inode associations of xattr_tdb.
    sysvol = root / "state/sysvol"
    sysvol.rename(root / "sysvol")
    config_text = config_text.replace(str(sysvol), str(root / "sysvol"))
    header = re.search(r"(?mi)^\[globals?\]$", config_text)
    if not header:
        raise RuntimeError("Samba did not generate its global configuration")
    globals_ = ("\n\tbind interfaces only = yes\n\tinterfaces = lo " + settings["address"]
                + "\n\tpid directory = " + str(root / "run"))
    config.write_text(config_text[:header.end()] + globals_ + config_text[header.end():])
    (root / "run").mkdir(mode=0o700)
    root.chmod(0o711)
    (root / "private").chmod(0o700)
    subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolcheck", "-s", str(config)], check=True, timeout=30)


def initialize(settings):
    checkpoint = STATE / "controller.json"
    if checkpoint.exists():
        record = json.loads(checkpoint.read_text())
        if record.get("settings") != settings or not re.fullmatch(r"controller-[a-f0-9]{16}", record.get("root", "")):
            raise ValueError("the persistent directory belongs to another controller")
        path = STATE / record["root"] / "etc/smb.conf"
        if not path.is_file():
            raise RuntimeError("the active controller configuration is missing")
        return path

    # Until the checkpoint is published, the staged Samba identity has never
    # started listening. Only abandoned attempts can be discarded here.
    for abandoned in STATE.glob("controller-*"):
        if abandoned.is_dir() and re.fullmatch(r"controller-[a-f0-9]{16}", abandoned.name):
            shutil.rmtree(abandoned)
    root = STATE / ("controller-" + secrets.token_hex(8))
    root.mkdir(mode=0o700)
    with (root / "bootstrap.log").open("xb") as diagnostics:
        subprocess.run([sys.executable, str(SCRIPT), "provision", str(root)], check=True, timeout=150,
                       stdin=subprocess.DEVNULL, stdout=diagnostics, stderr=diagnostics)
    record = {"settings": settings, "root": root.name}
    temporary = STATE / ".controller.json.pending"
    with temporary.open("w") as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(checkpoint)
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return root / "etc/smb.conf"


def wait_for_address(address):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((address, 0))
                return
            except OSError:
                time.sleep(0.25)
    raise RuntimeError("the assigned directory address did not become available")


def serve(settings):
    os.umask(0o077)
    if not STATE.is_mount():
        raise RuntimeError("the directory requires its own persistent volume")
    STATE.chmod(0o711)
    with (STATE / "owner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wait_for_address(settings["address"])
        config = initialize(settings)
        Path("/run/samba").mkdir(mode=0o755, parents=True, exist_ok=True)
        process = subprocess.Popen(["/usr/sbin/samba", "-F", "--debug-stdout", "-s", str(config)], stdin=subprocess.DEVNULL)
        stopping = False

        def stop(_signum, _frame):
            nonlocal stopping
            stopping = True
            process.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        status = process.wait()
        return 0 if stopping else status


def stop_before_service(_signum, _frame):
    raise SystemExit(0)


if __name__ == "__main__":
    try:
        settings = directory_settings()
        if len(sys.argv) == 3 and sys.argv[1] == "provision":
            provision(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 1:
            signal.signal(signal.SIGTERM, stop_before_service)
            signal.signal(signal.SIGINT, stop_before_service)
            sys.exit(serve(settings))
        else:
            raise ValueError("unsupported directory command")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        # Provisioning diagnostics remain in the private volume.
        print(f"Directory controller failed ({type(error).__name__}).", file=sys.stderr)
        sys.exit(1)
