"""Build and run a Samba AD controller in a private Podman volume."""

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
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath

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
    settings = {"directoryId": ident, "domain": domain, "netbios": netbios, "address": str(address)}
    index = os.environ.get("OCEAN_AD_CONTROLLER", "1")
    if index == "2":
        primary = ipaddress.IPv4Address(os.environ["OCEAN_AD_PRIMARY"])
        if primary == address or primary.is_loopback or primary.is_multicast or primary.is_unspecified:
            raise ValueError("invalid primary directory address")
        settings.update(controller=2, primary=str(primary))
    elif index != "1":
        raise ValueError("invalid controller index")
    return settings


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


def configure(root, settings):
    config = root / "etc/smb.conf"
    config_text = config.read_text()
    # Preserve the inode associations in xattr_tdb during the path move.
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
    return config


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
    config = configure(root, settings)
    subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolcheck", "-s", str(config)], check=True, timeout=30)


def primary_ticket(directory, settings):
    realm = settings["domain"].upper()
    config = directory / "krb5.conf"
    config.write_text(f"[libdefaults]\n default_realm = {realm}\n rdns = false\n"
                      f"[realms]\n {realm} = {{\n  kdc = {settings['primary']}\n }}\n")
    cache = "FILE:" + str(directory / "ticket")
    os.environ.update(KRB5_CONFIG=str(config), KRB5CCNAME=cache)
    subprocess.run(["/usr/bin/kinit", "Administrator@" + realm], input=bootstrap_password() + "\n",
                   text=True, check=True, timeout=15)
    return cache


def join_replica(root, settings):
    from samba.netcmd.main import samba_tool

    with tempfile.TemporaryDirectory() as private:
        cache = primary_ticket(Path(private), settings)
        code = samba_tool(
            "domain", "join", settings["domain"], "DC", "--server=dc01." + settings["domain"],
            "--dns-backend=SAMBA_INTERNAL", "--targetdir=" + str(root),
            "--use-kerberos=required", "--use-krb5-ccache=" + cache,
            "--option=dns forwarder =", "--option=vfs objects = dfs_samba4 acl_xattr xattr_tdb",
            "--option=xattr_tdb:file = " + str(root / "private/sysvol-xattrs.tdb"),
        )
        if code:
            raise RuntimeError("Samba could not join the replica")
    configure(root, settings)


def clear_staged_sysvol(path):
    # A previous attempt can have applied some ACLs. Take ownership before
    # entering each directory so the rootless process can remove its own stage.
    os.chown(path, 0, 0, follow_symlinks=False)
    path.chmod(0o700)
    for entry in path.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            clear_staged_sysvol(entry)
        else:
            entry.unlink()
    path.rmdir()


def unpack_sysvol(archive, sysvol):
    with tarfile.open(archive) as policies:
        entries = {}
        for item in policies:
            path = PurePosixPath(item.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts or path in entries
                    or not (item.isreg() or item.isdir())):
                raise RuntimeError("invalid entry in replicated SYSVOL")
            entries[path] = item
        acls = {}
        for path, item in sorted(entries.items(), key=lambda entry: len(entry[0].parts)):
            if path.name.endswith(".NTACL"):
                continue
            acl = entries.get(path.with_name(path.name + ".NTACL"))
            if acl is None or not acl.isreg() or not acl.size:
                raise RuntimeError("the primary did not supply all SYSVOL ACLs")
            target = sysvol.joinpath(*path.parts)
            if item.isdir():
                target.mkdir(mode=0o700)
            else:
                with policies.extractfile(item) as data, target.open("xb") as file:
                    shutil.copyfileobj(data, file)
            with policies.extractfile(acl) as descriptor:
                acls[target] = descriptor.read().decode("utf-8").strip()
        if not acls:
            raise RuntimeError("the primary returned an empty SYSVOL")
        return acls


def install_sysvol_acls(lp, local, sid, sysvol, acls, root_acl):
    from samba import auth
    from samba.dcerpc import security
    from samba.ntacls import setntacl
    from samba.samba3 import param as s3param, passdb

    config = s3param.get_context()
    config.load(lp.configfile)
    config.set("passdb backend", "samba_dsdb:" + local.url)
    passdb.reload_static_pdb()
    mapping = passdb.PDB(config.get("passdb backend"))
    admin_sid = security.dom_sid(f"{sid}-{security.DOMAIN_RID_ADMINISTRATOR}")
    admin_group = security.dom_sid(security.SID_BUILTIN_ADMINISTRATORS)
    uid, _ = mapping.sid_to_id(admin_sid)
    gid, _ = mapping.sid_to_id(admin_group)
    flags = (auth.AUTH_SESSION_INFO_DEFAULT_GROUPS | auth.AUTH_SESSION_INFO_AUTHENTICATED |
             auth.AUTH_SESSION_INFO_SIMPLE_PRIVILEGES)
    session = auth.user_session(local, lp_ctx=lp, dn=f"<SID={admin_sid}>", session_info_flags=flags)
    auth.session_info_set_unix(session, lp_ctx=lp, user_name="Administrator", uid=uid, gid=gid)
    acls[sysvol] = root_acl
    for path, descriptor in sorted(acls.items(), key=lambda entry: len(entry[0].parts), reverse=True):
        setntacl(lp, str(path), descriptor, sid, session, use_ntvfs=False,
                 skip_invalid_chown=True, passdb=mapping, service="sysvol")


def seed_replica(root, settings):
    from samba.auth import system_session
    from samba.credentials import Credentials, MUST_USE_KERBEROS
    from samba.dcerpc import security
    from samba.netcmd.domain.backup import backup_online, smb_sysvol_conn
    from samba.ntacls import SMBHelper
    from samba.param import LoadParm
    from samba.samdb import SamDB

    config = root / "etc/smb.conf"
    sysvol = root / "policy/sysvol"
    sysvol.parent.mkdir(exist_ok=True)
    sysvol.parent.chmod(0o711)
    if sysvol.exists():
        clear_staged_sysvol(sysvol)
    sysvol.mkdir(mode=0o700)
    config.write_text(config.read_text().replace(str(root / "sysvol"), str(sysvol)))
    lp = LoadParm()
    lp.load(str(config))
    local = SamDB(lp=lp, session_info=system_session())
    sid = security.dom_sid(local.get_domain_sid())
    with tempfile.TemporaryDirectory() as private:
        archive = Path(private) / "sysvol.tar.gz"
        cache = primary_ticket(Path(private), settings)
        credentials = Credentials()
        credentials.guess(lp)
        credentials.set_kerberos_state(MUST_USE_KERBEROS)
        credentials.set_named_ccache(cache)
        connection = smb_sysvol_conn("dc01." + settings["domain"], lp, credentials)
        root_acl = SMBHelper(connection, sid).get_acl("", as_sddl=True)
        backup_online(connection, str(archive), sid)
        acls = unpack_sysvol(archive, sysvol)
        # Materialize Samba's POSIX inheritance from the replicated directory
        # before restoring the SMB security descriptors, including custom ACLs.
        subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolreset", "-s", str(config)],
                       check=True, timeout=30)
        install_sysvol_acls(lp, local, sid, sysvol, acls, root_acl)
    subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolcheck", "-s", str(config)], check=True, timeout=30)


def read_checkpoint(checkpoint, settings):
    record = json.loads(checkpoint.read_text())
    if record.get("settings") != settings or not re.fullmatch(r"controller-[a-f0-9]{16}", record.get("root", "")):
        raise ValueError("the persistent directory belongs to another controller")
    root = STATE / record["root"]
    if not (root / "etc/smb.conf").is_file():
        raise RuntimeError("the active controller configuration is missing")
    return root


def write_checkpoint(checkpoint, root, settings):
    temporary = checkpoint.with_suffix(".pending")
    with temporary.open("w") as stream:
        json.dump({"settings": settings, "root": root.name}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(checkpoint)
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def prepare(root, action):
    with (root / (action + ".log")).open("wb") as diagnostics:
        subprocess.run([sys.executable, str(SCRIPT), action, str(root)], check=True, timeout=150,
                       stdin=subprocess.DEVNULL, stdout=diagnostics, stderr=diagnostics)


def initialize(settings):
    checkpoint = STATE / "controller.json"
    if checkpoint.exists():
        return read_checkpoint(checkpoint, settings) / "etc/smb.conf"
    replica = settings.get("controller") == 2
    joined = STATE / "replica-joined.json"
    if joined.exists():
        root = read_checkpoint(joined, settings)
    else:
        # Until the checkpoint is published, the staged identity has never
        # started listening. Only abandoned attempts can be discarded here.
        for abandoned in STATE.glob("controller-*"):
            if abandoned.is_dir() and re.fullmatch(r"controller-[a-f0-9]{16}", abandoned.name):
                shutil.rmtree(abandoned)
        root = STATE / ("controller-" + secrets.token_hex(8))
        root.mkdir(mode=0o700)
        prepare(root, "join" if replica else "provision")
        if replica:
            write_checkpoint(joined, root, settings)

    if replica:
        prepare(root, "seed")
    write_checkpoint(checkpoint, root, settings)
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
        if settings.get("controller") == 2:
            primary = f"\n{settings['primary']} dc01.{settings['domain']}\n"
            hosts = Path("/etc/hosts")
            if primary.strip() not in hosts.read_text().splitlines():
                with hosts.open("a") as stream:
                    stream.write(primary)
        config = initialize(settings)
        # Samba performs authenticated dynamic registration against its own
        # DNS server. The container never uses a host or public resolver.
        Path("/etc/resolv.conf").write_text("nameserver " + settings["address"] + "\n")
        Path("/run/samba").mkdir(mode=0o755, parents=True, exist_ok=True)
        runtime = dict(os.environ, KRB5_CONFIG=str(config.parent.parent / "private/krb5.conf"))
        process = subprocess.Popen(["/usr/sbin/samba", "-F", "--debug-stdout", "-s", str(config)], stdin=subprocess.DEVNULL,
                                   env=runtime)
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
        elif len(sys.argv) == 3 and sys.argv[1] == "join" and settings.get("controller") == 2:
            join_replica(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "seed" and settings.get("controller") == 2:
            seed_replica(Path(sys.argv[2]), settings)
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
