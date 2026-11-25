"""Build and run a Samba AD controller in a private Podman volume."""

import fcntl
import hashlib
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

import sysvol as policy

STATE = Path("/var/lib/ocean-ad")
ADMIN_SECRET = Path("/run/secrets/ocean-directory-bootstrap")
STARTUP = Path("/run/ocean-directory-startup")
SCRIPT = Path(__file__).resolve()
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NETBIOS = re.compile(r"[A-Z](?:[A-Z0-9-]{0,13}[A-Z0-9])?")
DIRECTORY_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
DOMAIN_SID = re.compile(r"S-1-5-21(?:-[0-9]{1,10}){3}")
STARTUP_TOKEN = re.compile(r"[0-9a-f]{32}")


class DirectoryIdentityError(RuntimeError):
    pass


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


def target_kerberos(directory, settings, address):
    realm = settings["domain"].upper()
    config = directory / "krb5.conf"
    config.write_text(f"[libdefaults]\n default_realm = {realm}\n rdns = false\n"
                      f"[realms]\n {realm} = {{\n  kdc = {address}\n }}\n")
    cache = "FILE:" + str(directory / "ticket")
    os.environ.update(KRB5_CONFIG=str(config), KRB5CCNAME=cache)
    return cache


def primary_ticket(directory, settings):
    cache = target_kerberos(directory, settings, settings["primary"])
    realm = settings["domain"].upper()
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


def unpack_sysvol(archive, sysvol, sid):
    with tarfile.open(archive) as policies:
        entries = {}
        for item in policies:
            path = PurePosixPath(item.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts or path in entries or "\\" in item.name
                    or not (item.isreg() or item.isdir())):
                raise RuntimeError("invalid entry in replicated SYSVOL")
            entries[path] = item
        domain = entries.pop(PurePosixPath(policy.DOMAIN_METADATA), None)
        root_acl = entries.pop(PurePosixPath(policy.ROOT_METADATA), None)
        if (domain is None or not domain.isreg() or domain.size > 64 or root_acl is None
                or not root_acl.isreg() or not root_acl.size):
            raise RuntimeError("SYSVOL snapshot is missing its domain or root ACL")
        with policies.extractfile(domain) as value:
            if value.read().decode("ascii") != str(sid):
                raise RuntimeError("SYSVOL snapshot belongs to a different domain")
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
                    file.flush()
                    os.fsync(file.fileno())
            with policies.extractfile(acl) as descriptor:
                acls[target] = descriptor.read().decode("utf-8").strip()
        if not acls:
            raise RuntimeError("the primary returned an empty SYSVOL")
        with policies.extractfile(root_acl) as descriptor:
            acls[sysvol] = descriptor.read().decode("utf-8")
        return acls


def install_sysvol_acls(lp, local, sid, acls):
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
    for path, descriptor in sorted(acls.items(), key=lambda entry: len(entry[0].parts), reverse=True):
        setntacl(lp, str(path), descriptor, sid, session, use_ntvfs=False,
                 skip_invalid_chown=True, passdb=mapping, service="sysvol")


def seed_replica(root, settings):
    config = root / "etc/smb.conf"
    sysvol = root / "policy/sysvol"
    sysvol.parent.mkdir(exist_ok=True)
    sysvol.parent.chmod(0o711)
    if sysvol.exists():
        clear_staged_sysvol(sysvol)
    sysvol.mkdir(mode=0o700)
    policy.replace_config(config, config.read_text().replace(str(root / "sysvol"), str(sysvol)))
    with tempfile.TemporaryDirectory() as private:
        restore_sysvol(config, sysvol, download_policy(config, settings, Path(private)))


def restore_sysvol(config, sysvol, archive):
    from samba.auth import system_session
    from samba.dcerpc.security import dom_sid
    from samba.param import LoadParm
    from samba.samdb import SamDB

    lp = LoadParm()
    lp.load(str(config))
    local = SamDB(lp=lp, session_info=system_session())
    sid = dom_sid(local.get_domain_sid())
    acls = unpack_sysvol(archive, sysvol, sid)
    policy.verify_gpo_versions(sysvol, lp.get("realm").lower(), local)
    # Materialize Samba's POSIX inheritance from the replicated directory
    # before restoring the SMB security descriptors, including custom ACLs.
    subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolreset", "-s", str(config)], check=True, timeout=30)
    # Samba's sysvolcheck expects inherited GPO ACLs on every file.
    # Check that baseline, then verify the source ACLs after applying them.
    subprocess.run(["/usr/bin/samba-tool", "ntacl", "sysvolcheck", "-s", str(config)], check=True, timeout=30)
    install_sysvol_acls(lp, local, sid, acls)
    policy.verify_acls(config, sid, acls)


def download_policy(config, settings, directory):
    archive = directory / policy.ARCHIVE
    target_kerberos(directory, settings, settings["primary"])
    subprocess.run([
        "/usr/bin/smbclient", f"//dc01.{settings['domain']}/{policy.SHARE}", "-s", str(config),
        "-P", "--use-kerberos=required", "--client-protection=encrypt",
        "-c", f"get {policy.ARCHIVE} {archive}",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
    return archive


def refresh_policy(config, settings, previous):
    from samba.param import LoadParm

    with tempfile.TemporaryDirectory() as directory:
        archive = download_policy(config, settings, Path(directory))
        with archive.open("rb") as data:
            digest = hashlib.file_digest(data, "sha256").digest()
        if digest == previous:
            return digest

        lp = LoadParm()
        lp.load(str(config))
        live = Path(lp.get("path", "sysvol"))
        stage = live.parent / ".refresh" / "sysvol"
        stage.parent.mkdir(exist_ok=True)
        stage.parent.chmod(0o711)
        if stage.exists():
            clear_staged_sysvol(stage)
        stage.mkdir(mode=0o700)
        stage_config = Path(directory) / "smb.conf"
        stage_config.write_text(policy.set_share_read_only(config.read_text().replace(str(live), str(stage)), False))
        restore_sysvol(stage_config, stage, archive)
        policy.exchange(live, stage)
        print("SYSVOL policy snapshot installed.", flush=True)
        return digest


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


def initialize(settings, expected_sid):
    checkpoint = STATE / "controller.json"
    if checkpoint.exists():
        return read_checkpoint(checkpoint, settings) / "etc/smb.conf"
    replica = settings.get("controller") == 2
    if expected_sid and not replica:
        raise DirectoryIdentityError("the established primary requires its existing directory volume")
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


def local_domain_sid(config):
    from samba.auth import system_session
    from samba.param import LoadParm
    from samba.samdb import SamDB

    lp = LoadParm()
    lp.load(str(config))
    database = SamDB(lp=lp, session_info=system_session())
    sid = database.get_domain_sid()
    if not DOMAIN_SID.fullmatch(sid):
        raise DirectoryIdentityError("the local directory has an invalid SID")
    return sid


def authorize_startup(sid, challenge):
    if (not DOMAIN_SID.fullmatch(sid) or not STARTUP_TOKEN.fullmatch(challenge)
            or (STARTUP / "offer").read_text() != f"{sid} {challenge}\n"):
        raise DirectoryIdentityError("the startup challenge changed")
    temporary = STARTUP / "approval.pending"
    temporary.write_text(f"{sid} {challenge}\n")
    temporary.replace(STARTUP / "approval")


def wait_for_startup_authorization(sid):
    if not STARTUP.is_mount():
        raise DirectoryIdentityError("startup requires a dedicated temporary container filesystem")
    offer = STARTUP / "offer"
    approval = STARTUP / "approval"
    approval.unlink(missing_ok=True)
    pending = STARTUP / "offer.pending"
    challenge = f"{sid} {secrets.token_hex(16)}\n"
    pending.write_text(challenge)
    pending.replace(offer)
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if approval.exists() and approval.read_text() == challenge:
                return
            time.sleep(0.25)
        raise DirectoryIdentityError("directory startup authorization was not received")
    finally:
        offer.unlink(missing_ok=True)
        approval.unlink(missing_ok=True)


def health(settings):
    import ldb
    from samba import NTSTATUSError
    from samba.credentials import Credentials, MUST_USE_KERBEROS
    from samba.dcerpc.security import dom_sid
    from samba.ndr import ndr_unpack
    from samba.param import LoadParm
    from samba.samdb import SamDB

    root = read_checkpoint(STATE / "controller.json", settings)
    address = settings["address"]
    domain = settings["domain"]
    hostname = f"dc0{settings.get('controller', 1)}.{domain}"
    query = ["/usr/bin/dig", "+time=1", "+tries=1", "+short", "@" + address]
    addresses = subprocess.check_output([*query, hostname, "A"], text=True, timeout=2).split()
    service = subprocess.check_output([*query, "_ldap._tcp.dc._msdcs." + domain, "SRV"],
                                      text=True, timeout=2)
    if addresses != [address] or not any(record.split()[2:] == ["389", hostname + "."]
                                          for record in service.lower().splitlines()):
        raise RuntimeError("controller DNS records are not available")
    lp = LoadParm()
    lp.load(str(root / "etc/smb.conf"))
    with tempfile.TemporaryDirectory() as private:
        # Pin the KDC to this controller so a healthy peer cannot mask a fault.
        target_kerberos(Path(private), settings, address)
        try:
            credentials = Credentials()
            credentials.guess(lp)
            credentials.set_machine_account(lp)
            credentials.set_kerberos_state(MUST_USE_KERBEROS)
            remote = SamDB(url="ldap://" + hostname, lp=lp, credentials=credentials)
            entry, = remote.search(base="", scope=ldb.SCOPE_BASE,
                                   attrs=["dnsHostName", "isSynchronized", "defaultNamingContext"])
            domain_entry, = remote.search(base=entry["defaultNamingContext"][0].decode(), scope=ldb.SCOPE_BASE,
                                          attrs=["objectSid"])
        except (ldb.LdbError, NTSTATUSError) as error:
            raise RuntimeError("controller Kerberos LDAP bind failed") from error
        naming_context = ",".join("dc=" + label for label in domain.split(".")).encode()
        if (entry["dnsHostName"][0].lower() != hostname.encode()
                or entry["isSynchronized"][0] != b"TRUE"
                or entry["defaultNamingContext"][0].lower() != naming_context):
            raise RuntimeError("controller LDAP root does not match the assigned domain")
        print(ndr_unpack(dom_sid, domain_entry["objectSid"][0]))


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
        expected_sid = os.environ.get("OCEAN_AD_EXPECTED_SID", "")
        if expected_sid and not DOMAIN_SID.fullmatch(expected_sid):
            raise DirectoryIdentityError("invalid expected directory SID")
        config = initialize(settings, expected_sid)
        if expected_sid or os.environ.get("OCEAN_AD_REQUIRE_AUTHORIZATION") == "1":
            sid = local_domain_sid(config)
            if expected_sid and sid != expected_sid:
                raise DirectoryIdentityError("the local directory SID differs from the established SID")
            if os.environ.get("OCEAN_AD_REQUIRE_AUTHORIZATION") == "1":
                wait_for_startup_authorization(sid)
        maintain_policy = True
        if settings.get("controller") == 2:
            content = config.read_text()
            configured = policy.set_share_read_only(content, True)
            if content != configured:
                policy.replace_config(config, configured)
        else:
            replica = os.environ.get("OCEAN_AD_REPLICA")
            if replica:
                address = ipaddress.IPv4Address(replica)
                if address.is_loopback or address.is_multicast or address.is_unspecified or replica == settings["address"]:
                    raise ValueError("invalid replica policy address")
            policy.configure_export(config, settings, replica)
            maintain_policy = bool(replica)
        # Samba performs authenticated dynamic registration against its own
        # DNS server. The container never uses a host or public resolver.
        Path("/etc/resolv.conf").write_text("nameserver " + settings["address"] + "\n")
        Path("/run/samba").mkdir(mode=0o755, parents=True, exist_ok=True)
        runtime = dict(os.environ, KRB5_CONFIG=str(config.parent.parent / "private/krb5.conf"))
        # Native DRS notifications handle steady-state writes. Poll as well so
        # a late join or a disconnected partner catches up without a manual sync.
        process = subprocess.Popen([
            "/usr/sbin/samba", "-F", "--debug-stdout", "-s", str(config),
            "--option=dreplsrv:periodic_startup_interval=5",
            "--option=dreplsrv:periodic_interval=15",
        ], stdin=subprocess.DEVNULL, env=runtime)
        policy_worker = None
        if maintain_policy:
            policy_worker = subprocess.Popen([sys.executable, str(SCRIPT), "sync-policy", str(config)],
                                             stdin=subprocess.DEVNULL)
        stopping = False

        def stop(_signum, _frame):
            nonlocal stopping
            stopping = True
            process.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            status = process.wait()
        finally:
            if policy_worker is not None:
                policy_worker.terminate()
                policy_worker.wait()
        return 0 if stopping else status


def sync_policy(config, settings):
    import ldb
    from samba import NTSTATUSError
    from samba.ntacls import XattrBackendError

    digest = None
    while True:
        try:
            if settings.get("controller") == 2:
                digest = refresh_policy(config, settings, digest)
            else:
                policy.publish(config)
        except (OSError, RuntimeError, ValueError, NTSTATUSError, XattrBackendError, ldb.LdbError,
                subprocess.SubprocessError, tarfile.TarError, KeyError) as error:
            print(f"SYSVOL synchronization will retry ({type(error).__name__}).", file=sys.stderr)
        time.sleep(10)


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
        elif len(sys.argv) == 3 and sys.argv[1] == "sync-policy":
            sync_policy(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 2 and sys.argv[1] == "health":
            health(settings)
        elif len(sys.argv) == 2 and sys.argv[1] == "startup-identity":
            offer = STARTUP / "offer"
            if not offer.is_file():
                sys.exit(3)
            print(offer.read_text(), end="")
        elif len(sys.argv) == 4 and sys.argv[1] == "authorize-startup":
            authorize_startup(sys.argv[2], sys.argv[3])
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
