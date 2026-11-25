"""Build and run a Samba AD controller in a private Podman volume."""

import fcntl
import hashlib
import ipaddress
import json
import logging
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

import ldb

import domain_backup
import domain_join
import directory_graph
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
GENERATION = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


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
    writer = os.environ.get("OCEAN_AD_WRITER", "1")
    if index not in ("1", "2") or writer not in ("1", "2"):
        raise ValueError("invalid directory controller index")
    if index == "2":
        settings["controller"] = 2
    settings["writer"] = int(writer)
    if index != writer:
        primary = ipaddress.IPv4Address(os.environ["OCEAN_AD_PRIMARY"])
        if primary == address or primary.is_loopback or primary.is_multicast or primary.is_unspecified:
            raise ValueError("invalid primary directory address")
        settings["primary"] = str(primary)
    recovery_name = os.environ.get("OCEAN_AD_RECOVERY_NAME")
    local_name = os.environ.get("OCEAN_AD_CONTROLLER_NAME")
    remote_name = os.environ.get("OCEAN_AD_PEER_NAME")
    if local_name or remote_name:
        if (recovery_name or not local_name or not remote_name or local_name == remote_name
                or any(len(name) > 15 or not DNS_LABEL.fullmatch(name) or name.isdecimal()
                       for name in (local_name, remote_name))):
            raise ValueError("invalid managed controller names")
        settings.update(controllerName=local_name, peerName=remote_name)
    if recovery_name:
        if index != "1" or writer != "1" or len(recovery_name) > 15 or recovery_name in ("dc01", "dc02") or not DNS_LABEL.fullmatch(recovery_name):
            raise ValueError("invalid standalone recovery controller name")
        settings["recoveryName"] = recovery_name
    return settings


def controller_name(settings):
    return settings.get("controllerName") or settings.get("recoveryName") or f"dc0{settings.get('controller', 1)}"


def is_writer(settings):
    return settings.get("controller", 1) == settings.get("writer", 1)


def peer_name(settings):
    return settings.get("peerName") or f"dc0{3 - settings.get('controller', 1)}"


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
    config_text = re.sub(r"(?mi)^[ \t]*(?:bind interfaces only|interfaces|pid directory)[ \t]*=.*\n", "", config_text)
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
        "--server-role=dc", "--dns-backend=SAMBA_INTERNAL", "--host-name=" + controller_name(settings),
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
            "domain", "join", settings["domain"], "DC", "--server=" + peer_name(settings) + "." + settings["domain"],
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
        "/usr/bin/smbclient", f"//{peer_name(settings)}.{settings['domain']}/{policy.SHARE}", "-s", str(config),
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


def checkpoint_identity(settings):
    # Writer and peer are placement decisions. The directory, slot and local
    # address identify the keys and database held in this volume.
    return {key: value for key, value in settings.items() if key not in ("writer", "primary", "peerName")}


def read_checkpoint(checkpoint, settings):
    record = json.loads(checkpoint.read_text())
    saved = record.get("settings")
    if (not isinstance(saved, dict) or checkpoint_identity(saved) != checkpoint_identity(settings)
            or not re.fullmatch(r"controller-[a-f0-9]{16}", record.get("root", ""))):
        raise ValueError("the persistent directory belongs to another controller")
    root = STATE / record["root"]
    if not (root / "etc/smb.conf").is_file():
        raise RuntimeError("the active controller configuration is missing")
    return root


def write_checkpoint(checkpoint, root, settings, *, backup_checksum=None):
    temporary = checkpoint.with_suffix(".pending")
    record = {"settings": checkpoint_identity(settings), "root": root.name}
    if backup_checksum:
        record["backupChecksum"] = backup_checksum
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


def prepare(root, action):
    with (root / (action + ".log")).open("wb") as diagnostics:
        subprocess.run([sys.executable, str(SCRIPT), action, str(root)], check=True, timeout=150,
                       stdin=subprocess.DEVNULL, stdout=diagnostics, stderr=diagnostics)


def initialize(settings, expected_sid):
    checkpoint = STATE / "controller.json"
    if checkpoint.exists():
        root = read_checkpoint(checkpoint, settings)
        pending_backup = os.environ.get("OCEAN_AD_RECOVERY_SHA256")
        if pending_backup and json.loads(checkpoint.read_text()).get("backupChecksum") != pending_backup:
            raise DirectoryIdentityError("the active volume does not match the assigned recovery archive")
        return root / "etc/smb.conf"
    replica = not is_writer(settings)
    if not replica and (expected_sid or settings.get("recoveryName") or settings.get("controllerName")
                        or settings.get("controller") == 2):
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


def backup_identity(settings, sid):
    return {key: settings[key] for key in ("directoryId", "domain", "netbios")} | {"domainSid": sid}


def authorize_join(settings, stage):
    if not is_writer(settings):
        raise DirectoryIdentityError("manage join authorizations on the designated directory writer")
    config = read_checkpoint(STATE / "controller.json", settings) / "etc/smb.conf"
    database = domain_join.open_directory(config)
    expected = os.environ.get("OCEAN_AD_EXPECTED_SID", "")
    if expected and database.get_domain_sid() != expected:
        raise DirectoryIdentityError("the local directory SID differs from the established SID")
    request = domain_join.read_request(sys.stdin.buffer, stage)
    try:
        username = domain_join.managed_join(database, request, stage)
    except ldb.LdbError:
        raise DirectoryIdentityError("Samba could not update the join authorization") from None
    print(json.dumps({"userPrincipalName": username + "@" + settings["domain"],
                      "machineName": request["machineName"], "expiresAt": request["expiresAt"]}))


def backup_domain(settings):
    os.umask(0o077)
    if not is_writer(settings):
        raise DirectoryIdentityError("back up the designated SYSVOL writer")
    config = read_checkpoint(STATE / "controller.json", settings) / "etc/smb.conf"
    sid = local_domain_sid(config)
    realm = settings["domain"].upper()
    with tempfile.TemporaryDirectory() as private:
        directory = Path(private)
        cache = target_kerberos(directory, settings, settings["address"])
        subprocess.run(["/usr/bin/kinit", "Administrator@" + realm], stdout=sys.stderr, check=True, timeout=15)
        snapshot = directory / domain_backup.SYSVOL
        with snapshot.open("xb") as output:
            policy.capture(config, output, verify_directory=True)
        subprocess.run(["/usr/bin/samba-tool", "domain", "backup", "online",
                        "--server=" + controller_name(settings) + "." + settings["domain"], "--targetdir=" + private,
                        "--use-kerberos=required", "--use-krb5-ccache=" + cache, "-s", str(config)],
                       stdin=subprocess.DEVNULL, stdout=sys.stderr, check=True, timeout=120)
        archives = list(directory.glob("samba-backup-*.tar.bz2"))
        if len(archives) != 1:
            raise RuntimeError("Samba did not produce one domain backup")
        after = directory / "sysvol-after.tar.gz"
        with after.open("xb") as output:
            policy.capture(config, output, verify_directory=True)
        if domain_backup.digest(snapshot) != domain_backup.digest(after):
            raise RuntimeError("SYSVOL and its permissions changed during the database backup")
        domain_backup.write_bundle(sys.stdout.buffer, backup_identity(settings, sid), archives[0], snapshot)


def restore_domain(settings, checksum, source=None):
    from contextlib import redirect_stdout
    from samba.netcmd.domain import backup as native
    from samba.netcmd.main import samba_tool
    from samba.param import LoadParm

    os.umask(0o077)
    expected_sid = os.environ.get("OCEAN_AD_EXPECTED_SID", "")
    managed = bool(settings.get("controllerName"))
    if (not (managed or settings.get("recoveryName")) or not is_writer(settings) or not DOMAIN_SID.fullmatch(expected_sid)
            or not re.fullmatch(r"[a-f0-9]{64}", checksum) or not STATE.is_mount()):
        raise DirectoryIdentityError("recovery requires a fresh volume, backup checksum, SID and distinct controller name")
    if any(name != "lo" for _, name in socket.if_nameindex()):
        raise DirectoryIdentityError("restore the controller without any network attachment")
    checkpoint = STATE / "controller.json"
    with (STATE / "owner.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if managed and checkpoint.exists():
            config = read_checkpoint(checkpoint, settings) / "etc/smb.conf"
            if local_domain_sid(config) != expected_sid or json.loads(checkpoint.read_text()).get("backupChecksum") != checksum:
                raise DirectoryIdentityError("the recovery volume already contains a different restore")
            return
        root = STATE / ("controller-" + (checksum[:16] if managed else secrets.token_hex(8)))
        allowed = {"owner.lock", root.name, "controller.pending"} if managed else {"owner.lock"}
        if any(path.name not in allowed for path in STATE.iterdir()):
            raise DirectoryIdentityError("the recovery volume is not empty")
        with tempfile.TemporaryDirectory() as private:
            directory = Path(private)
            domain_backup.read_bundle(source if source is not None else sys.stdin.buffer, directory, checksum,
                                      backup_identity(settings, expected_sid))
            STATE.chmod(0o711)
            if root.exists():
                remove_restore_stage(root)
            root.mkdir(mode=0o700)

            def restore_policy(_native_archive, _native_path, _database, _config):
                config = configure(root, settings)
                if local_domain_sid(config) != expected_sid:
                    raise DirectoryIdentityError("restored Samba database has an unexpected SID")
                text = re.sub(r"(?mi)^[ \t]*(?:vfs objects|xattr_tdb:file)[ \t]*=.*\n", "", config.read_text())
                header = re.search(r"(?mi)^\[globals?\]$", text)
                settings_vfs = "\n\tvfs objects = dfs_samba4 acl_xattr xattr_tdb\n\txattr_tdb:file = " + str(root / "private/sysvol-xattrs.tdb")
                policy.replace_config(config, text[:header.end()] + settings_vfs + text[header.end():])
                restore_sysvol(config, root / "sysvol", directory / domain_backup.SYSVOL)

            # Keep Samba's database recovery and fresh controller identity.
            # Its SYSVOL helper requires host-root VFS privileges. In this
            # one-shot process use the controller's rootless ACL restore.
            original = native.backup_restore
            native.backup_restore = restore_policy
            try:
                with redirect_stdout(sys.stderr):
                    code = samba_tool("domain", "backup", "restore", "--backup-file=" + str(directory / domain_backup.DATABASE),
                                      "--targetdir=" + str(root), "--newservername=" + controller_name(settings),
                                      "--host-ip=" + settings["address"])
                if code:
                    raise RuntimeError("Samba could not restore the domain backup")
                config = root / "etc/smb.conf"
                lp = LoadParm()
                lp.load(str(config))
                if (lp.get("realm").lower() != settings["domain"] or lp.get("workgroup") != settings["netbios"]
                        or lp.get("netbios name").lower() != controller_name(settings) or local_domain_sid(config) != expected_sid):
                    raise DirectoryIdentityError("restored configuration does not match the managed directory")
                database = domain_join.open_directory(config)
                domain_join.revoke_join_accounts(database, restore=True)
                if managed:
                    # Roll the reserved credential forward from the region.
                    # Unrelated AD user and machine secrets stay in the archive.
                    database.setpassword("(objectSid=" + expected_sid + "-500)", bootstrap_password(), False)
                subprocess.run(["/usr/bin/sync", "-f", str(root)], check=True, timeout=30)
                write_checkpoint(checkpoint, root, settings, backup_checksum=checksum if managed else None)
            finally:
                native.backup_restore = original
                if not checkpoint.exists():
                    remove_restore_stage(root)


def remove_restore_stage(root):
    if (root / "sysvol").is_dir():
        clear_staged_sysvol(root / "sysvol")
    shutil.rmtree(root)


def verify_promotion_sysvol(config):
    # An AD policy version can replicate ahead of its files. A mismatched
    # snapshot must never become the authoritative SYSVOL.
    with open(os.devnull, "wb") as output:
        policy.capture(config, output, verify_directory=True)


def promote_writer(config, database):
    from samba import dn_from_dns_name
    from samba.netcmd.fsmo import get_fsmo_roleowner

    verify_promotion_sysvol(config)
    subprocess.run(["/usr/bin/samba-tool", "fsmo", "seize", "--role=all", "--force", "-s", str(config)],
                   timeout=30, check=True, stdout=subprocess.DEVNULL)
    domain = database.domain_dn()
    forest = dn_from_dns_name(database.forest_dns_name())
    roles = {
        "rid": "CN=RID Manager$,CN=System," + domain,
        "pdc": domain,
        "infrastructure": "CN=Infrastructure," + domain,
        "naming": "CN=Partitions," + str(database.get_config_basedn()),
        "schema": database.get_schema_basedn(),
        "domaindns": "CN=Infrastructure,DC=DomainDnsZones," + domain,
        "forestdns": "CN=Infrastructure,DC=ForestDnsZones," + forest,
    }
    owner = ldb.Dn(database, database.get_dsServiceName())
    if any(get_fsmo_roleowner(database, str(dn), role) != owner for role, dn in roles.items()):
        raise DirectoryIdentityError("the local controller does not own every FSMO role")


def require_promoted_volume(config):
    root = config.parent.parent
    if (STATE / "replica-joined.json").is_file():
        records = root / "private/replica-retirements"
        if not any(GENERATION.fullmatch(record.stem) and record.read_text() == record.stem + "\n"
                   for record in records.glob("*.promotion")):
            raise DirectoryIdentityError("a former replica requires a completed local promotion")


def retire_replica(settings, generation, *, promotion=False, status=False):
    from samba.auth import system_session
    from samba.param import LoadParm
    from samba.remove_dc import remove_dc
    from samba.samdb import SamDB

    if not is_writer(settings) or not GENERATION.fullmatch(generation):
        raise DirectoryIdentityError("replica retirement requires the assigned primary")
    os.umask(0o077)
    root = read_checkpoint(STATE / "controller.json", settings)
    expected = os.environ.get("OCEAN_AD_EXPECTED_SID")
    config = root / "etc/smb.conf"
    lp = LoadParm()
    lp.load(str(config))
    database = SamDB(lp=lp, session_info=system_session())
    if (promotion and not expected) or (expected and database.get_domain_sid() != expected):
        raise DirectoryIdentityError("replica retirement requires the established domain")
    records = root / "private/replica-retirements"
    records.mkdir(exist_ok=True)
    receipt = records / (generation + (".promotion" if promotion else ""))
    peer = peer_name(settings).upper()
    with (records / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if receipt.exists():
            if receipt.read_text() != generation + "\n":
                raise DirectoryIdentityError("the local retirement receipt is invalid")
            return
        if status:
            raise DirectoryIdentityError("the local writer promotion has not finished")
        if promotion:
            promote_writer(config, database)
        servers = database.search(base=database.get_config_basedn(), scope=ldb.SCOPE_SUBTREE,
                                  expression=f"(&(objectClass=server)(cn={peer}))", attrs=[])
        if servers:
            # Samba's removal transaction covers the server, account and DNS records.
            remove_dc(database, logging.getLogger("ocean-directory"), peer)
        elif database.search(base=database.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                             expression=f"(&(objectClass=computer)(sAMAccountName={peer}$))", attrs=[]):
            raise DirectoryIdentityError("the retired replica metadata is inconsistent")
        pending = records / (receipt.name + ".pending")
        with pending.open("w") as stream:
            stream.write(generation + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(receipt)
        policy.sync_directory(records)


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
    from samba import NTSTATUSError
    from samba.credentials import Credentials, MUST_USE_KERBEROS
    from samba.dcerpc.security import dom_sid
    from samba.ndr import ndr_unpack
    from samba.param import LoadParm
    from samba.samdb import SamDB

    root = read_checkpoint(STATE / "controller.json", settings)
    address = settings["address"]
    domain = settings["domain"]
    hostname = f"{controller_name(settings)}.{domain}"
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
        if not is_writer(settings):
            primary = f"\n{settings['primary']} {peer_name(settings)}.{settings['domain']}\n"
            hosts = Path("/etc/hosts")
            if primary.strip() not in hosts.read_text().splitlines():
                with hosts.open("a") as stream:
                    stream.write(primary)
        expected_sid = os.environ.get("OCEAN_AD_EXPECTED_SID", "")
        if expected_sid and not DOMAIN_SID.fullmatch(expected_sid):
            raise DirectoryIdentityError("invalid expected directory SID")
        require_authorization = os.environ.get("OCEAN_AD_REQUIRE_AUTHORIZATION") == "1"
        if (settings.get("recoveryName") or settings.get("controllerName")) and (not expected_sid or not require_authorization):
            raise DirectoryIdentityError("the recovered controller requires SID authorization")
        promotion = os.environ.get("OCEAN_AD_PROMOTE")
        if promotion and (not is_writer(settings) or not expected_sid or not require_authorization):
            raise DirectoryIdentityError("writer promotion requires regional SID authorization")
        config = initialize(settings, expected_sid)
        if expected_sid or require_authorization:
            sid = local_domain_sid(config)
            if expected_sid and sid != expected_sid:
                raise DirectoryIdentityError("the local directory SID differs from the established SID")
            if require_authorization:
                wait_for_startup_authorization(sid)
        if promotion:
            retire_replica(settings, promotion, promotion=True)
        if is_writer(settings):
            require_promoted_volume(config)
        content = config.read_text()
        configured = policy.set_share_read_only(content, not is_writer(settings))
        if content != configured:
            policy.replace_config(config, configured)
        maintain_policy = True
        if is_writer(settings):
            replica = os.environ.get("OCEAN_AD_REPLICA")
            if replica:
                address = ipaddress.IPv4Address(replica)
                if address.is_loopback or address.is_multicast or address.is_unspecified or replica == settings["address"]:
                    raise ValueError("invalid replica policy address")
            policy.configure_export(config, settings, replica, peer_name(settings).upper())
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
        workers = []
        if maintain_policy:
            workers.append(subprocess.Popen([sys.executable, str(SCRIPT), "sync-policy", str(config)],
                                            stdin=subprocess.DEVNULL))
        if is_writer(settings):
            workers.append(subprocess.Popen([sys.executable, str(SCRIPT), "expire-joins", str(config)],
                                            stdin=subprocess.DEVNULL))
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
            for worker in workers:
                worker.terminate()
                worker.wait()
        return 0 if stopping else status


def sync_policy(config, settings):
    from samba import NTSTATUSError
    from samba.ntacls import XattrBackendError

    digest = None
    while True:
        try:
            if not is_writer(settings):
                digest = refresh_policy(config, settings, digest)
            else:
                policy.publish(config)
        except (OSError, RuntimeError, ValueError, NTSTATUSError, XattrBackendError, ldb.LdbError,
                subprocess.SubprocessError, tarfile.TarError, KeyError) as error:
            print(f"SYSVOL synchronization will retry ({type(error).__name__}).", file=sys.stderr)
        time.sleep(10)


def expire_joins(config):
    while True:
        try:
            domain_join.revoke_join_accounts(domain_join.open_directory(config))
        except (OSError, RuntimeError, ValueError, KeyError, ldb.LdbError) as error:
            print(f"Join expiration will retry ({type(error).__name__}).", file=sys.stderr)
        time.sleep(10)


def stop_before_service(_signum, _frame):
    raise SystemExit(0)


if __name__ == "__main__":
    try:
        settings = directory_settings()
        if len(sys.argv) == 3 and sys.argv[1] == "provision":
            provision(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "join" and not is_writer(settings):
            join_replica(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "seed" and not is_writer(settings):
            seed_replica(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "sync-policy":
            sync_policy(Path(sys.argv[2]), settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "expire-joins" and is_writer(settings):
            expire_joins(Path(sys.argv[2]))
        elif len(sys.argv) == 2 and sys.argv[1] == "health":
            health(settings)
        elif len(sys.argv) == 2 and sys.argv[1] == "startup-identity":
            offer = STARTUP / "offer"
            if not offer.is_file():
                sys.exit(3)
            print(offer.read_text(), end="")
        elif len(sys.argv) == 4 and sys.argv[1] == "authorize-startup":
            authorize_startup(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3 and sys.argv[1] == "retire-replica":
            retire_replica(settings, sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "promotion-status":
            retire_replica(settings, sys.argv[2], promotion=True, status=True)
        elif len(sys.argv) == 2 and sys.argv[1] == "promotion-preflight" and not is_writer(settings):
            verify_promotion_sysvol(read_checkpoint(STATE / "controller.json", settings) / "etc/smb.conf")
        elif len(sys.argv) == 2 and sys.argv[1] == "backup-domain":
            backup_domain(settings)
        elif len(sys.argv) == 3 and sys.argv[1] == "restore-domain":
            restore_domain(settings, sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "restore-domain-file":
            with open("/run/ocean-directory-recovery.tar", "rb") as archive:
                restore_domain(settings, sys.argv[2], archive)
        elif len(sys.argv) == 2 and sys.argv[1] in ("stage-join", "close-join"):
            authorize_join(settings, stage=sys.argv[1] == "stage-join")
        elif len(sys.argv) == 2 and sys.argv[1] == "graph":
            if not is_writer(settings):
                raise DirectoryIdentityError("Graph tasks require the directory writer")
            config = read_checkpoint(STATE / "controller.json", settings) / "etc/smb.conf"
            database = domain_join.open_directory(config)
            expected = os.environ.get("OCEAN_AD_EXPECTED_SID", "")
            if expected and database.get_domain_sid() != expected:
                raise DirectoryIdentityError("the local directory SID differs from the established SID")
            print(json.dumps(directory_graph.run(database, settings["domain"], sys.stdin.buffer)))
        elif len(sys.argv) == 1:
            signal.signal(signal.SIGTERM, stop_before_service)
            signal.signal(signal.SIGINT, stop_before_service)
            sys.exit(serve(settings))
        else:
            raise ValueError("unsupported directory command")
    except domain_join.JoinConflict:
        print("Directory join authorization was rejected.", file=sys.stderr)
        sys.exit(3)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, tarfile.TarError, KeyError) as error:
        # Provisioning diagnostics remain in the private volume.
        print(f"Directory controller failed ({type(error).__name__}).", file=sys.stderr)
        sys.exit(1)
