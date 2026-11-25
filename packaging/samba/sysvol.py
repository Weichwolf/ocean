"""Publish a consistent snapshot of the primary controller's SYSVOL."""

import configparser
import ctypes
import gzip
import io
import os
import re
import stat
import tarfile
import tempfile
from pathlib import Path

SHARE = "ocean-policy$"
ARCHIVE = "sysvol.tar.gz"
ROOT_METADATA = ".ocean-root.NTACL"
DOMAIN_METADATA = ".ocean-domain"
AT_FDCWD = -100
RENAME_EXCHANGE = 2
GPO_NAME = re.compile(r"\{[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\}")


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_config(config, content):
    pending = config.with_suffix(".pending")
    with pending.open("w") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    pending.replace(config)
    sync_directory(config.parent)


def configure_export(config, settings, replica, peer):
    original = config.read_text()
    configured = re.sub(rf"(?mis)^\[{re.escape(SHARE)}\]\n.*?(?=^\[|\Z)", "", original)
    if replica:
        folder = config.parent.parent / "policy-export"
        folder.mkdir(exist_ok=True)
        folder.chmod(0o711)
        configured = (configured.rstrip() + f"\n\n[{SHARE}]\n\tpath = {folder}\n"
                      "\tread only = yes\n\tbrowseable = no\n\tguest ok = no\n"
                      f"\tvalid users = {settings['netbios']}\\{peer}$\n\thosts allow = {replica}\n"
                      "\tserver smb encrypt = required\n")
    if configured != original:
        replace_config(config, configured)


def set_share_read_only(content, read_only):
    def rewrite(match):
        value = "yes" if read_only else "no"
        section = re.sub(r"(?mi)^[ \t]*read only[ \t]*=.*\n?", "", match.group(2))
        return match.group(1) + f"\tread only = {value}\n" + section

    content, sections = re.subn(r"(?mis)(^\[(?:sysvol|netlogon)\]\n)(.*?)(?=^\[|\Z)", rewrite, content)
    if sections != 2:
        raise ValueError("Samba did not configure both policy shares")
    return content


def archive_metadata(archive, name, value):
    data = value.encode("utf-8")
    item = tarfile.TarInfo(name)
    item.size = len(data)
    archive.addfile(item, io.BytesIO(data))


def metadata_version(info):
    return info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def archive_directory(archive, root, path, acls, session, versions):
    before = path.stat(follow_symlinks=False)
    name = path.relative_to(root).as_posix()
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("SYSVOL contains a non-directory entry")
    if path == root:
        descriptor_name = ROOT_METADATA
    else:
        descriptor_name = name + ".NTACL"
        item = tarfile.TarInfo(name)
        item.type = tarfile.DIRTYPE
        archive.addfile(item)
    acl = acls.getntacl(str(path), session, as_sddl=True)
    versions[path] = metadata_version(before), acl
    archive_metadata(archive, descriptor_name, acl)

    for entry in sorted(path.iterdir()):
        share_name = entry.relative_to(root).as_posix()
        if (entry.name.lower().endswith(".ntacl") or entry.name.lower() == DOMAIN_METADATA
                or "\\" in entry.name):
            raise ValueError("SYSVOL contains a reserved filename")
        if entry.is_dir() and not entry.is_symlink():
            archive_directory(archive, root, entry, acls, session, versions)
            continue
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            version = os.fstat(source.fileno())
            if not stat.S_ISREG(version.st_mode):
                raise ValueError("SYSVOL contains a non-regular file")
            item = tarfile.TarInfo(share_name)
            item.size = version.st_size
            archive.addfile(item, source)
            acl = acls.getntacl(str(entry), session, as_sddl=True)
            versions[entry] = metadata_version(version), acl
            archive_metadata(archive, share_name + ".NTACL", acl)


def capture(config, output, *, verify_directory=False):
    from samba.auth import system_session
    from samba.auth_util import system_session_unix
    from samba.dcerpc.security import dom_sid
    from samba.ntacls import NtaclsHelper
    from samba.param import LoadParm
    from samba.samdb import SamDB

    lp = LoadParm()
    lp.load(str(config))
    db = SamDB(lp=lp, session_info=system_session())
    sid = dom_sid(db.get_domain_sid())
    helper = NtaclsHelper("sysvol", str(config), sid)
    session = system_session_unix()
    source = Path(lp.get("path", "sysvol"))
    versions = {}
    with gzip.GzipFile(fileobj=output, filename="", mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            archive_metadata(archive, DOMAIN_METADATA, str(sid))
            archive_directory(archive, source, source, helper, session, versions)
    for path, (version, acl) in versions.items():
        if (metadata_version(path.stat(follow_symlinks=False)) != version
                or helper.getntacl(str(path), session, as_sddl=True) != acl):
            raise RuntimeError("SYSVOL changed while capturing the snapshot")
    if verify_directory:
        verify_gpo_versions(source, lp.get("realm").lower(), db)


def publish(config):
    folder = config.parent.parent / "policy-export"
    with tempfile.NamedTemporaryFile(dir=folder, delete=False) as output:
        pending = Path(output.name)
        try:
            capture(config, output)
            output.flush()
            os.fsync(output.fileno())
            pending.chmod(0o444)
            pending.replace(folder / ARCHIVE)
            sync_directory(folder)
        finally:
            pending.unlink(missing_ok=True)


def verify_acls(config, sid, expected):
    from samba.auth_util import system_session_unix
    from samba.ntacls import NtaclsHelper

    helper = NtaclsHelper("sysvol", str(config), sid)
    session = system_session_unix()
    for path, descriptor in expected.items():
        if helper.getntacl(str(path), session, as_sddl=True) != descriptor:
            raise RuntimeError("staged SYSVOL ACL differs from the source")


def verify_gpo_versions(sysvol, domain, db):
    import ldb

    policies = sysvol / domain / "Policies"
    folders = {path.name.lower(): path for path in policies.iterdir() if path.is_dir() and GPO_NAME.fullmatch(path.name)}
    for gpo in db.search(base="CN=Policies,CN=System," + str(db.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                         expression="(objectClass=groupPolicyContainer)", attrs=["name", "versionNumber"]):
        folder = folders.pop(gpo["name"][0].decode().lower(), None)
        if folder is None:
            raise RuntimeError("SYSVOL is missing a replicated Group Policy")
        content = (folder / "GPT.INI").read_bytes()
        encoding = "utf-16" if content.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        ini = configparser.ConfigParser(interpolation=None)
        try:
            ini.read_string(content.decode(encoding))
        except configparser.Error as error:
            raise ValueError("invalid Group Policy template") from error
        general = next((section for section in ini if section.lower() == "general"), "")
        version = int(gpo.get("versionNumber", [b"0"])[0])
        if not general or ini.getint(general, "Version", fallback=-1) != version:
            raise RuntimeError("SYSVOL and the replicated directory have different Group Policy versions")
    if folders:
        raise RuntimeError("the directory has not replicated every Group Policy in SYSVOL")


def exchange(live, staged):
    # Both directories are on the same private volume. A failed exchange keeps
    # the last verified SYSVOL at the live share path.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(AT_FDCWD, os.fsencode(live), AT_FDCWD, os.fsencode(staged), RENAME_EXCHANGE) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    sync_directory(live.parent)
    sync_directory(staged.parent)
