"""Archive a native Samba domain backup and the exact SYSVOL ACLs."""

import hashlib
import io
import json
import shutil
import tarfile
from pathlib import PurePosixPath

DATABASE = "directory.tar.bz2"
SYSVOL = "sysvol.tar.gz"
MANIFEST = "manifest.json"
FORMAT = "ocean-samba-backup-v1"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_bundle(output, identity, database, policy):
    manifest = json.dumps({"format": FORMAT, "identity": identity,
                           "sha256": {DATABASE: digest(database), SYSVOL: digest(policy)}},
                          sort_keys=True).encode()
    with tarfile.open(fileobj=output, mode="w|") as archive:
        entry = tarfile.TarInfo(MANIFEST)
        entry.size = len(manifest)
        archive.addfile(entry, io.BytesIO(manifest))
        for name, path in ((DATABASE, database), (SYSVOL, policy)):
            entry = tarfile.TarInfo(name)
            entry.size = path.stat().st_size
            with path.open("rb") as stream:
                archive.addfile(entry, stream)


def read_bundle(source, directory, expected, identity):
    sealed = directory / "input.tar"
    with sealed.open("xb") as stream:
        shutil.copyfileobj(source, stream)
    if digest(sealed) != expected:
        raise ValueError("backup archive checksum does not match")
    with tarfile.open(sealed, mode="r:") as archive:
        members = {}
        for entry in archive:
            if (entry.name not in (MANIFEST, DATABASE, SYSVOL) or entry.name in members
                    or not entry.isreg() or entry.size == 0):
                raise ValueError("invalid domain backup entry")
            members[entry.name] = entry
        if len(members) != 3 or members[MANIFEST].size > 4096:
            raise ValueError("invalid domain backup manifest")
        with archive.extractfile(members[MANIFEST]) as raw:
            manifest = json.load(raw)
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("identity") != identity:
            raise ValueError("backup belongs to a different managed directory")
        hashes = manifest.get("sha256")
        if not isinstance(hashes, dict) or hashes.keys() != {DATABASE, SYSVOL}:
            raise ValueError("backup manifest does not describe both components")
        for name in (DATABASE, SYSVOL):
            destination = directory / name
            with archive.extractfile(members[name]) as raw, destination.open("xb") as stream:
                shutil.copyfileobj(raw, stream)
            if digest(destination) != hashes[name]:
                raise ValueError("domain backup component checksum does not match")
    # Samba's native tool extracts this nested archive. Check the archive
    # structure first, including entries it would not use after restore.
    with tarfile.open(directory / DATABASE, mode="r:bz2") as native:
        seen = set()
        for entry in native:
            path = PurePosixPath(entry.name)
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.name or path in seen
                    or not (entry.isreg() or entry.isdir())):
                raise ValueError("invalid native Samba backup entry")
            seen.add(path)
