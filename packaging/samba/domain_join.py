"""Prestage one AD computer and a short-lived join principal for that object."""

import json
import re
import time
from contextlib import contextmanager

import ldb
from samba import dsdb, unix2nttime
from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.sd_utils import SDUtils

REQUEST_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
MACHINE_NAME = re.compile(r"[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?")
JOIN_MARKER = re.compile(rf"Ocean join ({REQUEST_ID.pattern}) ({REQUEST_ID.pattern})")
USER_ATTRS = ("description", "objectSid", "accountExpires", "userAccountControl", "sAMAccountName")
COMPUTER_ATTRS = ("objectGUID", "objectClass", "pwdLastSet")
JOIN_ATTRS = ("userAccountControl", "msDS-SupportedEncryptionTypes",
              "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack")
RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"
ALLOWED_TO_AUTHENTICATE = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
VALIDATED_DNS_HOST = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
VALIDATED_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"


def open_directory(config):
    lp = LoadParm()
    lp.load(str(config))
    return SamDB(lp=lp, session_info=system_session())


@contextmanager
def transaction(database):
    database.transaction_start()
    try:
        yield
    except BaseException:
        database.transaction_cancel()
        raise
    else:
        database.transaction_commit()


def replace(database, dn, **fields):
    update = ldb.Message()
    update.dn = dn
    for name, value in fields.items():
        update[name] = ldb.MessageElement(str(value), ldb.FLAG_MOD_REPLACE, name)
    database.modify(update)


def restrict_machine_creation(database):
    domain = database.domain_dn()
    entry, = database.search(base=domain, scope=ldb.SCOPE_BASE, attrs=["ms-DS-MachineAccountQuota"])
    if int(entry["ms-DS-MachineAccountQuota"][0]) != 0:
        replace(database, entry.dn, **{"ms-DS-MachineAccountQuota": 0})


def principal(database, account, *attrs):
    entries = database.search(base=database.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                              expression=f"(sAMAccountName={ldb.binary_encode(account)})", attrs=list(attrs))
    if len(entries) > 1:
        raise RuntimeError("directory account name is ambiguous")
    return next(iter(entries), None)


def join_rights(database, sid):
    attributes = "".join(f"(lDAPDisplayName={name})" for name in JOIN_ATTRS)
    schema = database.search(base=database.get_schema_basedn(), scope=ldb.SCOPE_ONELEVEL,
                             expression=f"(&(objectClass=attributeSchema)(|{attributes}))", attrs=["schemaIDGUID"])
    if len(schema) != len(JOIN_ATTRS):
        raise RuntimeError("the directory is missing a join attribute")
    props = sorted(database.schema_format_value("schemaIDGUID", entry["schemaIDGUID"][0]).decode() for entry in schema)
    aces = [f"(A;;LCRPLORC;;;{sid})"]
    aces.extend(f"(OA;;CR;{right};;{sid})" for right in (ALLOWED_TO_AUTHENTICATE, CHANGE_PASSWORD, RESET_PASSWORD))
    aces.extend(f"(OA;;SW;{right};;{sid})" for right in (VALIDATED_DNS_HOST, VALIDATED_SPN))
    aces.extend(f"(OA;;WP;{prop};;{sid})" for prop in props)
    return "".join(aces)


def read_request(stream, stage):
    payload = stream.read(4097)
    if len(payload) > 4096:
        raise ValueError("directory join request exceeds its size limit")
    request = json.loads(payload)
    fields = {"requestId", "machineName", "expiresAt"}
    if stage:
        fields.add("password")
    if not isinstance(request, dict) or request.keys() != fields:
        raise ValueError("invalid directory join request")
    request_id, machine, expires = (request[key] for key in ("requestId", "machineName", "expiresAt"))
    if (not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id) or not isinstance(machine, str)
            or not MACHINE_NAME.fullmatch(machine) or machine.isdecimal()
            or type(expires) is not int or expires <= 0 or expires > int(time.time()) + 600):
        raise ValueError("invalid directory join request")
    if stage and (not isinstance(request["password"], str) or not re.fullmatch(r"[!-~]{32,128}", request["password"])):
        raise ValueError("invalid directory join credential")
    return request


def object_guid(database, entry):
    return database.schema_format_value("objectGUID", entry["objectGUID"][0]).decode()


def join_account(request_id):
    return "oj-" + request_id.replace("-", "")[:17]


def user_flags(user):
    return int(user["userAccountControl"][0])


def computer_has_password(computer):
    return computer is not None and int(computer.get("pwdLastSet", [b"0"])[0]) > 0


def revoke(database, user, computer):
    if computer is not None:
        sid = ndr_unpack(security.dom_sid, user["objectSid"][0])
        SDUtils(database).dacl_delete_aces(computer.dn, join_rights(database, sid))
    replace(database, user.dn, userAccountControl=user_flags(user) | dsdb.UF_ACCOUNTDISABLE)


def revoke_join_accounts(database, *, restore=False):
    # The same commit revokes the password and the object's permissions, so
    # an established LDAP session also loses permission to reset this machine.
    with transaction(database):
        expiry = "" if restore else f"(accountExpires<={unix2nttime(int(time.time()))})"
        accounts = database.search(base=database.domain_dn(), scope=ldb.SCOPE_SUBTREE,
                                   expression=f"(&(sAMAccountName=oj-*)(description=Ocean join *){expiry}"
                                   "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", attrs=list(USER_ATTRS))
        for user in accounts:
            match = JOIN_MARKER.fullmatch(user["description"][0].decode())
            if not match or user["sAMAccountName"][0].decode() != join_account(match[1]):
                continue
            try:
                computer, = database.search(base=f"<GUID={match[2]}>", scope=ldb.SCOPE_BASE, attrs=list(COMPUTER_ATTRS))
            except ldb.LdbError as error:
                if error.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                    raise
                computer = None
            if computer is None or b"computer" in computer["objectClass"]:
                revoke(database, user, computer)


def managed_join(database, request, stage):
    request_id, machine, expires = (request[key] for key in ("requestId", "machineName", "expiresAt"))
    name = join_account(request_id)
    expected_expiry = unix2nttime(expires)
    with transaction(database):
        computer = principal(database, machine + "$", *COMPUTER_ATTRS)
        user = principal(database, name, *USER_ATTRS)
        now = int(time.time())
        if user is None:
            if not stage or now >= expires or computer is not None:
                raise ValueError("join request is expired or the computer name is already in use")
            restrict_machine_creation(database)
            database.newcomputer(machine)
            computer = principal(database, machine + "$", *COMPUTER_ATTRS)
            marker = f"Ocean join {request_id} {object_guid(database, computer)}"
            database.newuser(name, request["password"], description=marker)
            user = principal(database, name, "objectSid", "userAccountControl")
            flags = user_flags(user) | dsdb.UF_NOT_DELEGATED
            replace(database, user.dn, accountExpires=expected_expiry, userAccountControl=flags)
            sid = ndr_unpack(security.dom_sid, user["objectSid"][0])
            SDUtils(database).dacl_add_ace(computer.dn, join_rights(database, sid))
            return name
        if computer is None or b"computer" not in computer["objectClass"]:
            raise ValueError("join authorization lost its target computer")
        marker = f"Ocean join {request_id} {object_guid(database, computer)}".encode()
        if user.get("description", [b""])[0] != marker or int(user["accountExpires"][0]) != expected_expiry:
            raise ValueError("join authorization does not match its target and expiration")
        flags = user_flags(user)
        if stage:
            if flags & dsdb.UF_ACCOUNTDISABLE or now >= expires or computer_has_password(computer):
                raise ValueError("join authorization was consumed or expired")
            return name
        if not flags & dsdb.UF_ACCOUNTDISABLE:
            if now < expires and not computer_has_password(computer):
                raise ValueError("the client has not joined and the authorization is still active")
            revoke(database, user, computer)
        return name
