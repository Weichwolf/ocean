"""Apply the managed Graph user profile to the workforce OU."""

import json
import re
import time

import ldb
from samba import dsdb
from samba.dcerpc.misc import GUID
from samba.ndr import ndr_pack

from domain_join import REQUEST_ID, object_guid, replace, transaction

WORKFORCE = "OU=Ocean Workforce Users"
USER_FILTER = "(&(objectClass=user)(objectCategory=person)(!(isCriticalSystemObject=TRUE))(!(adminCount=1)))"
PROPERTIES = ("objectGUID", "userPrincipalName", "displayName", "mail", "userAccountControl", "description",
              "sAMAccountName")
USERNAME = re.compile(r"[a-z][a-z0-9._-]{0,19}")
ALIAS = re.compile(r"[a-zA-Z0-9._-]{1,64}")
PAGE_SIZE = 100


class GraphFailure(ValueError):
    def __init__(self, status):
        self.status = status


def workforce_dn(database):
    return ldb.Dn(database, f"{WORKFORCE},{database.domain_dn()}")


def lookup(database, scope, expression):
    try:
        return database.search(base=scope, scope=ldb.SCOPE_ONELEVEL, expression=expression, attrs=list(PROPERTIES))
    except ldb.LdbError as error:
        if error.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        return []


def get_user(database, scope, selector):
    if REQUEST_ID.fullmatch(selector):
        guid = ndr_pack(GUID(selector))
        attribute, value = "objectGUID", guid
    else:
        attribute, value = "userPrincipalName", selector
    entries = lookup(database, scope, f"(&{USER_FILTER}({attribute}={ldb.binary_encode(value)}))")
    if len(entries) != 1:
        raise GraphFailure(404)
    return entries[0]


def user_view(database, user):
    def value(name):
        return user.get(name, [b""])[0].decode()

    return {"id": object_guid(database, user), "userPrincipalName": value("userPrincipalName"),
            "displayName": value("displayName"), "mailNickname": value("mail").partition("@")[0],
            "mail": value("mail"), "accountEnabled": not int(value("userAccountControl")) & dsdb.UF_ACCOUNTDISABLE}


def stage_user(database, scope, fields, domain, marker):
    principal = fields["userPrincipalName"]
    name, at, suffix = principal.partition("@")
    if at != "@" or suffix != domain or not USERNAME.fullmatch(name) or name.startswith("oj-"):
        raise GraphFailure(400)
    try:
        existing = get_user(database, scope, principal)
    except GraphFailure:
        existing = None
    if existing is not None:
        if existing.get("description", [b""])[0].decode() == marker:
            return user_view(database, existing)
        raise GraphFailure(409)

    password = fields["passwordProfile"]
    database.newuser(name, password["password"], userou=WORKFORCE,
                     force_password_change_at_next_login_req=password["forceChangePasswordNextSignIn"],
                     description=marker)
    user = get_user(database, scope, principal)
    return update_user(database, scope, user, {key: fields[key] for key in ("displayName", "mailNickname", "accountEnabled")},
                       domain, marker)


def update_user(database, scope, user, fields, domain, marker):
    flags = int(user["userAccountControl"][0])
    enabled = fields.get("accountEnabled", not flags & dsdb.UF_ACCOUNTDISABLE)
    changed = {"description": marker}
    if "displayName" in fields:
        changed["displayName"] = fields["displayName"]
    if "mailNickname" in fields:
        changed["mail"] = fields["mailNickname"] + "@" + domain
    if "passwordProfile" in fields:
        password = fields["passwordProfile"]
        expression = "(distinguishedName=" + ldb.binary_encode(str(user.dn)) + ")"
        database.setpassword(expression, password["password"], password["forceChangePasswordNextSignIn"])
        flags = int(get_user(database, scope, user["userPrincipalName"][0].decode())["userAccountControl"][0])
    changed["userAccountControl"] = (flags & ~dsdb.UF_ACCOUNTDISABLE) if enabled else (flags | dsdb.UF_ACCOUNTDISABLE)
    replace(database, user.dn, **changed)
    return user_view(database, get_user(database, scope, user["userPrincipalName"][0].decode()))


def ensure_workforce(database, scope):
    try:
        if database.search(base=scope, scope=ldb.SCOPE_BASE, attrs=[]):
            return
    except ldb.LdbError as error:
        if error.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
    database.add({"dn": scope, "objectClass": "organizationalUnit"})


def list_users(database, scope, query):
    expression = USER_FILTER
    if "upn" in query:
        expression = f"(&{expression}(userPrincipalName={ldb.binary_encode(query['upn'])}))"
    if "displayPrefix" in query:
        expression = f"(&{expression}(displayName={ldb.binary_encode(query['displayPrefix'])}*))"
    offset = query.get("offset", 0)
    entries = sorted(lookup(database, scope, expression), key=lambda user: user["sAMAccountName"][0].lower())
    return {"users": [user_view(database, user) for user in entries[offset:offset + PAGE_SIZE]],
            "more": len(entries) > offset + PAGE_SIZE}


def validate_fields(fields, create):
    names = {"displayName", "mailNickname", "accountEnabled", "passwordProfile"}
    if create:
        names.add("userPrincipalName")
    if not isinstance(fields, dict) or not fields or not fields.keys() <= names or create and fields.keys() != names:
        raise GraphFailure(400)
    if ("mailNickname" in fields and not ALIAS.fullmatch(fields["mailNickname"])
            or "accountEnabled" in fields and type(fields["accountEnabled"]) is not bool):
        raise GraphFailure(400)
    if "displayName" in fields:
        name = fields["displayName"]
        if not isinstance(name, str) or not name.strip() or len(name.encode()) > 120 or not name.isprintable():
            raise GraphFailure(400)
    if "passwordProfile" in fields:
        password = fields["passwordProfile"]
        if (not isinstance(password, dict) or password.keys() != {"password", "forceChangePasswordNextSignIn"}
                or not isinstance(password["password"], str) or not password["password"].isprintable()
                or not 12 <= len(password["password"].encode()) <= 256
                or type(password["forceChangePasswordNextSignIn"]) is not bool):
            raise GraphFailure(400)


def directory_users(database, domain, stream):
    body = stream.read(4097)
    if len(body) > 4096:
        raise ValueError("directory user task exceeds its size limit")
    task = json.loads(body)
    operation, attempt = task["operation"], task["id"]
    if not REQUEST_ID.fullmatch(attempt) or type(task["expiresAt"]) is not int:
        raise ValueError("invalid directory user task")
    marker = f"Ocean Graph write {attempt}"
    scope = workforce_dn(database)
    try:
        with transaction(database):
            if int(time.time()) >= task["expiresAt"]:
                raise GraphFailure(409)
            if operation == "userList":
                return {"status": 200} | list_users(database, scope, task.get("query", {}))
            if operation == "userGet":
                return {"status": 200, "user": user_view(database, get_user(database, scope, task["selector"]))}
            fields = task["fields"]
            if operation == "userCreate":
                validate_fields(fields, True)
                ensure_workforce(database, scope)
                return {"status": 201, "user": stage_user(database, scope, fields, domain, marker)}
            if operation == "userUpdate":
                validate_fields(fields, False)
                user = get_user(database, scope, task["selector"])
                if user.get("description", [b""])[0].decode() != marker:
                    update_user(database, scope, user, fields, domain, marker)
                return {"status": 204}
            raise GraphFailure(400)
    except GraphFailure as error:
        return {"status": error.status}
    except ldb.LdbError as error:
        if error.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
            return {"status": 409}
        if error.args[0] in (ldb.ERR_CONSTRAINT_VIOLATION, ldb.ERR_UNWILLING_TO_PERFORM):
            return {"status": 400}
        raise
