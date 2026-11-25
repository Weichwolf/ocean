"""Managed security groups and direct workforce membership in Samba AD."""

import ldb
from samba import dsdb
from samba.dcerpc.misc import GUID
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack

from directory_users import ALIAS, USER_FILTER, GraphFailure, ensure_ou, get_user, lookup, page, user_view, workforce_dn
from domain_join import REQUEST_ID, object_guid, replace

GROUP_OU = "OU=Ocean Workforce Groups"
GROUP_FIELDS = ["objectGUID", "objectSid", "displayName", "sAMAccountName", "description"]
GLOBAL_SECURITY = dsdb.GTYPE_SECURITY_GLOBAL_GROUP
# LDAP represents the unsigned flags as a signed 32-bit value.
GROUP_FILTER = (f"(&(objectClass=group)(!(isCriticalSystemObject=TRUE))(!(adminCount=1))"
                f"(groupType={GLOBAL_SECURITY - (1 << 32)}))")


def field(entry, name):
    return entry.get(name, [b""])[0].decode()


def group_view(database, group):
    return {"id": object_guid(database, group), "displayName": field(group, "displayName"),
            "mailNickname": field(group, "sAMAccountName"), "description": field(group, "description"),
            "onPremisesSecurityIdentifier": str(ndr_unpack(dom_sid, group["objectSid"][0])),
            "securityEnabled": True, "mailEnabled": False}


def group_by_selector(database, scope, selector):
    if not REQUEST_ID.fullmatch(selector):
        raise GraphFailure(400)
    guid = ldb.binary_encode(ndr_pack(GUID(selector)))
    found = lookup(database, scope, f"(&{GROUP_FILTER}(objectGUID={guid}))", GROUP_FIELDS)
    if len(found) != 1:
        raise GraphFailure(404)
    return found[0]


def desktop_user(database, task):
    if not REQUEST_ID.fullmatch(task["selector"]):
        raise GraphFailure(400)
    user = get_user(database, workforce_dn(database), task["selector"])
    view = user_view(database, user)
    if not view["accountEnabled"]:
        raise GraphFailure(404)
    if "groupId" in task:
        scope = ldb.Dn(database, GROUP_OU + "," + database.domain_dn())
        group = group_by_selector(database, scope, task["groupId"])
        expression = f"(memberOf={ldb.binary_encode(str(group.dn))})"
        if not database.search(base=user.dn, scope=ldb.SCOPE_BASE, expression=expression, attrs=[]):
            raise GraphFailure(404)
    return {"status": 200, "user": view}


def create(database, scope, fields):
    if not isinstance(fields, dict) or fields.keys() - {"displayName", "mailNickname", "description", "mailEnabled", "securityEnabled"}:
        raise GraphFailure(400)
    alias, name, description = fields.get("mailNickname"), fields.get("displayName"), fields.get("description", "")
    if (not isinstance(alias, str) or not ALIAS.fullmatch(alias) or not isinstance(name, str)
            or not name.strip() or len(name.encode()) > 120 or not name.isprintable()
            or not isinstance(description, str) or len(description.encode()) > 256
            or fields.get("mailEnabled") is not False or fields.get("securityEnabled") is not True):
        raise GraphFailure(400)
    ensure_ou(database, scope)
    query = f"(&{GROUP_FILTER}(sAMAccountName={ldb.binary_encode(alias)}))"
    existing = lookup(database, scope, query, GROUP_FIELDS)
    if existing:
        old, = existing
        if field(old, "displayName") != name or field(old, "description") != description:
            raise GraphFailure(409)
        return old
    database.newgroup(alias, groupou=GROUP_OU, grouptype=GLOBAL_SECURITY, description=description or None)
    group, = lookup(database, scope, query, GROUP_FIELDS)
    replace(database, group.dn, displayName=name)
    group, = lookup(database, scope, query, GROUP_FIELDS)
    return group


def group_operation(database, task):
    operation = task["operation"]
    scope = ldb.Dn(database, GROUP_OU + "," + database.domain_dn())
    if operation == "groupCreate":
        return {"status": 201, "group": group_view(database, create(database, scope, task["fields"]))}
    if operation == "groupList":
        query = task.get("query", {})
        expression = GROUP_FILTER
        if "displayPrefix" in query:
            expression = f"(&{expression}(displayName={ldb.binary_encode(query['displayPrefix'])}*))"
        if "groupName" in query and "groupAlias" in query:
            expression = f"(&{expression}(displayName={ldb.binary_encode(query['groupName'])})" \
                         f"(sAMAccountName={ldb.binary_encode(query['groupAlias'])}))"
        groups, more = page(database, lookup(database, scope, expression, GROUP_FIELDS), query.get("offset", 0), group_view)
        return {"status": 200, "groups": groups, "more": more}

    group = group_by_selector(database, scope, task["selector"])
    if operation == "groupGet":
        return {"status": 200, "group": group_view(database, group)}
    if operation == "groupMembers":
        expression = f"(&{USER_FILTER}(memberOf={ldb.binary_encode(str(group.dn))}))"
        users, more = page(database, lookup(database, workforce_dn(database), expression),
                           task.get("query", {}).get("offset", 0), user_view)
        return {"status": 200, "users": [user | {"@odata.type": "#microsoft.graph.user"} for user in users], "more": more}
    if operation not in ("groupMemberAdd", "groupMemberRemove"):
        raise GraphFailure(400)
    user = get_user(database, workforce_dn(database), task["member"])
    expression = f"(memberOf={ldb.binary_encode(str(group.dn))})"
    exists = bool(database.search(base=user.dn, scope=ldb.SCOPE_BASE, expression=expression, attrs=[]))
    add = operation == "groupMemberAdd"
    if add != exists:
        change = ldb.Message()
        change.dn = group.dn
        mode = ldb.FLAG_MOD_ADD if add else ldb.FLAG_MOD_DELETE
        change["member"] = ldb.MessageElement(str(user.dn), mode, "member")
        database.modify(change)
    return {"status": 204}
