"""Execute one authenticated Graph operation in a Samba transaction."""

import json
import time

import ldb

from directory_groups import desktop_user, group_operation
from directory_users import GraphFailure, user_operation
from domain_join import REQUEST_ID, transaction


def run(database, domain, stream):
    body = stream.read(4097)
    if len(body) > 4096:
        raise ValueError("directory Graph task exceeds its size limit")
    task = json.loads(body)
    if not REQUEST_ID.fullmatch(task["id"]) or type(task["expiresAt"]) is not int:
        raise ValueError("invalid directory Graph task")
    try:
        with transaction(database):
            if int(time.time()) >= task["expiresAt"]:
                raise GraphFailure(409)
            if task["operation"] == "userDesktopCheck":
                return desktop_user(database, task)
            if task["operation"].startswith("group"):
                return group_operation(database, task)
            return user_operation(database, domain, task)
    except GraphFailure as error:
        return {"status": error.status}
    except ldb.LdbError as error:
        if error.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
            return {"status": 409}
        if error.args[0] in (ldb.ERR_CONSTRAINT_VIOLATION, ldb.ERR_UNWILLING_TO_PERFORM):
            return {"status": 400}
        raise RuntimeError("Samba could not execute the Graph task") from None
