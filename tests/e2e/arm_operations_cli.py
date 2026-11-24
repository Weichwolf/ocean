#!/usr/bin/env python3
"""Exercise one ARM operation across a separate controller lifecycle."""

import argparse
import concurrent.futures
import json
import os
import tempfile
import time
import uuid
from pathlib import Path

from arm_cli import GroupContract, create_customers, load_matrix
from identity_cli import AzureCLI
from onboarding_cli import send_token


def save_state(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)


def prepare(settings, matrix_path, path):
    first, second = create_customers(settings)
    matrix = load_matrix(matrix_path)
    name = "operation-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="ocean-lro-first-") as one, tempfile.TemporaryDirectory(prefix="ocean-lro-second-") as two:
        cli, foreign_cli = AzureCLI(first, one), AzureCLI(second, two)
        for client in (cli, foreign_cli):
            client.login_device()
        primary, foreign = (GroupContract(client, matrix) for client in (cli, foreign_cli))
        primary.command("group-create", name)
        context = {"ca": settings["ca"], "arm": primary.origin, "token": primary.token, "foreignToken": foreign.token,
                   "tenantId": first["tenant"], "subscriptionId": first["subscription"], "foreignSubscription": second["subscription"],
                   "group": name, "apiVersion": primary.api, "azureCLI": primary.version["azure-cli"],
                   "groupURL": primary.collection + "/" + name + "?api-version=" + primary.api}
        save_state(path, context)


def send(context, method, url, data=None, discard=False, headers=False, foreign=False):
    return send_token(context, context["foreignToken" if foreign else "token"], method, url, data, discard, headers)


def start(context, path):
    url = context["groupURL"]
    # The caller discards the accepted response, including both polling URLs.
    if send(context, "DELETE", url, discard=True)[0] != 202:
        raise RuntimeError("the first deletion was not accepted")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        replies = list(pool.map(lambda _: send(context, "DELETE", url, discard=True, headers=True), range(6)))
    if any(code != 202 for code, _, _ in replies):
        raise RuntimeError("a concurrent deletion did not recover the pending operation")
    headers = [row[2] for row in replies]
    statuses = {row.get("azure-asyncoperation") for row in headers}
    results = {row.get("location") for row in headers}
    if len(statuses) != 1 or len(results) != 1 or any(row.get("retry-after") != "1" for row in headers):
        raise RuntimeError("retried requests returned inconsistent ARM metadata")
    status_url, result_url = statuses.pop(), results.pop()
    prefix = context["arm"] + f"/subscriptions/{context['subscriptionId']}/providers/Microsoft.Resources/"
    if not status_url or not result_url or not status_url.startswith(prefix + "operationStatuses/") or not result_url.startswith(prefix + "operationResults/"):
        raise RuntimeError("the operation URLs use an unexpected origin, subscription, or provider")
    operation_id = str(uuid.UUID(status_url.split("?", 1)[0].rsplit("/", 1)[1]))
    context.update({"statusURL": status_url, "resultURL": result_url, "operationId": operation_id,
                    "concurrentRetries": len(replies)})
    save_state(path, context)
    return check_pending(context)


def check_pending(context):
    status, record = send(context, "GET", context["statusURL"])
    if status != 200 or record["status"] != "InProgress" or record["name"] != context["operationId"] or "endTime" in record:
        raise RuntimeError("the saved operation did not remain pending")
    if send(context, "GET", context["resultURL"], discard=True)[0] != 202:
        raise RuntimeError("the result endpoint did not report the pending operation")
    group_status, group = send(context, "GET", context["groupURL"])
    if group_status != 200 or group["properties"]["provisioningState"] != "Deleting":
        raise RuntimeError("the resource group did not reflect the pending deletion")
    rejected, error = send(context, "PUT", context["groupURL"], {"location": "farm-1"})
    if rejected != 409 or error["error"]["code"] != "ResourceGroupBeingDeleted":
        raise RuntimeError("a request could change a group marked for deletion")
    error_status, response = send(context, "GET", context["statusURL"], foreign=True)
    if error_status != 404 or response["error"]["code"] != "SubscriptionNotFound":
        raise RuntimeError("a foreign principal was able to poll the saved operation")
    foreign_url = context["statusURL"].replace(context["subscriptionId"], context["foreignSubscription"], 1)
    error_status, response = send(context, "GET", foreign_url, foreign=True)
    if error_status != 404 or response["error"]["code"] != "OperationNotFound":
        raise RuntimeError("the operation could be discovered through a foreign subscription")
    return {"operationId": context["operationId"], "state": record["status"], "crossTenantPollDenied": True}


def finish(context):
    deadline = time.monotonic() + 25
    while True:
        status, record = send(context, "GET", context["statusURL"])
        if status != 200 or record["status"] == "Failed" or time.monotonic() >= deadline:
            raise RuntimeError("the accepted deletion did not converge after restoration")
        if record["status"] == "Succeeded":
            break
        time.sleep(1)
    if not record.get("endTime") or record["name"] != context["operationId"]:
        raise RuntimeError("the terminal state is missing the original operation identity or finish time")
    if send(context, "GET", context["resultURL"], discard=True)[0] != 204:
        raise RuntimeError("the result endpoint did not report successful deletion")
    code, response = send(context, "GET", context["groupURL"])
    if code != 404 or response["error"]["code"] != "ResourceGroupNotFound":
        raise RuntimeError("the deleted group remained visible after completion")
    code, _, headers = send(context, "DELETE", context["groupURL"], discard=True, headers=True)
    if code != 202 or headers.get("azure-asyncoperation") != context["statusURL"]:
        raise RuntimeError("a retry after completion did not recover its terminal operation")
    status, recreated = send(context, "PUT", context["groupURL"], {"location": "farm-1"})
    if status != 201 or recreated["properties"]["provisioningState"] != "Succeeded":
        raise RuntimeError("the group could not be recreated after deletion")
    if send(context, "GET", context["statusURL"])[1] != record:
        raise RuntimeError("recreation changed the previous operation's result")
    return {"tenantId": context["tenantId"], "subscriptionId": context["subscriptionId"], "group": context["group"],
            "operationId": context["operationId"], "operationStatus": record["status"], "concurrentRetries": context["concurrentRetries"],
            "azureCLI": context["azureCLI"], "apiVersion": context["apiVersion"], "startTime": record["startTime"], "endTime": record["endTime"],
            "retryAfterCompletionRecovered": True, "recreationPreservedPriorStatus": True}


def cleanup(context):
    code, _, headers = send(context, "DELETE", context["groupURL"], discard=True, headers=True)
    if code == 200:
        return
    status_url = headers.get("azure-asyncoperation", "")
    if code != 202 or not status_url.startswith(context["arm"] + "/"):
        raise RuntimeError("the operation fixture could not be cleaned up")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status, record = send(context, "GET", status_url)
        if status == 200 and record["status"] == "Succeeded":
            return
        if status != 200 or record["status"] == "Failed":
            break
        time.sleep(1)
    raise RuntimeError("the fixture cleanup operation did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "start", "pending", "finish", "cleanup"))
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    args = parser.parse_args()
    if args.stage == "prepare":
        prepare(json.loads(args.settings.read_text()), args.matrix, args.session)
        return
    if args.stage == "cleanup" and not args.session.exists():
        return
    state = json.loads(args.session.read_text())
    if args.stage == "start":
        result = start(state, args.session)
    elif args.stage == "pending":
        result = check_pending(state)
    elif args.stage == "finish":
        result = finish(state)
    else:
        cleanup(state)
        return
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
