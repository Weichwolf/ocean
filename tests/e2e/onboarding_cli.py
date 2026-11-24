#!/usr/bin/env python3
"""Verify tenant onboarding, response recovery, and tenant isolation using Azure CLI."""

import argparse
import http.client
import json
import secrets
import ssl
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from identity_cli import AzureCLI


def endpoint(config, tenant):
    return f"{config['arm']}/ocean/tenants/{tenant}?api-version=2026-11-01"


def send(cli, method, url, data=None, discard=False, resource="arm"):
    token = cli.run("account", "get-access-token", "--resource", cli.config[resource],
                    "--query", "accessToken", "-o", "tsv").strip()
    return send_token(cli.config, token, method, url, data, discard)


def send_token(config, token, method, url, data=None, discard=False):
    parts = urlsplit(url)
    route = parts.path
    if parts.query:
        route += "?" + parts.query
    tls = ssl.create_default_context(cafile=config["ca"])
    connection = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=28, context=tls)
    try:
        headers = {"Authorization": "Bearer " + token, "Connection": "close"}
        payload = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(data).encode()
        connection.request(method, route, payload, headers)
        with connection.getresponse() as reply:
            return reply.status, None if discard else json.load(reply)
    finally:
        connection.close()


def put(cli, tenant, data, request_file):
    request_file.write_text(json.dumps(data))
    request_file.chmod(0o600)
    return json.loads(cli.run("rest", "--method", "put", "--url", endpoint(cli.config, tenant),
                              "--body", "@" + str(request_file), "-o", "json"))


def fixture():
    tenant = uuid.uuid4()
    return str(tenant), {
        "displayName": f"Ocean onboarding {tenant.hex[:8]}",
        "administratorUserPrincipalName": f"admin-{tenant.hex[:8]}@lab.ocean.test",
        "administratorPassword": secrets.token_urlsafe(28),
    }


def graph_users(customer):
    user_id = uuid.uuid4().hex[:12]
    upn = f"graph-{user_id}@lab.ocean.test"
    name = f"Graph User {user_id}"
    alias = f"ocean-{user_id}"
    password = secrets.token_urlsafe(24)
    created = json.loads(customer.run("ad", "user", "create", "--display-name", name,
                                      "--user-principal-name", upn, "--mail-nickname", alias,
                                      "--password", password, "-o", "json"))
    if created["userPrincipalName"] != upn or created["displayName"] != name or created["mailNickname"] != alias:
        raise RuntimeError("the created directory user properties did not round-trip")
    object_id = created["id"]
    for key, value in (("--upn", upn), ("--display-name", name)):
        listed = json.loads(customer.run("ad", "user", "list", key, value, "-o", "json"))
        if [entry["id"] for entry in listed] != [object_id]:
            raise RuntimeError("a directory filter returned unexpected users")
    shown = json.loads(customer.run("ad", "user", "show", "--id", upn, "-o", "json"))
    if shown["id"] != object_id:
        raise RuntimeError("the user principal name resolved to a different directory object")
    updated_name = f"{name} Updated"
    customer.run("ad", "user", "update", "--id", object_id, "--display-name", updated_name, "-o", "none")
    shown = json.loads(customer.run("ad", "user", "show", "--id", object_id, "-o", "json"))
    if shown["displayName"] != updated_name or shown["mailNickname"] != alias:
        raise RuntimeError("the display-name update did not preserve the mail alias")
    config = dict(customer.config, subscription=None, user=upn, password=password)
    with tempfile.TemporaryDirectory(prefix="ocean-graph-user-") as directory:
        cli = AzureCLI(config, directory)
        cli.login_device()
        if cli.resource_subject() != object_id:
            raise RuntimeError("the directory credentials did not identify the new user")
        cli.run("ad", "user", "list", reject=True)
        status, reply = send(cli, "GET", config["graph"] + "/v1.0/users", resource="graph")
        if status != 403 or reply["error"]["code"] != "Authorization_RequestDenied":
            raise RuntimeError("a regular tenant user could administer the directory")
    customer.run("ad", "user", "delete", "--id", object_id)
    customer.run("ad", "user", "show", "--id", object_id, reject=True)
    with tempfile.TemporaryDirectory(prefix="ocean-graph-deleted-") as directory:
        AzureCLI(config, directory).login_device(reject=True)


def graph_application(customer):
    name = "Ocean Automation " + uuid.uuid4().hex[:12]
    app = json.loads(customer.run("ad", "app", "create", "--display-name", name, "-o", "json"))
    client, app_id = app["appId"], app["id"]
    if client == app_id or app["displayName"] != name:
        raise RuntimeError("the Graph application identity is invalid")
    principal = json.loads(customer.run("ad", "sp", "create", "--id", client, "-o", "json"))
    if principal["appId"] != client or principal["id"] in (app_id, client):
        raise RuntimeError("the service principal does not refer to the application")
    shown = json.loads(customer.run("ad", "sp", "show", "--id", client, "-o", "json"))
    if shown["id"] != principal["id"]:
        raise RuntimeError("the service principal lookup returned another object")

    def append(label):
        data = json.loads(customer.run("ad", "app", "credential", "reset", "--id", client,
                                       "--append", "--display-name", label, "-o", "json"))
        if data["appId"] != client or data["tenant"] != customer.config["tenant"]:
            raise RuntimeError("the credential was minted for another application")
        return data["password"]

    def sign_in(password, reject=False):
        config = dict(customer.config, subscription=None)
        with tempfile.TemporaryDirectory(prefix="ocean-graph-principal-") as directory:
            cli = AzureCLI(config, directory)
            cli.login_service_principal(client, password, reject=reject)
            if not reject and cli.resource_subject() != principal["id"]:
                raise RuntimeError("the credential did not identify the service principal")

    first = append("Original secret")
    sign_in(first)
    second = append("Appended secret")
    if first == second:
        raise RuntimeError("appending a credential returned the old secret")
    sign_in(second)
    sign_in(first)
    data = json.loads(customer.run("ad", "app", "show", "--id", client, "-o", "json"))
    credentials = data["passwordCredentials"]
    labels = {row["displayName"]: row["keyId"] for row in credentials}
    if labels.keys() != {"Original secret", "Appended secret"} or any("secretText" in row for row in credentials):
        raise RuntimeError("the application did not retain both credential records")
    customer.run("ad", "app", "credential", "delete", "--id", client, "--key-id", labels["Original secret"], "-o", "none")
    sign_in(first, reject=True)
    sign_in(second)
    return {"applicationId": app_id, "clientId": client, "principalId": principal["id"]}


def verify(config, directory_users=False, directory_apps=False):
    first, first_input = fixture()
    second, second_input = fixture()
    with tempfile.TemporaryDirectory(prefix="ocean-operator-") as directory:
        operator = AzureCLI(config, directory)
        operator.login_service_principal(config["app"], config["secret"])
        limit = time.monotonic() + 90
        while True:
            status, _ = send(operator, "PUT", endpoint(config, first), first_input, discard=True)
            if status != 503 or time.monotonic() >= limit:
                break
            time.sleep(1)
        if status != 201:
            raise RuntimeError(f"the request with discarded response returned HTTP {status}")
        request_file = Path(directory) / "tenant-request.json"
        first_result = put(operator, first, first_input, request_file)
        if first_result != put(operator, first, first_input, request_file):
            raise RuntimeError("registration retry changed the allocation")
        second_result = put(operator, second, second_input, request_file)
        changed = dict(first_input, displayName="A different registration")
        status, reply = send(operator, "PUT", endpoint(config, first), changed)
        if status != 409 or reply["error"]["code"] != "TenantAlreadyRegistered":
            raise RuntimeError("a different registration replaced the original allocation")
    if first_result["tenantId"] != first or second_result["tenantId"] != second:
        raise RuntimeError("the API returned a different tenant")
    if any(first_result[key] == second_result[key] for key in ("subscriptionId", "administratorId")):
        raise RuntimeError("tenant registrations share an allocation")

    applications = []
    for own, body, other in ((first_result, first_input, second_result), (second_result, second_input, first_result)):
        tenant_config = dict(config, tenant=own["tenantId"], subscription=own["subscriptionId"], location="farm-1",
                             user=body["administratorUserPrincipalName"], password=body["administratorPassword"])
        with tempfile.TemporaryDirectory(prefix="ocean-customer-") as directory:
            customer = AzureCLI(tenant_config, directory)
            customer.login_device()
            customer.check_subscription()
            if customer.resource_subject() != own["administratorId"]:
                raise RuntimeError("the tenant token represents a different administrator")
            url = f"{config['arm']}/subscriptions/{other['subscriptionId']}?api-version=2022-12-01"
            status, reply = send(customer, "GET", url)
            if status != 404 or reply["error"]["code"] != "SubscriptionNotFound":
                raise RuntimeError("the customer could access another tenant's subscription")
            forbidden, forbidden_input = fixture()
            url = endpoint(tenant_config, forbidden)
            request_file = Path(directory) / "forbidden-tenant.json"
            request_file.write_text(json.dumps(forbidden_input))
            request_file.chmod(0o600)
            customer.run("rest", "--method", "put", "--url", url, "--body", "@" + str(request_file), reject=True)
            status, reply = send(customer, "PUT", url, forbidden_input)
            if status != 403 or reply["error"]["code"] != "AuthorizationFailed":
                raise RuntimeError("the tenant could provision another tenant")
            if directory_users:
                foreign = f"{config['graph']}/v1.0/users/{other['administratorId']}"
                status, reply = send(customer, "GET", foreign, resource="graph")
                if status != 404 or reply["error"]["code"] != "Request_ResourceNotFound":
                    raise RuntimeError("Graph disclosed a user from another tenant")
                status, reply = send(customer, "GET", config["graph"] + "/v1.0/users")
                if status != 401 or reply["error"]["code"] != "InvalidAuthenticationToken":
                    raise RuntimeError("Graph accepted a token issued for ARM")
                graph_users(customer)
            if directory_apps:
                if applications:
                    url = f"{config['graph']}/v1.0/applications/{applications[0]['applicationId']}"
                    status, reply = send(customer, "GET", url, resource="graph")
                    if status != 404 or reply["error"]["code"] != "Request_ResourceNotFound":
                        raise RuntimeError("Graph disclosed an application from another tenant")
                applications.append(graph_application(customer))
    result = {"tenants": [first_result, second_result], "discardedResponseRecovered": True,
              "tenantRegistrationsDenied": True, "crossTenantSubscriptionsHidden": True}
    if directory_users:
        result["graphUserLifecycle"] = True
    if directory_apps:
        result.update({"applications": applications, "appendedCredentialsPreserved": True, "revokedCredentialsDenied": True})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--directory-users", action="store_true")
    parser.add_argument("--directory-apps", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.directory_users, args.directory_apps), sort_keys=True))


if __name__ == "__main__":
    main()
