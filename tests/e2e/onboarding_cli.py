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


def send(cli, method, url, data=None, discard=False):
    token = cli.run("account", "get-access-token", "--resource", cli.config["arm"],
                    "--query", "accessToken", "-o", "tsv").strip()
    parts = urlsplit(url)
    route = parts.path + "?" + parts.query
    tls = ssl.create_default_context(cafile=cli.config["ca"])
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


def verify(config):
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
    return {"tenants": [first_result, second_result], "discardedResponseRecovered": True,
            "tenantRegistrationsDenied": True, "crossTenantSubscriptionsHidden": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text())), sort_keys=True))


if __name__ == "__main__":
    main()
