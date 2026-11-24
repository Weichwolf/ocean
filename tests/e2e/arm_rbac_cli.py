#!/usr/bin/env python3
"""Verify scoped authorization with the pinned CLI and real OAuth tokens."""

import argparse
import contextlib
import json
import tempfile
import uuid
from pathlib import Path

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI
from onboarding_cli import send_token


def create_service_principal(cli):
    app = json.loads(cli.run("ad", "app", "create", "--display-name", "Ocean RBAC integration", "-o", "json"))
    client = app["appId"]
    principal = json.loads(cli.run("ad", "sp", "create", "--id", client, "-o", "json"))["id"]
    secret = json.loads(cli.run("ad", "app", "credential", "reset", "--id", client, "--append", "-o", "json"))["password"]
    return client, principal, secret


def token_for(cli, resource="arm"):
    return cli.run("account", "get-access-token", "--resource", cli.config[resource], "--query", "accessToken", "-o", "tsv").strip()


def require_error(response, status, code):
    if response[0] != status or response[1].get("error", {}).get("code") != code:
        raise RuntimeError(f"the ARM request did not return {status} {code}")


def verify(config, matrix_path):
    first, second = create_customers(config)
    matrix = load_matrix(matrix_path, "IDENTITY-04")
    group_matrix = load_matrix(matrix_path)
    with contextlib.ExitStack() as cleanup:
        def new_cli(settings):
            directory = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="ocean-role-cli-"))
            return AzureCLI(settings, directory)

        admin, foreign = new_cli(first), new_cli(second)
        for cli in (admin, foreign):
            cli.login_device()
        primary, other = (GroupContract(cli, group_matrix) for cli in (admin, foreign))
        app, principal, password = create_service_principal(admin)
        fixture = "rbac-" + uuid.uuid4().hex[:12]
        for contract, name in ((primary, fixture), (primary, fixture + "-private"), (other, fixture)):
            cleanup.callback(contract.command, "group-delete", name)
            contract.command("group-create", name)
        scope = f"/subscriptions/{first['subscription']}/resourceGroups/{fixture}"
        name = str(uuid.uuid4())
        identifier = scope + f"/providers/Microsoft.Authorization/roleAssignments/{name}"
        location = primary.collection + "/" + fixture
        assignment_url = primary.origin + identifier
        metadata_url = primary.collection.removesuffix("/resourcegroups") + "/providers/Microsoft.Authorization"
        metadata_status, metadata = primary.request("GET", metadata_url)
        if metadata_status != 200 or {item["resourceType"]: item["apiVersions"] for item in metadata["resourceTypes"]} != {
                "roleAssignments": ["2022-04-01"], "roleDefinitions": ["2022-05-01-preview"]}:
            raise RuntimeError("provider discovery did not advertise the implemented authorization contracts")
        unauthorized = new_cli(dict(first, subscription=None))
        unauthorized.login_service_principal(app, password)
        require_error(send_token(first, token_for(unauthorized), "GET", location + f"?api-version={primary.api}"),
                      403, "AuthorizationFailed")

        def command(label, **overrides):
            args = {"scope": scope, "name": name, "id": identifier, "principal": principal, "kind": "ServicePrincipal"}
            args.update(overrides)
            output = admin.run(*command_args(matrix[label], primary.version, **args))
            return json.loads(output) if output else None

        definition = f"/subscriptions/{first['subscription']}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
        properties = {"principalId": principal, "principalType": "ServicePrincipal", "roleDefinitionId": definition}
        version = matrix["role-delete"]["api_version"]
        foreign_subject = dict(properties, principalId=second["administrator"], principalType="User")
        require_error(primary.request("PUT", assignment_url, {"properties": foreign_subject}, f"api-version={version}"),
                      400, "PrincipalNotFound")
        assignment = command("role-create")
        if assignment["id"] != identifier or assignment["principalId"] != principal or assignment["roleDefinitionId"] != definition:
            raise RuntimeError("the created ARM role assignment did not identify its role, assignee, and scope")
        if command("role-create")["id"] != identifier:
            raise RuntimeError("the assignment retry changed its resource ID")
        listed = command("role-list")
        if len(listed) != 1 or listed[0]["id"] != identifier or listed[0]["roleDefinitionName"] != "Reader":
            raise RuntimeError("the scoped role assignment list did not resolve its role definition")
        other_scope = scope + "-private"
        user_assignment = command("role-create", scope=other_scope, name=str(uuid.uuid4()), principal=first["administrator"], kind="User")
        if user_assignment["principalId"] != first["administrator"] or user_assignment["scope"] != other_scope:
            raise RuntimeError("the tenant user assignment did not identify its assignee and scope")
        command("role-delete", id=user_assignment["id"])

        reader = new_cli(first)
        reader.login_service_principal(app, password)
        reader.check_subscription()
        reader_contract = GroupContract(reader, group_matrix)
        if [group["name"] for group in reader_contract.command("group-list")] != [fixture]:
            raise RuntimeError("the scoped group list exposed resources outside the grant")
        if reader_contract.command("group-show", fixture)["id"] != scope:
            raise RuntimeError("the Reader could not read its assigned group")
        assignment_query = f"api-version={version}"
        assigned, record = reader_contract.request("GET", assignment_url, query=assignment_query)
        if assigned != 200 or record["id"] != identifier:
            raise RuntimeError("the scoped Reader could not inspect its role assignment")
        require_error(reader_contract.request("GET", location + "-private"), 403, "AuthorizationFailed")
        require_error(reader_contract.request("GET", other.collection + "/" + fixture), 404, "SubscriptionNotFound")
        require_error(reader_contract.request("DELETE", location), 403, "AuthorizationFailed")
        require_error(reader_contract.request("DELETE", assignment_url, query=f"api-version={version}"), 403, "AuthorizationFailed")
        arm_url = location + f"?api-version={primary.api}"
        head, signing = reader_contract.token.rsplit(".", 1)
        modified = head + "." + ("A" if signing[0] != "A" else "B") + signing[1:]
        require_error(send_token(first, modified, "GET", arm_url), 401, "InvalidAuthenticationToken")
        require_error(send_token(first, token_for(reader, "graph"), "GET", arm_url), 401, "InvalidAuthenticationToken")

        command("role-delete")
        command("role-delete")
        if command("role-list"):
            raise RuntimeError("the deleted assignment remained visible")
        require_error(reader_contract.request("GET", location), 403, "AuthorizationFailed")
        require_error(reader_contract.request("GET", assignment_url, query=assignment_query), 403, "AuthorizationFailed")
        if reader_contract.command("group-list"):
            raise RuntimeError("the old token retained group visibility after revocation")
        if primary.command("group-show", fixture)["id"] != scope:
            raise RuntimeError("a denied action changed the group")

        command("role-create")
        primary.command("group-delete", fixture)
        primary.command("group-create", fixture)
        require_error(reader_contract.request("GET", location), 403, "AuthorizationFailed")
        if command("role-list"):
            raise RuntimeError("the recreated group inherited a deleted role assignment")

        return {"azureCLI": primary.version["azure-cli"], "extensions": primary.version["extensions"],
                "commands": sorted(matrix), "tenantId": first["tenant"], "subscriptionId": first["subscription"],
                "administratorId": first["administrator"], "principalId": principal, "assignmentId": identifier,
                "groupId": scope, "outOfScopeDenied": True, "crossTenantDenied": True, "retainedTokenRevoked": True,
                "modifiedAndWrongAudienceDenied": True, "deletedGroupGrantRemoved": True, "tenantUserAssignmentVerified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix), sort_keys=True))


if __name__ == "__main__":
    main()
