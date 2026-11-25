#!/usr/bin/env python3
"""Run the declared resource-centric Logs queries with unmodified Azure CLI."""

import argparse
import json
import tempfile
from pathlib import Path

from arm_cli import GroupContract, load_matrix
from functions_cli import command
from identity_cli import AzureCLI
from onboarding_cli import send_token

QUERIES = {
    "summary": ("AppRequests | summarize Requests=count(), Errors=countif(Success == false), "
                "ErrorRate=100.0*countif(Success == false)/count(), P50=percentile(DurationMs, 50), P95=percentile(DurationMs, 95)"),
    "requests": "AppRequests | project TimeGenerated, Name, ResultCode, Success, DurationMs",
    "dependencies": "AppDependencies | project TimeGenerated, Name, Target, ResultCode, Success, DurationMs",
    "exceptions": "AppExceptions | project TimeGenerated, ExceptionType",
    "gaps": "OceanTelemetryGaps_CL | project TimeGenerated, Dropped, From, To",
}


def verify(matrix, fixture, timespan):
    with tempfile.TemporaryDirectory(prefix="ocean-insights-cli-") as temporary:
        root = Path(temporary)
        tenant, foreign = [AzureCLI(fixture[scope], str(root / scope)) for scope in ("tenant", "foreign")]
        for cli in (tenant, foreign):
            cli.login_device()
            cli.check_subscription()
        rows = load_matrix(matrix, "OBS-02") | load_matrix(matrix, "OBS-04")
        contracts = [GroupContract(cli, load_matrix(matrix)) for cli in (tenant, foreign)]
        context, stranger = contracts
        name = fixture["app"]
        if "kind" in fixture:
            kind = fixture["kind"]
        else:
            kind = "Microsoft.Web/sites"
        subscription = fixture["tenant"]["subscription"]
        resource = f"/subscriptions/{subscription}/resourceGroups/{fixture['group']}/providers/{kind}/{name}"
        values = {"origin": context.origin, "id": resource, "body": str(root / "query.json")}
        result = {"azureCLI": context.version["azure-cli"]}
        only_gaps = kind == "Microsoft.ContainerInstance/containerGroups"
        queries = {"gaps": QUERIES["gaps"]} if only_gaps else QUERIES
        for key, query in queries.items():
            request = {"query": query, "timespan": timespan}
            Path(values["body"]).write_text(json.dumps(request))
            label = "telemetry-gap-query" if key == "gaps" else "insights-query"
            table = command(tenant, rows, context.version, values, label)["tables"][0]
            if table["name"] != "PrimaryResult":
                raise RuntimeError(f"{label} returned an unexpected result type")
            fields = [column["name"] for column in table["columns"]]
            result[key] = [dict(zip(fields, row, strict=True)) for row in table["rows"]]
        endpoint = f"{context.origin}/v1{resource}/query"
        status, response = send_token(foreign.config, stranger.token, "POST", endpoint, request)
        if status != 404 or response["error"]["code"] != "SubscriptionNotFound":
            raise RuntimeError("the Logs query accepted a valid foreign token")
        status, response = send_token(tenant.config, context.token, "POST", endpoint, {"query": "search *"})
        if status != 400 or response["error"]["code"] != "UnsupportedQuery":
            raise RuntimeError("the Logs query accepted an unsupported expression")
        result["crossTenantReadDenied"] = result["unsupportedQueryDenied"] = True
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--timespan", default="PT5M")
    args = parser.parse_args()
    print(json.dumps(verify(args.matrix, json.loads(args.fixture.read_text()), args.timespan)))


if __name__ == "__main__":
    main()
