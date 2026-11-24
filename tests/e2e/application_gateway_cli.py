#!/usr/bin/env python3
"""Verify the pinned Application Gateway CLI validation workflow."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from arm_cli import GroupContract, command_args, create_customers, load_matrix
from identity_cli import AzureCLI


def issue_test_certificate(folder):
    certificate = folder / "ingress.pem"
    private_key = folder / "ingress.key"
    bundle = folder / "ingress.pfx"
    password = "fixture-" + uuid4().hex
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-noenc", "-days", "1",
                    "-subj", "/CN=ingress.ocean.test", "-addext", "subjectAltName=DNS:ingress.ocean.test",
                    "-keyout", private_key, "-out", certificate], check=True, capture_output=True)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", private_key, "-in", certificate,
                    "-out", bundle, "-passout", "pass:" + password], check=True, capture_output=True)
    return bundle, password


def verify(config, matrix_path):
    tenant, _ = create_customers(config)
    group = "appgw-" + uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="ocean-app-gateway-cli-") as directory:
        folder = Path(directory)
        cli = AzureCLI(tenant, str(folder / "az"))
        cli.login_device()
        contract = GroupContract(cli, load_matrix(matrix_path))
        gateway = load_matrix(matrix_path, "NETWORK-02")
        network = load_matrix(matrix_path, "NETWORK-01")
        egress = load_matrix(matrix_path, "NETWORK-03")
        bundle, password = issue_test_certificate(folder)
        network_id = (f"/subscriptions/{tenant['subscription']}/resourceGroups/{group}"
                      "/providers/Microsoft.Network")
        bindings = {"group": group, "location": tenant["location"], "vnet": "private", "subnet": "workloads",
                    "vnet_prefix": "10.89.0.0/16", "subnet_prefix": "10.89.1.0/24", "ip": "external",
                    "public_ip_id": network_id + "/publicIPAddresses/external",
                    "subnet_id": network_id + "/virtualNetworks/private/subnets/workloads", "gateway": "ingress",
                    "backend_ip": "10.89.1.4", "backend_port": "8080", "certificate_pfx": str(bundle),
                    "certificate_password": password, "nat": "control"}

        def validate(expected_error=None, **overrides):
            args = command_args(gateway["app-gateway-create"], contract.version, **(bindings | overrides))
            reply = subprocess.run(["az", *args, "--validate"], env=cli.env, capture_output=True, text=True, timeout=40)
            if expected_error:
                if reply.returncode == 0 or f"({expected_error})" not in reply.stderr:
                    raise RuntimeError(f"the Azure CLI did not report {expected_error} for the invalid gateway")
            elif reply.returncode != 0:
                code = next((line.rsplit(":", 1)[-1].strip() for line in reply.stderr.splitlines() if line.startswith("Code:")), "")
                raise RuntimeError(f"the Azure CLI rejected gateway validation ({code or reply.returncode})")

        def inventory():
            return json.loads(cli.run("resource", "list", "--resource-group", group, "-o", "json"))

        contract.command("group-create", group)
        try:
            cli.run(*command_args(network["vnet-create"], contract.version, **bindings))
            cli.run(*command_args(egress["public-ip-create"], contract.version, **bindings))
            before = inventory()
            validate()
            validate("InvalidTemplate", backend_ip="10.89.2.4")
            validate("InvalidCertificate", certificate_password="incorrect")
            if inventory() != before:
                raise RuntimeError("application gateway validation modified the resource group")
            cli.run(*command_args(egress["nat-create"], contract.version, **bindings))
            validate("PublicIPAddressInUse")
            cli.run(*command_args(egress["nat-delete"], contract.version, **bindings))
            validate()
            if inventory() != before:
                raise RuntimeError("the validated configuration left resources behind")
            return {"azureCLI": contract.version["azure-cli"],
                    "deploymentsAndTemplateVersions": gateway["app-gateway-create"]["api_version"],
                    "validHTTPSConfiguration": True, "outsideSubnetRejected": True, "wrongPFXPasswordRejected": True,
                    "claimedPublicAddressRejected": True, "validationLeftResourcesUnchanged": True}
        finally:
            contract.command("group-delete", group)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.settings.read_text()), args.matrix), sort_keys=True))


if __name__ == "__main__":
    main()
