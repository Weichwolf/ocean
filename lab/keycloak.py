#!/usr/bin/env python3
"""Deploy redundant Keycloak instances for the regional identity lab."""

import argparse
import concurrent.futures
import hashlib
import json
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from postgres import credential, primary
from region import ARM, DEST as REGION, GRAPH, IDENTITY, NODES, OAUTH, OPERATOR, ROOT
from region import ca, eventually, gateway_files, leaf, resolver_unit, ssh, upload

DEST = "/opt/ocean-keycloak"
VERSION = "26.8.2"
SHA256 = "dd124787283918bc597628887168333465ee2a811a389e0003569e52be7e487f"
RUNTIME = f"{DEST}/keycloak-{VERSION}"
SERVICE = "ocean-keycloak.service"
ACCOUNT = "ocean-keycloak"
REPLICAS = dict(list(NODES.items())[:2])
TENANT = "c8c02ae2-b2c9-4762-9bb5-08b660caf0ae"
APP = "7d72738e-5243-4803-85b4-ce34eaf6b3f2"
DISABLED_APP = "e60f7c71-8c98-40eb-8e3c-d2a38141cb09"
USER = "customer@lab.ocean.test"
CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
EXCHANGE = "ocean-token-exchange"
OPERATOR_TENANT = "4fd57c3e-f49c-4b52-a834-7ef394451db6"
OPERATOR_APP = "b356c1b7-18e4-43e8-957d-d964f5f8aa63"


def mapper(name, kind, **config):
    return {"name": name, "protocol": "openid-connect", "protocolMapper": f"oidc-{kind}-mapper", "config": config}


def scope(name, *mappers, visible=True):
    return {"name": name, "protocol": "openid-connect", "protocolMappers": list(mappers),
            "attributes": {"include.in.token.scope": str(visible).lower()}}


def tenant_fixture(passwords):
    profile = scope("profile",
                    mapper("username", "usermodel-property", **{
                        "user.attribute": "username", "claim.name": "preferred_username", "id.token.claim": "true",
                        "access.token.claim": "true", "userinfo.token.claim": "true", "jsonType.label": "String",
                    }),
                    mapper("tenant", "hardcoded-claim", **{
                        "claim.name": "tid", "claim.value": TENANT, "access.token.claim": "true",
                        "id.token.claim": "true", "jsonType.label": "String",
                    }))
    basic = scope("basic", mapper("subject", "sub", **{"access.token.claim": "true"}), visible=False)
    exchange_scope = scope("ocean-grant", mapper("exchange", "audience", **{
        "included.client.audience": EXCHANGE, "access.token.claim": "true", "id.token.claim": "false",
    }), visible=False)
    resources = [
        scope(f"https://{host}/.default", mapper(host, "audience", **{
            "included.custom.audience": f"https://{host}", "access.token.claim": "true", "id.token.claim": "false",
        }))
        for host in (ARM, GRAPH)
    ]
    resource_scopes = [item["name"] for item in resources]
    public = {
        "clientId": CLI, "enabled": True, "publicClient": True, "protocol": "openid-connect",
        "fullScopeAllowed": False, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        "attributes": {"oauth2.device.authorization.grant.enabled": "true"},
        "defaultClientScopes": ["profile", "basic", exchange_scope["name"]], "optionalClientScopes": ["offline_access"],
    }
    clients = [
        {"clientId": client, "enabled": enabled, "publicClient": False, "protocol": "openid-connect",
         "fullScopeAllowed": False, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
         "serviceAccountsEnabled": True, "clientAuthenticatorType": "client-secret", "secret": passwords[label],
         "defaultClientScopes": ["basic"], "optionalClientScopes": resource_scopes}
        for client, label, enabled in ((APP, "app", True), (DISABLED_APP, "disabled-app", False))
    ]
    exchange = {
        "clientId": EXCHANGE, "enabled": True, "publicClient": False, "protocol": "openid-connect",
        "fullScopeAllowed": False, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False, "clientAuthenticatorType": "client-secret", "secret": passwords["exchange"],
        "attributes": {"standard.token.exchange.enabled": "true"},
        "defaultClientScopes": ["profile", "basic"], "optionalClientScopes": resource_scopes,
    }
    user = {
        "username": USER, "enabled": True, "firstName": "Lab", "lastName": "Customer",
        "email": USER, "emailVerified": True, "realmRoles": ["offline_access"],
        "credentials": [{"type": "password", "value": passwords["user"], "temporary": False}],
    }
    return {
        "realm": TENANT, "displayName": "Ocean identity failover lab", "enabled": True, "sslRequired": "all",
        "accessTokenLifespan": 300, "offlineSessionMaxLifespanEnabled": True,
        "offlineSessionMaxLifespan": 28800, "offlineSessionIdleTimeout": 3600,
        "roles": {"realm": [{"name": "offline_access"}]}, "scopeMappings": [{"clientScope": "offline_access", "roles": ["offline_access"]}],
        "clientScopes": [basic, profile, scope("offline_access"), exchange_scope, *resources],
        "clients": [public, exchange, *clients], "users": [user],
    }


def provider_unit():
    return f"""[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={ACCOUNT}
EnvironmentFile={DEST}/environment.secret
ExecStart={RUNTIME}/bin/kc.sh start --optimized --import-realm --spi-connections-jpa--quarkus--async-commit=false
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
""".encode()


def prepare_node(state, node, archive, files, java_options):
    ssh(state, node, "if ! test -x /usr/bin/java; then sudo apt-get -qq update && "
        "sudo env DEBIAN_FRONTEND=noninteractive apt-get -yqq --no-install-recommends install openjdk-21-jre-headless; fi; "
        f"if ! getent passwd {ACCOUNT} >/dev/null; then "
        f"sudo useradd --system --home-dir {DEST} --shell /usr/sbin/nologin {ACCOUNT}; fi; "
        f"sudo install -d -m 0755 {DEST}")
    present = ssh(state, node, f"test ! -x {RUNTIME}/bin/kc.sh || printf present").strip()
    if not present:
        ssh(state, node, f"sudo tar -xzf - --no-same-owner -C {DEST} && sudo chown -R {ACCOUNT}:{ACCOUNT} {RUNTIME}", archive.read_bytes())
    ssh(state, node, f"sudo install -d -m 0700 -o {ACCOUNT} {RUNTIME}/data/import")
    upload(state, node, files, DEST, ACCOUNT)
    ssh(state, node, f"sudo install -m 0600 -o {ACCOUNT} {DEST}/realm.secret {RUNTIME}/data/import/{TENANT}-realm.json && "
        f"sudo install -m 0644 {DEST}/units/{SERVICE} /etc/systemd/system/{SERVICE} && sudo systemctl daemon-reload && "
        f"if ! test -e {RUNTIME}/.ocean-built; then "
        f"sudo -u {ACCOUNT} env JAVA_OPTS_APPEND={shlex.quote(java_options)} "
        f"{RUNTIME}/bin/kc.sh build --db=postgres --health-enabled=true --metrics-enabled=true && "
        f"sudo touch {RUNTIME}/.ocean-built; fi")


def provider_health(state, node):
    address = REPLICAS[node]
    return ssh(state, node, f"curl -fsS --max-time 3 --cacert {REGION}/pki/ingress-ca.pem "
               f"--resolve {OAUTH}:9000:{address} https://{OAUTH}:9000/health/ready")


def prepare_operator(state, passwords):
    arm = f"https://{ARM}"
    realm = {
        "realm": OPERATOR_TENANT, "enabled": True, "sslRequired": "all", "accessTokenLifespan": 300,
        "attributes": {"oceanOperatorFixture": OPERATOR_APP},
        "clientScopes": [
            scope("basic", mapper("subject", "sub", **{"access.token.claim": "true"}), visible=False),
            scope(arm + "/.default", mapper("arm", "audience", **{
                "included.custom.audience": arm, "access.token.claim": "true", "id.token.claim": "false",
            })),
        ],
        "clients": [{
            "clientId": OPERATOR_APP, "enabled": True, "publicClient": False, "protocol": "openid-connect",
            "fullScopeAllowed": False, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True, "clientAuthenticatorType": "client-secret", "secret": passwords["operator"],
            "defaultClientScopes": ["basic"], "optionalClientScopes": [arm + "/.default"],
        }],
    }
    node, address = next(iter(REPLICAS.items()))
    program = """
import json, ssl, sys
from urllib import error, parse, request
config = json.load(sys.stdin)
origin = config["origin"]
realm = config["realm"]
tls = ssl.create_default_context(cafile=config["ca"])
body = parse.urlencode({"grant_type":"client_credentials","client_id":"ocean-bootstrap","client_secret":config["admin"]}).encode()
with request.urlopen(origin + "/realms/master/protocol/openid-connect/token", body, context=tls, timeout=12) as reply:
    token = json.load(reply)["access_token"]
headers = {"Authorization": "Bearer "+token, "Content-Type": "application/json"}
url = origin + "/admin/realms/" + realm["realm"]
try:
    with request.urlopen(request.Request(url, headers=headers), context=tls, timeout=12) as reply:
        if json.load(reply).get("attributes",{}).get("oceanOperatorFixture") != config["client"]:
            raise RuntimeError("the operator realm is already in use")
except error.HTTPError as exc:
    if exc.code != 404:
        raise
    with request.urlopen(request.Request(origin + "/admin/realms", json.dumps(realm).encode(), headers),
                         context=tls, timeout=60) as reply:
        if reply.status != 201:
            raise RuntimeError("failed to create the lab operator realm")
"""
    ssh(state, node, shlex.join(["python3", "-c", program]), json.dumps({
        "origin": f"https://{address}:8444", "ca": f"{REGION}/pki/ingress-ca.pem",
        "admin": passwords["bootstrap"], "realm": realm, "client": OPERATOR_APP,
    }).encode())


def configure_gateways(state, pki, ingress):
    for index, (node, address) in enumerate(REPLICAS.items()):
        files = gateway_files(index + 1, address, list(REPLICAS.values())[1 - index], identity=True)
        certificate = leaf(pki, node + "-oauth-ingress", ingress, "serverAuth", f"DNS:{OAUTH}")
        files["pki/oauth-ingress.key"] = certificate[f"pki/{node}-oauth-ingress.pem"] + certificate[f"pki/{node}-oauth-ingress.key"]
        files["pki/ingress-ca.pem"] = ingress[0].read_bytes()
        upload(state, node, files)
        ssh(state, node, f"sudo /usr/sbin/haproxy -c -f {REGION}/haproxy.cfg && "
            "sudo systemctl restart ocean-gateway.service ocean-dns.service")


def configure_api(state, pki, ingress, passwords):
    for node, address in NODES.items():
        name = node + "-api-identity"
        config = json.loads(ssh(state, node, f"cat {REGION}/api.json"))
        config["tls"] = {"certificateFile": f"{REGION}/pki/{name}.pem", "keyFile": f"{REGION}/pki/{name}.key"}
        config["identity"] = {
            "authority": f"https://{IDENTITY}", "provider": f"https://{OAUTH}",
            "providerCAFile": f"{REGION}/pki/ingress-ca.pem", "exchangeSecretDirectory": f"{REGION}/exchange",
            "cloud": {"resourceManager": f"https://{ARM}", "microsoftGraph": f"https://{GRAPH}"},
            "onboarding": {
                "operatorTenant": OPERATOR_TENANT, "operatorClient": OPERATOR_APP,
                "adminEndpoints": [f"https://{member}:8444" for member in REPLICAS.values()],
                "adminClient": "ocean-bootstrap", "adminSecretFile": f"{REGION}/identity-admin.secret",
                "regionalKeyFile": f"{REGION}/identity-regional.secret",
            },
        }
        files = leaf(pki, name, ingress, "serverAuth", f"DNS:{ARM},DNS:{IDENTITY},DNS:{GRAPH},IP:{address}")
        files.update({
            "api.json": json.dumps(config).encode(), f"exchange/{TENANT}.secret": passwords["exchange"].encode(),
            "identity-admin.secret": passwords["bootstrap"].encode(), "identity-regional.secret": passwords["regional"].encode(),
            "bin/ocean-control-plane.next": (ROOT / "bin/ocean-control-plane").read_bytes(),
            "pki/ingress-ca.pem": ingress[0].read_bytes(),
            "units/ocean-resolver.service": resolver_unit(),
        })
        ssh(state, node, f"sudo install -m 0700 -d -o ocean {REGION}/exchange")
        upload(state, node, files)
        ssh(state, node, f"sudo mv {REGION}/bin/ocean-control-plane.next {REGION}/bin/ocean-control-plane && "
            f"sudo install -m 0644 {REGION}/units/ocean-resolver.service /etc/systemd/system/ && "
            "sudo systemctl daemon-reload && sudo systemctl enable --now ocean-resolver.service && "
            "sudo systemctl restart ocean-api.service")
        eventually(lambda: ssh(state, node, f"curl -fsS --max-time 3 --cacert {REGION}/pki/ingress-ca.pem "
                   f"--resolve {ARM}:8443:{address} https://{ARM}:8443/readyz"))


def deploy(state, archive, heap_mib=768):
    if not 256 <= heap_mib <= 768:
        raise ValueError("the lab Keycloak heap must be between 256 and 768 MiB")
    java_options = f"-XX:ActiveProcessorCount=2 -Xms128m -Xmx{heap_mib}m"
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SHA256:
            raise RuntimeError("Keycloak archive SHA-256 does not match the pinned release")
    primary(state, next(iter(NODES)))
    pki = state / "identity-pki"
    pki.mkdir(mode=0o700, exist_ok=True)
    ingress = ca(state / "region-pki", "ingress-ca")
    database_ca = state / "postgres-pki/postgres-rsa-ca.pem"
    passwords = {label: credential(pki, label) for label in ("bootstrap", "exchange", "user", "app", "disabled-app", "operator", "regional")}
    fixture = json.dumps(tenant_fixture(passwords)).encode()
    database = ",".join(f"{address}:5432" for address in NODES.values())
    jobs = []
    for node, address in REPLICAS.items():
        name = node + "-keycloak"
        files = leaf(pki, name, ingress, "serverAuth", f"DNS:{OAUTH},IP:{address}", "rsa:3072")
        settings = {
            "KC_DB_USERNAME": "keycloak", "KC_DB_PASSWORD": (state / "postgres-pki/keycloak.secret").read_text(),
            "KC_DB_URL": f"jdbc:postgresql://{database}/keycloak?targetServerType=primary&hostRecheckSeconds=1"
                         f"&connectTimeout=3&socketTimeout=8&sslmode=verify-full&sslrootcert={DEST}/pki/postgres-ca.pem",
            "KC_DB_POOL_INITIAL_SIZE": "2", "KC_DB_POOL_MIN_SIZE": "2", "KC_DB_POOL_MAX_SIZE": "12",
            "KC_HOSTNAME": f"https://{OAUTH}", "KC_HTTP_HOST": address, "KC_HTTPS_PORT": "8444",
            "KC_HTTPS_CERTIFICATE_FILE": f"{DEST}/pki/{name}.pem", "KC_HTTPS_CERTIFICATE_KEY_FILE": f"{DEST}/pki/{name}.key",
            "KC_PROXY_HEADERS": "xforwarded", "KC_PROXY_TRUSTED_ADDRESSES": ",".join(REPLICAS.values()),
            "KC_CACHE_EMBEDDED_NETWORK_BIND_ADDRESS": address, "KC_CACHE_EMBEDDED_NODE_NAME": node,
            "KC_BOOTSTRAP_ADMIN_CLIENT_ID": "ocean-bootstrap", "KC_BOOTSTRAP_ADMIN_CLIENT_SECRET": passwords["bootstrap"],
            "JAVA_OPTS_APPEND": json.dumps(java_options),
        }
        files.update({
            "pki/postgres-ca.pem": database_ca.read_bytes(), "environment.secret": "".join(f"{k}={v}\n" for k, v in settings.items()).encode(),
            "realm.secret": fixture, f"units/{SERVICE}": provider_unit(),
        })
        jobs.append((state, node, archive, files, java_options))
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(REPLICAS)) as pool:
        list(pool.map(lambda job: prepare_node(*job), jobs))
    for node in REPLICAS:
        ssh(state, node, f"sudo systemctl enable --now --no-block {SERVICE}")
        eventually(lambda node=node: provider_health(state, node), 240)
    eventually(lambda: prepare_operator(state, passwords), 90)
    configure_gateways(state, pki, ingress)
    configure_api(state, pki, ingress, passwords)
    upload(state, OPERATOR, {"pki/ingress-ca.pem": ingress[0].read_bytes()})
    eventually(lambda: ssh(state, OPERATOR, f"curl -fsS --max-time 3 --cacert {REGION}/pki/ingress-ca.pem "
               f"https://{IDENTITY}/{TENANT}/v2.0/.well-known/openid-configuration"), 35)
    print(f"Two Keycloak replicas are ready behind https://{IDENTITY} and https://{OAUTH}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--keycloak-archive", type=Path, required=True)
    parser.add_argument("--heap-mib", type=int, default=768)
    args = parser.parse_args()
    deploy(args.state.resolve(), args.keycloak_archive, args.heap_mib)


if __name__ == "__main__":
    main()
