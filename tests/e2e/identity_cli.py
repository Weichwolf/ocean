#!/usr/bin/env python3
"""Exercise fresh Azure CLI sign-ins against a live ocean region."""

import argparse
import base64
import http.cookiejar
import json
import os
import re
import selectors
import ssl
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib import error, parse, request


class LoginForms(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "form":
            self.current = (attrs.get("action", ""), {})
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None and attrs.get("type") == "hidden" and "name" in attrs:
            self.current[1][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class Browser:
    def __init__(self, origin, ca):
        self.origin = origin
        tls = ssl.create_default_context(cafile=ca)
        self.session = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=tls),
                                            request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def open(self, url, fields=None, referer=None):
        if not url.startswith(self.origin + "/"):
            raise RuntimeError("device flow referenced a different origin")
        req = request.Request(url)
        if fields is not None:
            req = request.Request(url, data=parse.urlencode(fields).encode(),
                                  headers={"Origin": self.origin, "Referer": referer})
        with self.session.open(req, timeout=12) as reply:
            if not reply.url.startswith(self.origin + "/"):
                raise RuntimeError("device flow redirected to a different origin")
            return reply.url, reply.read(1 << 20).decode()

    def submit(self, page, expected, fields):
        url, html = page
        forms = LoginForms(html).forms
        for action, hidden in forms:
            target = parse.urljoin(url, action)
            if parse.urlsplit(target).path.endswith("/login-actions/" + expected):
                return self.open(target, hidden | fields, url)
        raise RuntimeError(f"device flow omitted the {expected} form")

    def approve(self, endpoint, code, user, password, reject=False):
        page = self.open(endpoint + "?" + parse.urlencode({"user_code": code}))
        page = self.submit(page, "authenticate", {"username": user, "password": password})
        if reject:
            if parse.urlsplit(page[0]).path.endswith("/login-actions/authenticate") and "Invalid username or password" in page[1]:
                return
            raise RuntimeError("the deleted directory user reached a different device sign-in state")
        page = self.submit(page, "consent", {"code": code, "accept": "Yes"})
        if not parse.urlsplit(page[0]).path.endswith("/device/status"):
            raise RuntimeError("device authorization did not reach the confirmation page")


class AzureCLI:
    def __init__(self, config, cache, *, register=True):
        self.config = config
        self.env = dict(os.environ, AZURE_CONFIG_DIR=cache, AZURE_CORE_INSTANCE_DISCOVERY="false",
                        AZURE_CORE_COLLECT_TELEMETRY="0", REQUESTS_CA_BUNDLE=config["ca"])
        if register:
            self.run("cloud", "register", "--name", "ocean", "--endpoint-resource-manager", config["arm"], "-o", "none")
            self.run("cloud", "set", "--name", "ocean", "-o", "none")

    def run(self, *args, reject=False):
        try:
            result = subprocess.run(["az", *args], env=self.env, capture_output=True, text=True, timeout=32)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"az {args[0]} {args[1]} exceeded the command deadline") from None
        if reject and result.returncode != 0:
            return ""
        if reject or result.returncode != 0:
            raise RuntimeError(f"unexpected response for az {args[0]} {args[1]} (exit {result.returncode})")
        return result.stdout

    def login_service_principal(self, client, secret, reject=False):
        extra = [] if self.config.get("subscription") else ["--allow-no-subscriptions", "--skip-subscription-discovery"]
        # Azure CLI requires the joined form when a generated secret starts with '-'.
        self.run("login", "--tenant", self.config["tenant"], "--service-principal", "--username", client,
                 f"--password={secret}", *extra, "-o", "none", reject=reject)
        if reject:
            endpoint = self.config["authority"] + "/" + self.config["tenant"] + "/oauth2/v2.0/token"
            fields = parse.urlencode({"grant_type": "client_credentials", "client_id": client,
                                      "client_secret": secret, "scope": self.config["arm"] + "/.default"})
            req = request.Request(endpoint, data=fields.encode())
            tls = ssl.create_default_context(cafile=self.config["ca"])
            try:
                with request.urlopen(req, context=tls, timeout=8):
                    pass
            except error.HTTPError as reply:
                with reply:
                    if reply.code in (400, 401) and json.load(reply)["error"] in ("invalid_client", "unauthorized_client"):
                        return
            raise RuntimeError("the token endpoint did not reject the client credentials")

    def login_device(self, reject=False):
        tenant = self.config["tenant"]
        script = ["az", "login", "--tenant", tenant, "--use-device-code", "-o", "none"]
        if not self.config.get("subscription"):
            script += ["--allow-no-subscriptions", "--skip-subscription-discovery"]
        with subprocess.Popen(script, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True) as cli:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(cli.stderr, selectors.EVENT_READ)
                    if not selector.select(timeout=20):
                        raise RuntimeError("Azure CLI did not emit a device prompt")
                    prompt = cli.stderr.readline().strip()
                verification = self.config["provider"] + f"/realms/{tenant}/device"
                pattern = "Open " + re.escape(verification) + r" in a browser and enter the code ([A-Za-z0-9-]+) to sign in\."
                match = re.fullmatch(pattern, prompt)
                if match is None:
                    raise RuntimeError("Azure CLI emitted an unexpected device prompt")
                Browser(self.config["provider"], self.config["ca"]).approve(verification, match[1],
                                                                             self.config["user"], self.config["password"], reject)
                if reject:
                    return
                if cli.wait(timeout=22) != 0:
                    raise RuntimeError("Azure CLI rejected the approved device sign-in")
            finally:
                if cli.poll() is None:
                    cli.kill()

    def resource_subject(self):
        subjects = set()
        for audience in (self.config["arm"], self.config["graph"]):
            token = self.run("account", "get-access-token", "--resource", audience, "--query", "accessToken", "-o", "tsv").strip()
            fields = token.split(".")
            if len(fields) != 3:
                raise RuntimeError("Azure CLI returned an invalid access token")
            payload = fields[1] + "=" * (-len(fields[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            issuer = self.config["provider"] + "/realms/" + self.config["tenant"]
            if claims.get("aud") not in (audience, [audience]) or claims.get("iss") != issuer or not claims.get("sub"):
                raise RuntimeError("Azure CLI token has an unexpected issuer, subject, or audience")
            if audience == self.config["graph"] and self.config.get("subscription"):
                self.reject_graph_token_for_arm(token)
            subjects.add(claims["sub"])
        if len(subjects) != 1:
            raise RuntimeError("the ARM and Graph tokens identify different principals")
        return subjects.pop()

    def check_subscription(self):
        subscription = self.config.get("subscription")
        if not subscription:
            return
        tenant = self.config["tenant"]
        accounts = json.loads(self.run("account", "list", "--all", "-o", "json"))
        if [(item["id"], item["tenantId"]) for item in accounts] != [(subscription, tenant)]:
            raise RuntimeError("the CLI profile does not contain exactly the assigned subscription")
        self.run("account", "set", "--subscription", subscription)
        endpoint = self.config["arm"] + f"/subscriptions/{subscription}?api-version=2022-12-01"
        record = json.loads(self.run("rest", "--method", "get", "--url", endpoint, "-o", "json"))
        if record.get("subscriptionId") != subscription or record.get("tenantId") != tenant:
            raise RuntimeError("ARM returned an unexpected subscription or tenant")
        locations = json.loads(self.run("account", "list-locations", "--query", "[].name", "-o", "json"))
        if locations != [self.config["location"]]:
            raise RuntimeError("ARM returned unexpected subscription locations")

    def reject_graph_token_for_arm(self, token):
        url = self.config["arm"] + "/subscriptions?api-version=2022-12-01"
        req = request.Request(url, headers={"Authorization": "Bearer " + token})
        tls = ssl.create_default_context(cafile=self.config["ca"])
        try:
            with request.urlopen(req, context=tls, timeout=8):
                pass
        except error.HTTPError as reply:
            with reply:
                if reply.code == 401 and json.load(reply)["error"]["code"] == "InvalidAuthenticationToken":
                    return
        raise RuntimeError("ARM did not reject a token issued for Graph")


def check(config):
    with tempfile.TemporaryDirectory(prefix="ocean-user-") as cache:
        cli = AzureCLI(config, cache)
        version = json.loads(cli.run("version", "-o", "json"))
        if version["azure-cli"] != "2.93.0" or version["extensions"]:
            raise RuntimeError("expected Azure CLI 2.93.0 with no installed extensions")
        cli.login_device()
        cli.check_subscription()
        user = cli.resource_subject()
    with tempfile.TemporaryDirectory(prefix="ocean-app-") as cache:
        cli = AzureCLI(config, cache)
        cli.login_service_principal(config["app"], config["secret"])
        cli.check_subscription()
        app = cli.resource_subject()
    with tempfile.TemporaryDirectory(prefix="ocean-invalid-") as cache:
        cli = AzureCLI(config, cache)
        cli.login_service_principal(config["app"], "invalid-credential", reject=True)
        cli.login_service_principal(config["disabledApp"], config["disabledSecret"], reject=True)
    return {"user": user, "application": app, "invalidCredentialsRejected": True}


def check_web_regression(config):
    with (tempfile.TemporaryDirectory(prefix="ocean-web-cli-user-") as user_cache,
          tempfile.TemporaryDirectory(prefix="ocean-web-cli-sp-") as app_cache):
        administrator = AzureCLI(config, user_cache)
        version = json.loads(administrator.run("version", "-o", "json"))
        if version["azure-cli"] != "2.93.0" or version["extensions"]:
            raise RuntimeError("expected Azure CLI 2.93.0 with no installed extensions")
        administrator.login_device()
        administrator.check_subscription()
        user = administrator.resource_subject()
        graph = json.loads(administrator.run("ad", "app", "show", "--id", config["appObject"], "-o", "json"))
        if graph["id"] != config["appObject"] or graph["appId"] != config["app"]:
            raise RuntimeError("Graph returned the wrong tenant application")
        administrator.run("ad", "app", "show", "--id", config["foreignAppObject"], "-o", "json", reject=True)
        cli = AzureCLI(config, app_cache)
        cli.login_service_principal(config["app"], config["secret"])
        cli.check_subscription()
        app = cli.resource_subject()
        cli.run("ad", "app", "show", "--id", config["appObject"], "-o", "json", reject=True)
        policy = config.get("webPolicy")
        if policy is not None:
            path = f"/ocean/tenants/{config['tenant']}/directory/webApplications/{policy['appObject']}"
            url = config["arm"] + path + "?api-version=2026-11-01"
            result = json.loads(administrator.run("rest", "--method", "put", "--url", url,
                                                  "--body", json.dumps({"groupIds": policy["groupIds"]}), "-o", "json"))
            if result["properties"]["provisioningState"] != "Succeeded":
                raise RuntimeError("the tenant administrator could not publish the Kerberos web policy")
    return {"user": user, "application": app}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--web-regression", action="store_true")
    args = parser.parse_args()
    probe = check_web_regression if args.web_regression else check
    print(json.dumps(probe(json.loads(args.settings.read_text())), sort_keys=True))


if __name__ == "__main__":
    main()
