#!/usr/bin/env python3
"""Exercise a disposable Firefox profile inside a Samba employee's PAM session."""

import base64
import errno
import json
import os
import pty
import pwd
import select
import shlex
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib import error, request


def ticket_list():
    if not os.environ.get("KRB5CCNAME"):
        raise RuntimeError("PAM did not provide a Kerberos credential cache")
    return subprocess.check_output(["klist", "-e"], text=True)


def service_encryption(listing, service):
    found = False
    encryption = ""
    for line in listing.splitlines():
        if not line.startswith((" ", "\t")):
            found = line.rstrip().endswith(" " + service)
            encryption = ""
        elif "Etype (skey, tkt): " in line:
            encryption = line.rsplit(",", 1)[-1].strip()
        elif line.strip() == "Ticket server: " + service:
            found = True
        if found and encryption:
            return encryption
    return ""


def browser(config):
    account = pwd.getpwuid(os.getuid()).pw_name
    if account != config["user"]:
        raise RuntimeError("Firefox did not start as the domain account")
    before = ticket_list()
    if ("Default principal: " + config["principal"] not in before or
            config["ticketGrantingPrincipal"] not in before or config["servicePrincipal"] in before):
        raise RuntimeError("expected a new PAM cache with the employee's TGT")
    with tempfile.TemporaryDirectory(prefix="ocean-web-domain-") as directory:
        os.environ["HOME"] = directory
        profile = Path(directory)
        database = "sql:" + directory
        subprocess.run(["certutil", "-N", "--empty-password", "-d", database], check=True)
        for name in ("providerCA", "callbackCA"):
            certificate = profile / (name + ".pem")
            certificate.write_bytes(base64.b64decode(config[name], validate=True))
            subprocess.run(["certutil", "-A", "-n", name, "-i", certificate, "-t", "C,,", "-d", database], check=True)
        (profile / "user.js").write_text(
            'user_pref("network.negotiate-auth.trusted-uris", ' + json.dumps(config["origin"]) + ');\n'
            'user_pref("network.negotiate-auth.delegation-uris", "");\n'
            'user_pref("network.proxy.type", 0);\n')
        tls = ssl.create_default_context(cafile=str(profile / "callbackCA.pem"))
        opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=tls))
        started = time.monotonic()
        output = profile / "firefox.log"
        command = ["nice", "-n", "15", "firefox-esr", "--headless", "--no-remote", "--profile", directory, config["authorize"]]
        with output.open("w+") as diagnostics, subprocess.Popen(command, stdout=diagnostics, stderr=subprocess.STDOUT) as process:
            try:
                while time.monotonic() - started < 40:
                    if process.poll() is not None:
                        raise RuntimeError("Firefox exited before the callback")
                    try:
                        with opener.open(config["completed"], timeout=3) as reply:
                            if reply.status == 204:
                                measured = round((time.monotonic() - started) * 1000)
                                break
                    except error.HTTPError as failure:
                        if failure.code != 404:
                            raise
                    time.sleep(0.2)
                else:
                    diagnostics.seek(0)
                    raise RuntimeError("Firefox did not finish the domain session: " + diagnostics.read(2048))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    encryption = service_encryption(ticket_list(), config["servicePrincipal"])
    if encryption not in ("aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"):
        raise RuntimeError("Firefox did not acquire an AES HTTP service ticket in the PAM cache")
    print("OCEAN_BROWSER " + json.dumps({"user": account, "principal": config["principal"],
                                         "servicePrincipal": config["servicePrincipal"], "encryption": encryption,
                                         "durationMs": measured}))


def login(config, source):
    password = config.pop("password").encode()
    command = shlex.join(["/usr/bin/python3", "-c", source, "--browser", json.dumps(config)])
    child, terminal = pty.fork()
    if child == 0:
        os.execve("/usr/bin/su", ["su", "--login", "--command", command, "--", config["user"]],
                  {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1"})
    received = bytearray()
    deadline = time.monotonic() + 55
    sent = False
    try:
        while (remaining := deadline - time.monotonic()) > 0:
            readable, _, _ = select.select([terminal], [], [], remaining)
            if not readable:
                break
            try:
                block = os.read(terminal, 4096)
            except OSError as failure:
                if failure.errno != errno.EIO:
                    raise
                block = b""
            if not block:
                _, status = os.waitpid(child, 0)
                if not sent:
                    raise RuntimeError("PAM did not present the password prompt")
                sys.stdout.buffer.write(received.replace(password, b"[redacted]"))
                return os.waitstatus_to_exitcode(status)
            received.extend(block)
            if not sent and b"Password:" in received:
                os.write(terminal, password + b"\n")
                sent = True
        os.kill(child, signal.SIGTERM)
        os.waitpid(child, 0)
        raise TimeoutError("the PAM login session exceeded its deadline")
    finally:
        os.close(terminal)


if len(sys.argv) == 3 and sys.argv[1] == "--browser":
    browser(json.loads(sys.argv[2]))
elif len(sys.argv) == 2:
    raise SystemExit(login(json.load(sys.stdin), Path(sys.argv[1]).read_text()))
