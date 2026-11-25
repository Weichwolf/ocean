#!/usr/bin/env python3
"""Deploy the regional management stack in the single-farm KVM lab."""

import argparse
import concurrent.futures
import hashlib
import io
import json
import shlex
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = "/opt/ocean-region"
DOMAIN = "farm-1.ocean.test"
ARM = "arm." + DOMAIN
IDENTITY = "id." + DOMAIN
GRAPH = "graph." + DOMAIN
OAUTH = "oauth." + DOMAIN
VIP = "10.231.1.10"
NODES = {f"farm-1-node-{index:02d}": f"10.231.1.{index + 10}" for index in range(1, 4)}
OPERATOR = "farm-1-operator"
ETCD_SHA = "5c6365e03d0c81f605458f3f9a115f6daaebca08d1fb42d3ab0f1a38fd30909c"
ETCD_ROOT = "etcd-v3.6.17-linux-amd64"


def run(args, payload=None, *, timeout=180):
    result = subprocess.run(args, input=payload, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{shlex.join(map(str, args))}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def ssh(state, guest, command, payload=None, *, timeout=180):
    return run([ROOT / "bin/ocean-lab", "ssh", "-state", state, guest, "--", command], payload, timeout=timeout)


def eventually(check, seconds=30):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return check()
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            if time.monotonic() >= deadline:
                raise error
            time.sleep(1)


def ca(pki, name, key_type="ed25519"):
    certificate, key = pki / (name + ".pem"), pki / (name + ".key")
    if certificate.exists():
        public_key = run(["openssl", "x509", "-in", certificate, "-pubkey", "-noout"])
        if public_key != run(["openssl", "pkey", "-in", key, "-pubout"]):
            raise RuntimeError(f"the {name} certificate and private key do not match")
        usages = run(["openssl", "x509", "-in", certificate, "-noout", "-ext", "keyUsage"])
        if b"Certificate Sign" in usages and b"CRL Sign" in usages:
            return certificate, key
    with tempfile.TemporaryDirectory(dir=pki) as directory:
        staged_key = Path(directory) / "private.key"
        staged_certificate = Path(directory) / "certificate.pem"
        options = ["-key", key] if key.exists() else ["-newkey", key_type, "-noenc", "-keyout", staged_key]
        run(["openssl", "req", "-new", "-x509", *options, "-days", "30",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-subj", f"/CN=ocean-lab-{name}", "-out", staged_certificate])
        if staged_key.exists():
            staged_key.replace(key)
        staged_certificate.replace(certificate)
    return certificate, key


def leaf(pki, name, authority, usages, names="", key_type="ed25519"):
    certificate, key = pki / (name + ".pem"), pki / (name + ".key")
    if not certificate.exists():
        with tempfile.TemporaryDirectory(dir=pki) as directory:
            csr = Path(directory) / "request"
            extensions = Path(directory) / "extensions"
            lines = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature", f"extendedKeyUsage={usages}"]
            if names:
                lines.append(f"subjectAltName={names}")
            extensions.write_text("\n".join(lines) + "\n")
            run(["openssl", "req", "-new", "-newkey", key_type, "-noenc", "-subj", f"/CN={name}", "-keyout", key, "-out", csr])
            run(["openssl", "x509", "-req", "-in", csr, "-CA", authority[0], "-CAkey", authority[1], "-CAcreateserial",
                 "-days", "14", "-extfile", extensions, "-out", certificate])
    return {f"pki/{name}.pem": certificate.read_bytes(), f"pki/{name}.key": key.read_bytes()}


def upload(state, guest, files, destination=DEST, owner="ocean"):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name.startswith("bin/") else 0o600 if name.endswith((".key", ".secret")) else 0o644
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    scripts = [
        shlex.join(["sudo", "install", "-d", destination]),
        shlex.join(["sudo", "tar", "-xz", "--no-same-owner", "-C", destination]),
    ]
    secrets = [f"{destination}/{name}" for name in files if name.endswith((".key", ".secret"))]
    if secrets:
        scripts.append(shlex.join(["sudo", "chown", owner, *secrets]))
    scripts.append(shlex.join(["sudo", "sync", "-f", destination]))
    ssh(state, guest, " && ".join(scripts), payload.getvalue())


def unit(command, user="root", after="network-online.target"):
    return f"""[Unit]
After={after}
Wants=network-online.target

[Service]
Type=simple
User={user}
ExecStart={command}
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
""".encode()


def node_files(name, address, binary, etcd, public, pki, authorities):
    peer, storage, ingress = authorities
    files = dict(public, **etcd)
    files.update(leaf(pki, f"{name}-peer", peer, "serverAuth,clientAuth", f"IP:{address}"))
    # etcd's HTTPS gateway dials its own client listener with this certificate.
    server_name = f"{name}-etcd-gateway"
    files.update(leaf(pki, server_name, storage, "serverAuth,clientAuth", f"IP:{address}"))
    files.update(leaf(pki, f"{name}-api-client", storage, "clientAuth"))
    files.update(leaf(pki, f"{name}-api", ingress, "serverAuth", f"DNS:{ARM},IP:{address}"))
    files["bin/ocean-control-plane"] = binary
    cluster = ",".join(f"{node}=https://{ip}:2380" for node, ip in NODES.items())
    args = [f"--name={name}", f"--listen-client-urls=https://{address}:2379", f"--advertise-client-urls=https://{address}:2379",
            f"--listen-peer-urls=https://{address}:2380", f"--initial-advertise-peer-urls=https://{address}:2380",
            f"--initial-cluster={cluster}", "--initial-cluster-token=ocean-farm-1", f"--data-dir={DEST}/data",
            f"--cert-file={DEST}/pki/{server_name}.pem", f"--key-file={DEST}/pki/{server_name}.key",
            f"--trusted-ca-file={DEST}/pki/storage-ca.pem", "--client-cert-auth",
            f"--peer-cert-file={DEST}/pki/{name}-peer.pem", f"--peer-key-file={DEST}/pki/{name}-peer.key",
            f"--peer-trusted-ca-file={DEST}/pki/peer-ca.pem", "--peer-client-cert-auth"]
    files["units/ocean-etcd.service"] = unit(f"{DEST}/bin/etcd {' '.join(args)}", "ocean")
    files["units/ocean-api.service"] = unit(f"{DEST}/bin/ocean-control-plane -config {DEST}/api.json", "ocean")
    files["api.json"] = json.dumps({
        "listenAddress": f"{address}:8443",
        "tls": {"certificateFile": f"{DEST}/pki/{name}-api.pem", "keyFile": f"{DEST}/pki/{name}-api.key"},
        "region": {"name": "farm-1", "initialCell": "cell-1", "etcd": {
            "endpoints": [f"https://{ip}:2379" for ip in NODES.values()], "caFile": f"{DEST}/pki/storage-ca.pem",
            "certificateFile": f"{DEST}/pki/{name}-api-client.pem", "keyFile": f"{DEST}/pki/{name}-api-client.key"}},
    }).encode()
    return files


def gateway_files(index, address, peer, identity=False):
    servers = "\n".join(
        f"  server {node} {ip}:8443 check check-ssl check-sni {ARM} verify required ca-file {DEST}/pki/ingress-ca.pem verifyhost {ARM}"
        for node, ip in NODES.items()
    )
    dispatch = ""
    if identity:
        dispatch = f"""  tcp-request inspect-delay 2s
  tcp-request content accept if {{ req.ssl_hello_type 1 }}
  use_backend oauth_tls if {{ req.ssl_sni -i {OAUTH} }}
"""
    proxy = f"""global
  nbthread 1
defaults
  mode tcp
  timeout connect 2s
  timeout client 30s
  timeout server 30s
  timeout check 2s
frontend management
  bind {VIP}:443 transparent
{dispatch}  default_backend api
backend api
  option httpchk GET /readyz
  http-check expect status 204
  option redispatch
  retries 2
  default-server inter 500ms fall 2 rise 1
{servers}
"""
    if identity:
        provider_servers = "\n".join(
            f"  server {node} {ip}:8444 check ssl sni str({OAUTH}) verify required "
            f"ca-file {DEST}/pki/ingress-ca.pem verifyhost {OAUTH}"
            for node, ip in list(NODES.items())[:2]
        )
        proxy += f"""
backend oauth_tls
  server local 127.0.0.1:9443 send-proxy-v2
frontend oauth_http
  mode http
  bind 127.0.0.1:9443 accept-proxy ssl crt {DEST}/pki/oauth-ingress.key
  acl oauth_canonical path_reg ^/[A-Za-z0-9/_.~-]+$
  acl oauth_dot_path path_reg (//|(^|/)[.]{{1,2}}(/|$))
  http-request deny unless oauth_canonical
  http-request deny if oauth_dot_path
  acl oauth_path path_reg ^/realms/[0-9a-f-]+/(device(/status)?$|login-actions/|protocol/openid-connect/(auth(/device)?|certs|token)$|[.]well-known/openid-configuration$)
  acl oauth_assets path_beg /resources/
  http-request deny unless oauth_path or oauth_assets
  http-request del-header Forwarded
  http-request del-header X-Forwarded-Prefix
  http-request set-header X-Forwarded-Proto https
  http-request set-header X-Forwarded-Port 443
  http-request set-header X-Forwarded-Host {OAUTH}
  http-request set-header X-Forwarded-For %[src]
  http-request set-header Host {OAUTH}
  default_backend oauth
backend oauth
  mode http
  option httpchk
  http-check connect port 9000 ssl sni {OAUTH}
  http-check send meth GET uri /health/ready ver HTTP/1.1 hdr Host {OAUTH}
  http-check expect status 200
  option redispatch
  retries 2
  default-server inter 500ms fall 2 rise 1
{provider_servers}
"""
    vrrp = f"""global_defs {{
  script_user root
  enable_script_security
}}
vrrp_script check_gateway {{
  script \"/usr/bin/systemctl is-active --quiet ocean-gateway.service\"
  interval 1
}}
vrrp_instance MANAGEMENT {{
  state BACKUP
  interface mgmt0
  virtual_router_id 51
  priority {120 if index == 1 else 100}
  nopreempt
  advert_int 1
  unicast_src_ip {address}
  unicast_peer {{
    {peer}
  }}
  virtual_ipaddress {{
    {VIP}/24 dev mgmt0
  }}
  track_script {{
    check_gateway
  }}
}}
"""
    names = [ARM, IDENTITY]
    if identity:
        names += [OAUTH, GRAPH]
    dns = f"""no-resolv
no-hosts
bind-interfaces
listen-address={address}
auth-server=ns1.{DOMAIN},mgmt0
auth-zone={DOMAIN},10.231.1.0/24
auth-sec-servers=ns2.{DOMAIN}
host-record=ns1.{DOMAIN},10.231.1.11
host-record=ns2.{DOMAIN},10.231.1.12
host-record={",".join(names)},{VIP}
"""
    return {"haproxy.cfg": proxy.encode(), "keepalived.conf": vrrp.encode(), "dnsmasq.conf": dns.encode(),
            "units/ocean-gateway.service": unit(f"/usr/sbin/haproxy -db -f {DEST}/haproxy.cfg"),
            "units/ocean-vip.service": unit(f"/usr/sbin/keepalived --dont-fork --log-console --use-file {DEST}/keepalived.conf",
                                            after="network-online.target ocean-gateway.service"),
            "units/ocean-dns.service": unit(f"/usr/sbin/dnsmasq --keep-in-foreground --conf-file={DEST}/dnsmasq.conf")}


def resolver_unit():
    return f"""[Unit]
After=network-online.target systemd-resolved.service
Wants=network-online.target systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/resolvectl dns mgmt0 10.231.1.11 10.231.1.12
ExecStart=/usr/bin/resolvectl domain mgmt0 ~{DOMAIN}

[Install]
WantedBy=multi-user.target
""".encode()


def deploy(state, archive):
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != ETCD_SHA:
            raise RuntimeError("etcd archive SHA-256 does not match the pinned release")
    with tarfile.open(archive) as bundle:
        etcd = {f"bin/{name}": bundle.extractfile(f"{ETCD_ROOT}/{name}").read() for name in ("etcd", "etcdctl")}
    binary = (ROOT / "bin/ocean-control-plane").read_bytes()
    pki = state / "region-pki"
    pki.mkdir(mode=0o700, exist_ok=True)
    authorities = [ca(pki, name) for name in ("peer-ca", "storage-ca", "ingress-ca")]
    public = {f"pki/{cert.name}": cert.read_bytes() for cert, _ in authorities}

    def install(item):
        index, (name, address, files) = item
        eventually(lambda: ssh(state, name, "cloud-init status --wait"), 90)
        if index < 2:
            ssh(state, name, "if ! test -x /usr/sbin/haproxy || ! test -x /usr/sbin/keepalived || ! test -x /usr/sbin/dnsmasq; then "
                "sudo apt-get -qq update && sudo env DEBIAN_FRONTEND=noninteractive apt-get -yqq --no-install-recommends install haproxy keepalived dnsmasq-base; fi")
            ssh(state, name, "sudo systemctl disable --now haproxy.service keepalived.service")
        upload(state, name, files)
        ssh(state, name, f"sudo install -d -m 0700 -o ocean {DEST}/data && sudo install -m 0644 {DEST}/units/*.service /etc/systemd/system/ && sudo systemctl daemon-reload")

    images = []
    for index, (name, address) in enumerate(NODES.items()):
        files = node_files(name, address, binary, etcd, public, pki, authorities)
        if index < 2:
            files.update(gateway_files(index + 1, address, list(NODES.values())[1 - index]))
        images.append((index, (name, address, files)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(install, images))
    credential = leaf(pki, "lab-operator", authorities[1], "clientAuth")
    upload(state, OPERATOR, {"bin/etcdctl": etcd["bin/etcdctl"], "units/ocean-resolver.service": resolver_unit(), **public, **credential})
    ssh(state, OPERATOR, f"sudo install -m 0644 {DEST}/units/ocean-resolver.service /etc/systemd/system/ && sudo systemctl daemon-reload")
    for name in NODES:
        ssh(state, name, "sudo systemctl enable --now --no-block ocean-etcd.service")
    eventually(lambda: ssh(state, OPERATOR, etcdctl("endpoint health --cluster")))
    for name in NODES:
        ssh(state, name, "sudo systemctl enable --now --no-block ocean-api.service")
    for name in list(NODES)[:2]:
        ssh(state, name, "sudo systemctl enable --now --no-block ocean-gateway.service ocean-dns.service ocean-vip.service")
    ssh(state, OPERATOR, f"sudo sed -i '/{VIP} {ARM} /d' /etc/hosts && sudo systemctl enable --now ocean-resolver.service")
    eventually(lambda: ssh(state, OPERATOR, f"curl --fail --silent --show-error --max-time 3 --cacert {DEST}/pki/ingress-ca.pem https://{ARM}/readyz"))
    print(f"Regional management endpoint ready at https://{ARM}")


def etcdctl(arguments, addresses=None):
    endpoints = ",".join(f"https://{address}:2379" for address in (addresses or NODES.values()))
    return (f"{DEST}/bin/etcdctl --endpoints={endpoints} --cacert={DEST}/pki/storage-ca.pem "
            f"--cert={DEST}/pki/lab-operator.pem --key={DEST}/pki/lab-operator.key --command-timeout=2s {arguments}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--etcd-archive", type=Path, required=True)
    args = parser.parse_args()
    deploy(args.state.resolve(), args.etcd_archive)


if __name__ == "__main__":
    main()
