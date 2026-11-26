#!/usr/bin/env python3
"""Verify Chromium desktop sign-in and personal SMB access in the disposable workplace lab."""

import argparse
import base64
import contextlib
import datetime
import hashlib
import http.server
import json
import os
import secrets
import shlex
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse as urls
import urllib.request as urlrequest
from pathlib import Path
from urllib.error import HTTPError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from websocket import create_connection

import region

guest = 'farm-1-node-02'
domain_controller = 'farm-1-node-01'
file_server = 'farm-1-node-04'
realm = 'AD.OCEAN.TEST'
cifs = 'cifs/files04.ad.ocean.test@' + realm
checkpoint = 'ocean-browser-smb-' + secrets.token_hex(10)

gateway_host = 'farm-1-node-08'
user = 'smbwriter@ad.ocean.test'
machine = '9feab7c2-1302-4622-a932-729678cd61ee'
tenant = '84b678b0-0a39-47d3-a355-ff4d84de4a83'
desktop = f'/subscriptions/{tenant}/resourceGroups/workplace/providers/Ocean.Desktop/personalDesktops/personal'
subnet = f'/subscriptions/{tenant}/resourceGroups/workplace/providers/Microsoft.Network/virtualNetworks/office/subnets/personal'
nic = f'/subscriptions/{tenant}/resourceGroups/workplace/providers/Microsoft.Network/networkInterfaces/personal'
image = 'docker.io/guacamole/guacd@sha256:f39258e35244b6bf79bc6ac4e60eee176aea6f6a5adb13e8c3090e48df8ae515'
name = 'ocean-desktop-browser-' + secrets.token_hex(4)
remote_port = 48227
launch_signer = ed25519.Ed25519PrivateKey.generate()
oidc_signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bearer = secrets.token_urlsafe(32)
refresh = secrets.token_urlsafe(32)
deny = threading.Event()
renew = threading.Event()
requests = {}

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def form(query):
    return {key: values[0] for key, values in urls.parse_qs(query).items()}

def issue(expires):
    payload = struct.pack('>I', expires) + secrets.token_bytes(16)
    signed = b'ocean-desktop-launch-v1\x00' + machine.encode() + b'\x00' + user.encode() + b'\x00' + payload
    return 'ocean1.' + b64(payload + launch_signer.sign(signed))

def token(issuer, nonce):
    header = b64(json.dumps({'typ': 'JWT', 'alg': 'RS256', 'kid': 'fixture'}).encode())
    claims = b64(json.dumps({'iss': issuer, 'aud': tenant, 'sub': tenant, 'acr': 'ocean-web',
                             'nonce': nonce, 'iat': int(time.time()), 'exp': int(time.time())+120}).encode())
    message = (header + '.' + claims).encode()
    return message.decode() + '.' + b64(oidc_signer.sign(message, padding.PKCS1v15(), hashes.SHA256()))

def g(command, payload=None):
    return region.ssh(state, guest, command, payload, timeout=12)

def c(command, payload=None):
    return region.ssh(state, gateway_host, command, payload, timeout=12)

def install(path, payload, mode):
    g("set -eu; staged=$(mktemp); trap 'unlink \"$staged\"' EXIT; cat >\"$staged\"; "
      + shlex.join(['sudo', 'install', '-D', '-m', mode]) + ' "$staged" ' + shlex.quote(path), payload)

def port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]

class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, _msg, *_args):
        pass
    def send(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def do_GET(self):
        if self.path == '/.well-known/openid-configuration':
            self.send(200, {'issuer': issuer, 'authorization_endpoint': issuer + '/auth',
                            'token_endpoint': issuer + '/token', 'jwks_uri': issuer + '/jwks',
                            'id_token_signing_alg_values_supported': ['RS256']})
        elif self.path == '/jwks':
            public = oidc_signer.public_key().public_numbers()
            self.send(200, {'keys': [{'kty': 'RSA', 'kid': 'fixture', 'alg': 'RS256', 'use': 'sig',
                                      'n': b64(public.n.to_bytes(256, 'big')), 'e': 'AQAB'}]})
        elif self.path.startswith('/auth?'):
            args = form(urls.urlsplit(self.path).query)
            if args.get('client_id') != tenant or args.get('redirect_uri') != gateway + '/oauth/callback' or args.get('code_challenge_method') != 'S256' or args.get('acr_values') != 'ocean-web':
                self.send(400, {})
                return
            code = secrets.token_urlsafe(32)
            requests[code] = args
            self.send_response(302)
            self.send_header('Location', args['redirect_uri'] + '?' + urls.urlencode({'code': code, 'state': args['state'], 'iss': issuer}))
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send(404, {})
    def do_POST(self):
        if self.path == '/token':
            args = form(self.rfile.read(int(self.headers['Content-Length'])).decode())
            request = requests.pop(args.get('code'), None)
            if args.get('client_id') != tenant:
                self.send(401, {})
            elif args.get('grant_type') == 'refresh_token' and args.get('refresh_token') == refresh:
                renew.set()
                self.send(200, {'access_token': bearer, 'refresh_token': refresh, 'token_type': 'Bearer', 'expires_in': 120})
            elif (request and args.get('redirect_uri') == gateway + '/oauth/callback' and
                  b64(hashlib.sha256(args.get('code_verifier', '').encode()).digest()) == request['code_challenge']):
                self.send(200, {'access_token': bearer, 'refresh_token': refresh, 'token_type': 'Bearer', 'expires_in': 19,
                                'id_token': token(issuer, request['nonce'])})
            else:
                self.send(401, {})
            return
        path = urls.urlsplit(self.path).path
        if self.headers.get('Authorization') != 'Bearer ' + bearer or self.connection.getpeercert(binary_form=True) != host_cert:
            self.send(403, {})
            return
        expires = int(time.time()) + 12
        response = {'assignmentId': tenant, 'machineId': machine, 'generation': tenant, 'user': user, 'privateIp': '10.232.1.12',
                    'networkInterfaceId': nic, 'subnetId': subnet,
                    'expiresAt': datetime.datetime.fromtimestamp(expires, datetime.timezone.utc).isoformat()}
        if path == desktop + '/launch':
            response['credential'] = issue(expires)
            self.send(200, response)
        elif path == desktop + '/renew':
            self.send(403 if deny.is_set() else 200, {} if deny.is_set() else response)
        else:
            self.send(404, {})

def wait(check, timeout=16):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(0.15)
    raise RuntimeError('fixture timed out: ' + check.__name__)

def serve(server, context):
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return 'https://127.0.0.1:' + str(server.server_port)

def forward_port(node_name, flag, spec):
    machines = json.loads(region.run([Path('bin/ocean-lab').absolute(), 'status', '-state', state]))
    node = next(entry for entry in machines if entry['guest']['name'] == node_name)
    return subprocess.Popen(['ssh', '-N', '-p', str(node['sshPort']), '-i', str(state / 'ssh-key'), '-o', 'IdentitiesOnly=yes',
                             '-o', 'StrictHostKeyChecking=yes', '-o', f'HostKeyAlias={node_name}', '-o', f'UserKnownHostsFile={state / "known-hosts"}',
                             '-o', 'ExitOnForwardFailure=yes', flag, spec, 'ocean@127.0.0.1'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def close_process(proc):
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)

def dc(command):
    return region.ssh(state, domain_controller, command, timeout=20)

def pem_leaf(ca, signer, name, key, now):
    cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca.subject)
    cert = cert.public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
    return cert.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False).sign(signer, hashes.SHA256())

def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def stop_container(container):
    subprocess.run(['podman', 'stop', '--time', '2', container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start_real_broker(work, cleanup, ca, signer, cert_path, key_path, now):
    local_kdc = port()
    host_port, guest_port = port(), port()
    to_kdc = forward_port(domain_controller, '-L', f'127.0.0.1:{local_kdc}:10.232.1.11:88')
    to_guest = forward_port(guest, '-R', f'127.0.0.1:{guest_port}:127.0.0.1:{host_port}')
    cleanup.callback(close_process, to_kdc)
    cleanup.callback(close_process, to_guest)
    account = 'smbdesk' + secrets.token_hex(5)
    dc(shlex.join(['sudo', 'samba-tool', 'user', 'create', account, '--random-password']))
    cleanup.callback(dc, shlex.join(['sudo', 'samba-tool', 'user', 'delete', account]))
    dc(shlex.join(['sudo', 'samba-tool', 'spn', 'add', 'HTTP/'+account+'.ad.ocean.test', account]))
    dc(shlex.join(['sudo', 'samba-tool', 'delegation', 'for-any-protocol', account, 'on']))
    dc(shlex.join(['sudo', 'samba-tool', 'delegation', 'add-service', account, cifs.split('@')[0]]))
    extract = """set -eu
umask 077
private=$(mktemp -d /run/ocean-desktop-export.XXXXXX)
trap 'find "$private" -mindepth 1 -delete; rmdir "$private"' EXIT
samba-tool domain exportkeytab "$private/broker" --principal "$1" --only-current-keys >&2
cat "$private/broker"
"""
    (work/'broker.keytab').write_bytes(dc(shlex.join(['sudo', 'sh', '-c', extract, 'sh', account + '@' + realm])))
    (work/'broker.keytab').chmod(0o600)
    (work/'krb5.conf').write_text(f"""[libdefaults]
default_realm = {realm}
dns_lookup_kdc = false
dns_uri_lookup = false
udp_preference_limit = 1
[realms]
{realm} = {{
    kdc = 127.0.0.1:{local_kdc}
}}
""")
    (work/'krb5.conf').chmod(0o600)
    (work/'launch.seed').write_bytes(launch_signer.private_bytes_raw())
    (work/'launch.seed').chmod(0o600)
    guest_key = ed25519.Ed25519PrivateKey.generate()
    guest_cert = pem_leaf(ca, signer, 'desktop-fixture', guest_key, now)
    guest_pem = guest_cert.public_bytes(serialization.Encoding.PEM)
    guest_fingerprint = guest_cert.fingerprint(hashes.SHA256()).hex()
    (work/'guest.pem').write_bytes(guest_pem)
    (work/'guest.key').write_bytes(key_pem(guest_key))
    (work/'guest.key').chmod(0o600)
    guest_ca = '/etc/ocean-desktop/kerberos-ca.pem'
    guest_identity = '/etc/ocean-desktop/kerberos-guest.pem'
    guest_secret = '/etc/ocean-desktop/kerberos-guest.key'
    for file, data in [(guest_ca, cert_path.read_bytes()), (guest_identity, guest_pem), (guest_secret, key_pem(guest_key))]:
        install(file, data, '0600')
        cleanup.callback(g, 'sudo unlink '+file)
    host_origin = 'https://127.0.0.1:'+str(host_port)
    guest_origin = 'https://127.0.0.1:'+str(guest_port)
    broker_cfg = {'origin': guest_origin, 'listen': '127.0.0.1:'+str(host_port),
          'etcd': etcd, 'namespace': name, 'doneFile': '/fixture/broker.done',
          'tls': {'certificateFile': '/fixture/tls.pem', 'keyFile': '/fixture/tls.key', 'clientCAFile': '/fixture/tls.pem'},
          'smb': {'tenantId': tenant, 'subscriptionId': tenant, 'member': {'dnsDomain': 'ad.ocean.test', 'serverName': 'FILES04'}},
          'launch': {'signingKeyFile': '/fixture/launch.seed', 'gateways': ['gateway-a','gateway-b'],
                     'smbBrokers': [{'tenantId': tenant, 'subscriptionId': tenant, 'account': account,
                                     'keytabFile': '/fixture/broker.keytab', 'kerberosConfigFile': '/fixture/krb5.conf',
                                     'guests': [{'machineId': machine, 'certificateSha256': guest_fingerprint}]}]}}
    binary = work / 'desktop-kerberos-lab.test'
    subprocess.run(['go', 'test', '-mod=readonly', '-tags=e2e', '-c', '-o', str(binary), './internal/controlplane'],
                   env={**os.environ, 'CGO_ENABLED': '0'}, check=True, timeout=60)

    def start_replica(replica, address):
        config_path = work / f'broker-{replica}.json'
        config_path.write_text(json.dumps(broker_cfg | {'listen': address}))
        container = f'{name}-broker-{replica}'
        log_path = report / f'desktop-smb-broker-{replica}.log'
        log = cleanup.enter_context(log_path.open('wb'))
        server = subprocess.Popen(['nice', '-n', '10', 'podman', 'run', '--pull=never', '--rm', '--name', container,
                                   '--network=host', '-v', f'{work}:/fixture:ro',
                                   '-e', f'OCEAN_E2E_DESKTOP_KERBEROS_SERVICE=/fixture/{config_path.name}',
                                   '--entrypoint', '/usr/bin/nice', broker_image, '-n', '10',
                                   '/fixture/desktop-kerberos-lab.test', '-test.v',
                                   '-test.run', '^TestDesktopKerberosLabService$'], stdout=log, stderr=log)
        cleanup.callback(stop_container, container)

        def ready():
            if server.poll() is not None:
                raise RuntimeError(f'The desktop broker replica {replica} stopped. See {log_path}.')
            return 'endpoint ready' in log_path.read_text()
        wait(ready, 12)
        return server

    second_port = port()
    servers = [start_replica('a', f'127.0.0.1:{host_port}'), start_replica('b', f'127.0.0.1:{second_port}')]
    # The guest origin is preserved through the test port forward.
    guest_context = ssl.create_default_context(cafile=cert_path)
    guest_context.load_cert_chain(work/'guest.pem',work/'guest.key')
    anonymous = ssl.create_default_context(cafile=cert_path)
    check_origin = host_origin
    # For a local direct request, use the same HTTP Host checked by ARM.
    def request_with_host(trust, request_user, credential, origin=check_origin):
        body = json.dumps({'user':request_user,'credential':base64.b64encode(credential.encode()).decode()}).encode()
        request = urlrequest.Request(origin+'/ocean/desktops/kerberos',data=body,
                         headers={'Content-Type':'application/json','Host':guest_origin.removeprefix('https://')})
        try:
            with urlrequest.urlopen(request,context=trust,timeout=15) as reply:
                return reply.status,len(reply.read())
        except HTTPError as error:
            return error.code,0
    credential = issue(int(time.time()) + 14)
    if request_with_host(anonymous, user, credential)[0] != 403:
        raise RuntimeError('The broker accepted a request without a guest certificate.')
    other_key = ed25519.Ed25519PrivateKey.generate()
    other_cert = pem_leaf(ca, signer, 'other-fixture-guest', other_key, now)
    (work/'other.pem').write_bytes(other_cert.public_bytes(serialization.Encoding.PEM))
    (work/'other.key').write_bytes(key_pem(other_key))
    (work/'other.key').chmod(0o600)
    other_context = ssl.create_default_context(cafile=cert_path)
    other_context.load_cert_chain(work/'other.pem',work/'other.key')
    if request_with_host(other_context, user, credential)[0] != 403:
        raise RuntimeError('The broker accepted an unregistered certificate from the same CA.')
    if request_with_host(guest_context, 'smbreader@ad.ocean.test', credential)[0] != 403:
        raise RuntimeError('The broker accepted a request for a different user.')
    status, size = request_with_host(guest_context, user, credential)
    if status != 200 or size == 0:
        raise RuntimeError(f'The valid ticket could not obtain a service cache. Status {status}.')
    if request_with_host(guest_context, user, credential)[0] != 403:
        raise RuntimeError('The issuing broker accepted a replay.')
    replica = f'https://127.0.0.1:{second_port}'
    if request_with_host(guest_context, user, credential, replica)[0] != 403:
        raise RuntimeError('The second replica accepted a ticket redeemed through the first.')
    fresh_status, fresh_cache_size = request_with_host(guest_context, user, issue(int(time.time()) + 14), replica)
    if fresh_status != 200 or fresh_cache_size == 0:
        raise RuntimeError('The second replica could not issue a service ticket.')
    (report / 'desktop-smb-broker-security.tsv').write_text(
        'case\tresult\nmissing-certificate\tPASS\nother-certificate\tPASS\nwrong-account\tPASS\n'
        'valid-single-service-cache\tPASS\nregional-replay\tPASS\nreplica-replay\tPASS\nsecond-replica-issuance\tPASS\n')
    return {'region': guest_origin, 'caFile': guest_ca, 'certificateFile': guest_identity,
            'keyFile': guest_secret, 'service': cifs}, servers

def prepare_user_probe(cleanup):
    probe_id = checkpoint
    home = '/home/' + user
    bootstrap = home+'/.xsession'
    result = home+'/.local/state/'+probe_id
    original_user = g('sudo cat '+shlex.quote(bootstrap))
    def write_user(data):
        g(shlex.join(['sudo','-u',user,'tee',bootstrap])+' >/dev/null',data)
    cleanup.callback(g, 'sudo -u '+shlex.quote(user)+' python3 -c '+shlex.quote(
        f'import shutil; shutil.rmtree({result!r}, ignore_errors=True)'))
    cleanup.callback(write_user, original_user)
    # Replace only the fixture account's sessions left by earlier probes.
    g('sudo pkill -TERM -u '+shlex.quote(user)+' -x openbox || true')
    write_user(f"""#!/bin/sh
umask 077
probe={shlex.quote(result)}
mkdir -p "$probe"
printf '%s' '{probe_id}' >"$probe/source"
id -un >"$probe/account"
printf '%s
' "$KRB5CCNAME" >"$probe/cache-name"
LC_ALL=C TZ=UTC klist >"$probe/klist" 2>&1
if timeout 12 smbclient //files04.ad.ocean.test/company-files --use-kerberos=required --client-protection=encrypt \
    -c "put $probe/source {probe_id}; get {probe_id} $probe/readback; del {probe_id}" >"$probe/smb" 2>&1 && cmp "$probe/source" "$probe/readback"; then
    echo PASS >"$probe/result"
else
    echo FAIL >"$probe/result"
fi
exec openbox-session
""".encode())
    return result
def main():
    global state, report, script, broker_image, etcd, host_cert, issuer, gateway
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--guacamole-js', required=True, type=Path)
    parser.add_argument('--samba-image', required=True)
    parser.add_argument('--etcd', required=True)
    args = parser.parse_args()
    endpoint = urls.urlsplit(args.etcd)
    if (endpoint.scheme != 'http' or endpoint.hostname != '127.0.0.1' or not endpoint.port or
            endpoint.username is not None or endpoint.path or endpoint.query or endpoint.fragment):
        parser.error('Provide a disposable loopback etcd endpoint.')
    state, script, broker_image, etcd = args.state.resolve(), args.guacamole_js.resolve(), args.samba_image, args.etcd
    if hashlib.sha256(script.read_bytes()).hexdigest() != 'cc89f710ecc544477dbe6bfea453fab752dafa1b1ab9770f523676e7b744b44a':
        parser.error('Use guacamole-common-js/all.min.js from the verified Apache Guacamole 1.6.0 WAR.')
    os.chdir(region.ROOT)
    report = state / 'evidence'
    report.mkdir(mode=0o700, exist_ok=True)
    stage = '/etc/pam.d/xrdp-sesman'
    helper = '/usr/libexec/ocean/ocean-desktop-guest'
    configuration = '/etc/ocean-desktop/guest.json'
    original = g('sudo -n cat ' + stage)
    if b'ocean-desktop-guest' in original or original.count(b'@include common-auth') != 1:
        raise RuntimeError('unexpected PAM stack')
    g('test ! -e ' + helper + ' && test ! -e ' + configuration + ' && test ! -e /var/lib/ocean-desktop/replay')
    changed = False
    started = False
    with tempfile.TemporaryDirectory(prefix='ocean-desktop-browser.') as work, contextlib.ExitStack() as cleanup:
        try:
            work = Path(work)
            cert_path, key_path = work / 'tls.pem', work / 'tls.key'
            subprocess.run(['openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '1',
                            '-subj', '/CN=Ocean browser fixture', '-addext', 'subjectAltName=IP:127.0.0.1',
                            '-addext', 'basicConstraints=critical,CA:TRUE', '-out', str(cert_path), '-keyout', str(key_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ca = x509.load_pem_x509_certificate(cert_path.read_bytes())
            ca_key = serialization.load_pem_private_key(key_path.read_bytes(), None)
            key = ed25519.Ed25519PrivateKey.generate()
            now = datetime.datetime.now(datetime.timezone.utc)
            leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gateway-fixture')])).issuer_name(ca.subject)
            leaf = leaf.public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
            leaf = leaf.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False).sign(ca_key, hashes.SHA256())
            host_cert = leaf.public_bytes(serialization.Encoding.DER)
            (work / 'identity.crt').write_bytes(host_cert)
            (work / 'identity.key').write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            for file in ['identity.crt', 'identity.key']:
                (work / file).chmod(0o600)
            identity_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            identity_context.load_cert_chain(cert_path, key_path)
            region_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            region_context.load_cert_chain(cert_path, key_path)
            region_context.load_verify_locations(cert_path)
            region_context.verify_mode = ssl.CERT_REQUIRED
            identity_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
            arm_server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
            issuer = serve(identity_server, identity_context)
            regional = serve(arm_server, region_context)
            cleanup.callback(identity_server.shutdown)
            cleanup.callback(arm_server.shutdown)
            gateway_port = port()
            gateway = 'https://127.0.0.1:' + str(gateway_port)
            broker, broker_processes = start_real_broker(work, cleanup, ca, ca_key, cert_path, key_path, now)
            session_script = '/etc/X11/Xsession.d/60-ocean-desktop-cifs'
            g('test ! -e '+session_script+' && test ! -e /run/ocean-desktop-cifs')
            cleanup.callback(g, 'sudo unlink '+session_script)
            install(session_script, Path('packaging/debian/60-ocean-desktop-cifs').read_bytes(), '0644')
            probe_result = prepare_user_probe(cleanup)
            settings = json.dumps({'machineId': machine, 'publicKey': base64.b64encode(launch_signer.public_key().public_bytes_raw()).decode(),
                                   'kerberos': broker}).encode()
            install(helper, Path('bin/ocean-desktop-guest').read_bytes(), '0755')
            install(configuration, settings, '0600')
            g('sudo install -d -m0700 /var/lib/ocean-desktop/replay')
            snippet = Path('packaging/debian/ocean-desktop-pam').read_bytes()
            install(stage, original.replace(b'@include common-auth', snippet + b'@include common-auth'), '0644')
            changed = True
            g('sudo systemctl start xrdp-sesman xrdp')
            pin = g('sudo openssl x509 -in /etc/xrdp/cert.pem -noout -fingerprint -sha256').decode().strip().split('=', 1)[1]
            c(shlex.join(['nice', '-n', '10', 'podman', 'run', '--pull=never', '--rm', '-d', '--name', name,
                          '--publish', f'127.0.0.1:{remote_port}:4822', '--entrypoint', '/bin/sh', image, '-ec', 'exec nice -n 10 /opt/guacamole/entrypoint.sh']))
            started = True
            mapped = port()
            forward = forward_port(gateway_host, '-L', f'127.0.0.1:{mapped}:127.0.0.1:{remote_port}')
            cleanup.callback(close_process, forward)
            host_cfg = work / 'host.json'
            host_cfg.write_text(json.dumps({'enrollment': {'origin': regional, 'hostId': 'gateway-fixture', 'managementInterface': 'lo',
                                                             'stateDirectory': str(work), 'caFile': str(cert_path), 'tokenFile': str(work / 'unused')}}))
            config = work / 'gateway.json'
            config.write_text(json.dumps({'listenAddress': f'127.0.0.1:{gateway_port}', 'tls': {'certificateFile': str(cert_path), 'keyFile': str(key_path)},
                                          'publicOrigin': gateway, 'hostConfigFile': str(host_cfg), 'identity': {'issuer': issuer, 'caFile': str(cert_path), 'clientId': tenant},
                                          'guacamoleScriptFile': str(script), 'guacamoleScriptSha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                                          'desktops': {'personal': {'desktopId': desktop, 'subnetId': subnet, 'fingerprint': pin, 'guacd': f'127.0.0.1:{mapped}'}}}))
            gateway_log = cleanup.enter_context((report / 'desktop-smb-gateway.log').open('wb'))
            server = subprocess.Popen(['bin/ocean-desktop-gateway', '-config', str(config)], stdout=gateway_log, stderr=gateway_log)
            cleanup.callback(close_process, server)
            trust = ssl.create_default_context(cafile=cert_path)
            def healthy():
                try:
                    with urlrequest.urlopen(gateway + '/readyz', context=trust, timeout=2) as reply:
                        return reply.status == 204
                except OSError:
                    return False
            wait(healthy, 15)
            pub = ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            spki = base64.b64encode(hashlib.sha256(pub).digest()).decode()
            profile = work / 'chromium'
            chrome_log = cleanup.enter_context((report / 'desktop-smb-chromium.log').open('wb'))
            chrome = subprocess.Popen(['chromium', '--headless', '--disable-dev-shm-usage', '--no-first-run', '--remote-debugging-port=0',
                                       '--remote-debugging-address=127.0.0.1', '--user-data-dir=' + str(profile), '--ignore-certificate-errors-spki-list=' + spki, 'about:blank'],
                                      stdout=chrome_log, stderr=chrome_log)
            cleanup.callback(close_process, chrome)
            active = profile / 'DevToolsActivePort'
            wait(active.exists, 12)
            with urlrequest.urlopen('http://127.0.0.1:' + active.read_text().splitlines()[0] + '/json/list', timeout=3) as reply:
                endpoint = next(page['webSocketDebuggerUrl'] for page in json.load(reply) if page['type'] == 'page')
            cdp = create_connection(endpoint, suppress_origin=True, timeout=5)
            cleanup.callback(cdp.close)
            msgid = 0
            def command(method, params):
                nonlocal msgid
                msgid += 1
                cdp.send(json.dumps({'id': msgid, 'method': method, 'params': params}))
                while True:
                    result = json.loads(cdp.recv())
                    if result.get('id') == msgid:
                        return result.get('result', {})
            def browser_state():
                expression = '({status: document.querySelector("#status")?.textContent, canvas: document.querySelectorAll("canvas").length, path: location.pathname, text: document.body?.innerText?.slice(0, 120)})'
                return command('Runtime.evaluate', {'expression': expression, 'returnByValue': True}).get('result', {}).get('value', {})
            before = int(g('sudo wc -l /var/log/xrdp-sesman.log').split()[0])
            command('Page.navigate', {'url': gateway + '/d/personal'})
            def drawn():
                result = browser_state()
                (report / 'desktop-smb-browser-state.json').write_text(json.dumps(result))
                return result.get('status') == 'Desktop connected' and result.get('canvas', 0) > 0
            wait(drawn, 18)
            def authenticated_guest():
                guest_log = g(f'sudo tail -n +{before + 1} /var/log/xrdp-sesman.log').decode()
                (report / 'desktop-smb-xrdp.log').write_text(guest_log)
                return 'Access permitted' in guest_log and renew.is_set()
            wait(authenticated_guest, 10)
            def read_smb_result():
                raw = g('sudo cat '+shlex.quote(probe_result+'/result')+' 2>/dev/null || true').decode().strip()
                return raw == 'PASS'
            try:
                wait(read_smb_result, 20)
            finally:
                evidence = g(shlex.join(['sudo','cat']+[probe_result+'/'+name for name in ('account','cache-name','klist','smb','result')])+' 2>/dev/null || true').decode()
                (report/'desktop-smb-session.log').write_text(evidence)
            audit = region.ssh(state, file_server, "sudo journalctl -t smbd_audit --since '-3 minutes' --no-pager -o cat").decode()
            matches = [line for line in audit.splitlines() if checkpoint in line and '|smbwriter|10.232.1.12|company-files|' in line]
            if not any('|create_file|ok|' in line for line in matches):
                raise RuntimeError('the file server did not audit the browser login user')
            (report/'desktop-smb-audit.log').write_text('\n'.join(matches)+'\n')
            uid = g(shlex.join(['id', '-u', user])).decode().strip()
            cache_path = '/run/ocean-desktop-cifs/' + uid
            permissions = g(shlex.join(['sudo', 'stat', '-c', '%a %u', cache_path])).decode().strip()
            if permissions != f'600 {uid}':
                raise RuntimeError('the CIFS cache was not private to the desktop account')
            g(shlex.join(['sudo', '-u', 'smbreader@ad.ocean.test', 'test', '!', '-r', cache_path]))
            started_at = time.monotonic()
            deny.set()
            def revoked():
                return browser_state().get('status') == 'Desktop disconnected'
            wait(revoked, 15)
            ms = round((time.monotonic() - started_at)*1000)
            (report / 'desktop-smb-browser.tsv').write_text('case\tresult\tduration_ms\nchromium-oidc-to-real-xrdp\tPASS\t\nchromium-open-tunnel-revocation\tPASS\t' + str(ms) + '\n')
            (report/'desktop-smb-results.tsv').write_text('case\tresult\nkerberos-broker-and-guest\tPASS\napplication-session-to-encrypted-share\tPASS\npersonal-samba-audit\tPASS\ncache-uid-isolation\tPASS\n')
            (work/'broker.done').write_text('done')
            if any(process.wait(10) != 0 for process in broker_processes):
                raise RuntimeError('the regional broker fixture did not shut down cleanly')
            print('Chromium opened the Debian desktop and its personal encrypted SMB share, then disconnected after revocation in', ms, 'ms')
        finally:
            if started:
                c(shlex.join(['podman', 'stop', '--time', '2', name]))
            if changed:
                install(stage, original, '0644')
            g('sudo systemctl stop xrdp xrdp-sesman; sudo python3 -c ' +
              shlex.quote('import shutil, pathlib; shutil.rmtree("/var/lib/ocean-desktop/replay", ignore_errors=True); ' +
                          f'pathlib.Path({helper!r}).unlink(missing_ok=True); pathlib.Path({configuration!r}).unlink(missing_ok=True); shutil.rmtree("/run/ocean-desktop-cifs", ignore_errors=True)'))


if __name__ == '__main__':
    main()
