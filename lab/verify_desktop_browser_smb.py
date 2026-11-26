#!/usr/bin/env python3
"""Verify Chromium desktop sign-in and personal SMB access in the disposable workplace lab."""

import argparse
import base64
import contextlib
import datetime
import hashlib
import hmac
import http.server
import io
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.parse as urls
import urllib.request as urlrequest
import uuid
from pathlib import Path
from urllib.error import HTTPError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
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
standby_gateway_host = 'farm-1-node-07'
gateway_observer = 'farm-1-node-05'
gateway_vip = '10.231.1.210'
user = 'smbwriter@ad.ocean.test'
machine = '9feab7c2-1302-4622-a932-729678cd61ee'
tenant = '84b678b0-0a39-47d3-a355-ff4d84de4a83'
subscription = tenant
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

def forward_port(node_name, flag, spec, *extra):
    machines = json.loads(region.run([Path('bin/ocean-lab').absolute(), 'status', '-state', state]))
    node = next(entry for entry in machines if entry['guest']['name'] == node_name)
    return subprocess.Popen(['ssh', '-N', '-p', str(node['sshPort']), '-i', str(state / 'ssh-key'), '-o', 'IdentitiesOnly=yes',
                             '-o', 'StrictHostKeyChecking=yes', '-o', f'HostKeyAlias={node_name}', '-o', f'UserKnownHostsFile={state / "known-hosts"}',
                             '-o', 'ExitOnForwardFailure=yes', flag, spec, *extra, 'ocean@127.0.0.1'],
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


def directory_field(command, field):
    prefix = field + ': '
    data = dc(shlex.join(['sudo', 'samba-tool', *command])).decode()
    return next(line[len(prefix):] for line in data.splitlines() if line.startswith(prefix))


def private_fixture_file(path):
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError(f'The fixture needs a private regular file at {path}.')
    return path.read_bytes().strip()


def prepare_live_keycloak(work, cleanup, origin, ca, signer, deployment_ca, now):
    source = urls.urlsplit(live_args.keycloak_origin)
    if source.scheme != 'https' or source.hostname != '127.0.0.1' or not source.port or source.path:
        raise RuntimeError('Use a disposable Keycloak HTTPS origin on loopback.')
    admin_port = port()
    admin = subprocess.Popen(['socat', f'TCP-LISTEN:{admin_port},bind=127.0.0.1,reuseaddr,fork',
                              f'TCP:127.0.0.1:{source.port}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    cleanup.callback(close_process, admin)
    connector_ports = [port(), port()]
    for node, address, endpoint in zip((domain_controller, 'farm-1-node-03'), ('10.232.1.11', '10.232.1.13'), connector_ports):
        connect = forward_port(node, '-L', f'127.0.0.1:{endpoint}:{address}:636')
        cleanup.callback(close_process, connect)

    group = 'OceanDesktop' + secrets.token_hex(5)
    dc(shlex.join(['sudo', 'samba-tool', 'group', 'add', group, '--groupou=OU=Ocean Workforce Groups']))
    cleanup.callback(dc, shlex.join(['sudo', 'samba-tool', 'group', 'delete', group]))
    dc(shlex.join(['sudo', 'samba-tool', 'group', 'addmembers', group, 'smbwriter']))
    group_id = directory_field(['group', 'show', group], 'objectGUID')
    user_id = directory_field(['user', 'show', 'smbwriter'], 'objectGUID')
    directory_id = str(uuid.uuid4())
    otp = secrets.token_bytes(20)
    writer_key = ed25519.Ed25519PrivateKey.generate()
    writer_cert = pem_leaf(ca, signer, 'desktop-lab-writer', writer_key, now)
    (work / 'writer.der').write_bytes(writer_cert.public_bytes(serialization.Encoding.DER))
    (work / 'writer.pem').write_bytes(writer_cert.public_bytes(serialization.Encoding.PEM))
    (work / 'writer.key').write_bytes(key_pem(writer_key))
    (work / 'provider.pem').write_bytes(live_args.keycloak_ca.read_bytes())
    secrets_by_name = {'admin.secret': private_fixture_file(live_args.keycloak_secret),
                       'ldap.secret': private_fixture_file(live_args.ldap_reader),
                       'identity.seed': secrets.token_hex(32).encode(),
                       'workload.key': secrets.token_bytes(32), 'writer.key': key_pem(writer_key)}
    for name, value in secrets_by_name.items():
        file = work / name
        file.write_bytes(value)
        file.chmod(0o600)
    sid = live_args.domain_sid.read_text().strip()
    cfg = {
        'identity': {'authority': origin, 'provider': live_args.keycloak_origin,
                     'providerCAFile': '/fixture/provider.pem',
                     'onboarding': {'operatorTenant': str(uuid.uuid4()), 'operatorClient': str(uuid.uuid4()),
                                    'adminEndpoints': [f'https://127.0.0.1:{admin_port}'],
                                    'adminClient': live_args.keycloak_client,
                                    'adminSecretFile': '/fixture/admin.secret', 'regionalKeyFile': '/fixture/identity.seed',
                                    'webDirectories': {tenant: {'directoryId': directory_id, 'domainSid': sid,
                                                                'connectors': [f'ldaps://127.0.0.1:{p}' for p in connector_ports],
                                                                'readerSecretFile': '/fixture/ldap.secret',
                                                                'desktopApplicationId': live_args.application}}},
                     'cloud': {'resourceManager': origin, 'microsoftGraph': 'https://graph.desktop.test'}},
        'registration': {'tenantId': tenant, 'subscriptionId': subscription, 'administratorId': str(uuid.uuid4()),
                         'fingerprint': name},
        'workloadKey': '/fixture/workload.key',
        'directoryId': directory_id,
        'domainSid': sid,
        'machineId': machine,
        'userId': user_id,
        'gatewayDer': '/fixture/identity.crt',
        'writerDer': '/fixture/writer.der',
        'writerGeneration': str(uuid.uuid4()),
        'application': {'ApplicationID': live_args.application, 'ClientID': live_args.client_id,
                        'Callback': gateway + '/oauth/callback', 'GroupID': group_id, 'User': user,
                        'OTPSecret': base64.b32encode(otp).decode()},
    }
    if live_args.gateway_failover:
        cfg['standbyDer'] = '/fixture/standby.crt'
    if live_args.native_other_password:
        cfg['nativeRdp'] = True
    return cfg, (group, otp, deployment_ca)


def start_live_graph_worker(work, cleanup, origin, result):
    _, _, tls_ca = result
    trust = ssl.create_default_context(cafile=tls_ca)
    trust.load_cert_chain(work / 'writer.pem', work / 'writer.key')
    directory = dc('sudo mktemp -d /run/ocean-desktop-graph.XXXXXXXX').decode().strip()
    cleanup.callback(dc, 'sudo python3 -c ' + shlex.quote(f'import shutil; shutil.rmtree({directory!r})'))
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as files:
        for name in ('directory_graph.py', 'directory_groups.py', 'directory_users.py', 'domain_join.py'):
            files.add(region.ROOT / 'packaging/samba' / name, arcname=name)
    region.ssh(state, domain_controller, shlex.join(['sudo', 'tar', '-xf', '-', '-C', directory]), archive.getvalue())
    program = """import json,sys
sys.path.insert(0, sys.argv[1])
from directory_graph import run
from domain_join import open_directory
from io import StringIO
raw = sys.stdin.read()
answer = run(open_directory('/etc/samba/smb.conf'), 'ad.ocean.test', StringIO(raw))
answer['id'] = json.loads(raw)['id']
print(json.dumps(answer))
"""
    command = shlex.join(['sudo', '/usr/bin/python3', '-c', program, directory])
    stop = threading.Event()

    def request(path, method, body=None):
        with urlrequest.urlopen(urlrequest.Request(origin + '/fixture/writer/' + path, method=method, data=body,
                                  headers={'Content-Type': 'application/json'}), context=trust, timeout=4) as reply:
            return reply.read() if reply.status == 200 else None

    request('health', 'POST', b'')

    def poll():
        last_health = time.monotonic()
        try:
            while not stop.wait(0.15):
                if time.monotonic() - last_health >= 10:
                    request('health', 'POST', b'')
                    last_health = time.monotonic()
                task = request('graph', 'GET')
                if task is not None:
                    response = region.ssh(state, domain_controller, command, task, timeout=6)
                    request('graph', 'POST', response)
        except (RuntimeError, OSError) as error:
            if not stop.is_set():
                (report / 'desktop-smb-writer-error.log').write_text(type(error).__name__ + '\n')

    worker = threading.Thread(target=poll, daemon=True)
    worker.start()
    cleanup.callback(lambda: (stop.set(), worker.join(10)))
    return stop

def start_real_broker(work, cleanup, ca, signer, cert_path, key_path, now):
    local_kdc = port()
    host_port = guest_port = port()
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
          'smb': {'tenantId': tenant, 'subscriptionId': subscription, 'member': {'dnsDomain': 'ad.ocean.test', 'serverName': 'FILES04'}},
          'launch': {'signingKeyFile': '/fixture/launch.seed', 'gateways': ['gateway-fixture','gateway-b'],
                     'smbBrokers': [{'tenantId': tenant, 'subscriptionId': subscription, 'account': account,
                                     'keytabFile': '/fixture/broker.keytab', 'kerberosConfigFile': '/fixture/krb5.conf',
                                     'guests': [{'machineId': machine, 'certificateSha256': guest_fingerprint}]}]}}
    binary = work / 'desktop-kerberos-lab.test'
    subprocess.run(['go', 'test', '-mod=readonly', '-tags=e2e', '-c', '-o', str(binary), './internal/controlplane'],
                   env={**os.environ, 'CGO_ENABLED': '0'}, check=True, timeout=60)

    configured = None
    if live_args:
        configured, real = prepare_live_keycloak(work, cleanup, host_origin, ca, signer, cert_path, now)
        if live_args.native_other_password:
            broker_cfg['launch']['nativeGuests'] = [{'tenantId': tenant, 'subscriptionId': subscription,
                'desktopId': desktop, 'machineId': machine, 'certificateSha256': guest_fingerprint}]

    def start_replica(replica, address, identity=None):
        config_path = work / f'broker-{replica}.json'
        settings = broker_cfg | {'listen': address, 'cleanup': replica == 'a'}
        if identity is not None:
            settings['browser'] = identity
        config_path.write_text(json.dumps(settings))
        config_path.chmod(0o600)
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
        wait(ready, 45)
        return server

    second_port = port()
    servers = [start_replica('a', f'127.0.0.1:{host_port}', configured), start_replica('b', f'127.0.0.1:{second_port}')]
    worker = start_live_graph_worker(work, cleanup, host_origin, real) if configured else None
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
            'keyFile': guest_secret, 'service': cifs}, servers, host_origin, (real[0], real[1], worker) if configured else None

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
    stop_session = shlex.join(['sudo', 'pkill', '-TERM', '-u', user, '-x', 'openbox|Xorg']) + ' || true'
    g(stop_session)
    cleanup.callback(g, stop_session)
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
def finish_live_login(command, otp_secret):
    def evaluate(expression):
        result = command('Runtime.evaluate', {'expression': expression, 'returnByValue': True})
        return result.get('result', {}).get('value')

    def submit(selector, fields):
        found = evaluate(f"""(() => {{
            if (location.origin !== {json.dumps(live_args.keycloak_origin)} ||
                !location.href.startsWith({json.dumps(issuer + '/')})) return false;
            const form = document.querySelector({json.dumps(selector)});
            if (!form || new URL(form.action).origin !== location.origin) return false;
            for (const [name, value] of Object.entries({json.dumps(fields)})) {{
                const field = form.elements.namedItem(name);
                if (!field) return false;
                field.value = value;
            }}
            form.requestSubmit();
            return true;
        }})()""")
        return found is True

    password = private_fixture_file(live_args.browser_password).decode()
    wait(lambda: submit('#kc-form-login', {'username': user, 'password': password}), 15)

    def submit_otp():
        now = int(time.time())
        if now % 30 > 27:
            return False
        digest = hmac.digest(otp_secret, struct.pack('>Q', now // 30), 'sha1')
        number = int.from_bytes(digest[digest[-1] & 15:][:4], 'big') & 0x7fffffff
        return submit('#kc-otp-login-form', {'otp': f'{number % 1000000:06d}'})

    wait(submit_otp, 15)


def gateway_configuration(listen, directory, certificate, filename, web_client, pin, guacd_port):
    return {
        'listenAddress': listen,
        'tls': {'certificateFile': str(directory / certificate), 'keyFile': str(directory / filename)},
        'publicOrigin': gateway,
        'hostConfigFile': str(directory / 'host.json'),
        'identity': {'issuer': issuer, 'caFile': str(directory / 'provider.pem'), 'clientId': web_client},
        'guacamoleScriptFile': str(directory / 'guacamole.min.js'),
        'guacamoleScriptSha256': hashlib.sha256(script.read_bytes()).hexdigest(),
        'desktops': {'personal': {'desktopId': desktop, 'subnetId': subnet, 'fingerprint': pin,
                                  'guacd': f'127.0.0.1:{guacd_port}'}},
    }


def verify_native_rdp(cleanup, pin, enable_native):
    reader = 'smbreader@ad.ocean.test'
    authorized = private_fixture_file(live_args.browser_password) + b'\n'
    unassigned = private_fixture_file(live_args.native_other_password) + b'\n'
    settings = '/etc/xrdp/sesman.ini'
    original = g('sudo cat ' + settings)
    changed, count = re.subn(rb'(?m)^TerminalServerUsers=.*$', b'TerminalServerUsers=domain users@ad.ocean.test', original)
    if count != 1 or b'AlwaysGroupCheck=true' not in original:
        raise RuntimeError('The joined guest requires its disposable XRDP workforce group settings.')
    cleanup.callback(install, settings, original, '0644')
    install(settings, changed, '0644')
    g('sudo systemctl restart xrdp-sesman xrdp')
    c('command -v xfreerdp3 && command -v xvfb-run && command -v xauth')

    def login(account, password, *pam_actions):
        command = shlex.join(['sudo', 'pamtester', 'xrdp-sesman', account, *pam_actions])
        invoke = [Path('bin/ocean-lab'), 'ssh', '-state', state, guest, '--', command]
        return subprocess.run(invoke, input=password, capture_output=True, timeout=20)

    if login(user, authorized, 'authenticate').returncode == 0:
        raise RuntimeError('A signed-only managed guest allowed a raw password.')
    enable_native()
    for account, password in ((user, authorized), (reader, unassigned)):
        if login(account, password, 'authenticate').returncode != 0:
            raise RuntimeError('A disposable workforce credential failed the normal PAM password stack.')

    def remove_session(account):
        g(shlex.join(['sudo', 'pkill', '-TERM', '-u', account, '-x', 'openbox|Xorg']) + ' || true')
    for account in (user, reader):
        remove_session(account)
        cleanup.callback(remove_session, account)

    client_pin = pin.replace(':', '').lower()
    def connect(account, password, label, lifetime):
        command = shlex.join(['timeout', '-k', '2s', lifetime, 'xvfb-run', '-a', 'xfreerdp3', '/v:10.232.1.12:3389',
                              '/u:' + account, '/from-stdin:force', '/sec:tls', '/cert:fingerprint:sha256:' + client_pin,
                              '/size:800x600', '/log-level:WARN'])
        command += '; status=$?; test "$status" -eq 0 || test "$status" -eq 124'
        log = cleanup.enter_context((report / f'desktop-native-{label}.log').open('wb'))
        process = subprocess.Popen([Path('bin/ocean-lab'), 'ssh', '-state', state, gateway_host, '--', command],
                                   stdin=subprocess.PIPE, stdout=log, stderr=log)
        cleanup.callback(close_process, process)
        process.stdin.write(password)
        process.stdin.close()
        return process

    def session(account):
        query = shlex.join(['pgrep', '-u', account, '-x', 'openbox'])
        return bool(g(query + ' || true').strip())

    started_at = time.monotonic()
    assigned = connect(user, authorized, 'assigned', '16s')
    wait(lambda: session(user), 14)
    if assigned.poll() is not None:
        raise RuntimeError('The assigned RDP connection closed before its desktop was observed.')
    duration = round((time.monotonic() - started_at)*1000)
    denied = connect(reader, unassigned, 'unassigned', '8s')
    until = time.monotonic() + 10
    while time.monotonic() < until and denied.poll() is None:
        if session(reader):
            raise RuntimeError('The private RDP client opened an unassigned account.')
        time.sleep(0.2)
    if denied.poll() is None or session(reader):
        raise RuntimeError('The denied client did not exit cleanly without a desktop session.')
    if assigned.wait(12) != 0:
        raise RuntimeError('The native client exited unexpectedly after the desktop opened.')
    remove_session(user)
    (report / 'desktop-native-rdp.tsv').write_text('case\tresult\tduration_ms\n'
        'password-fails-on-signed-only-guest\tPASS\t\n'
        f'assigned-native-rdp-session\tPASS\t{duration}\n'
        'unassigned-valid-password-denied\tPASS\t\n')


def start_redundant_gateways(work, cleanup, ca, signer, now, regional, pin, web_client):
    directory = Path('/opt') / name
    public_port = urls.urlsplit(gateway).port
    region_port = urls.urlsplit(regional).port
    identity_port = urls.urlsplit(live_args.keycloak_origin).port
    gateway_unit, vrrp_unit = name + '-app', name + '-vrrp'
    primary, standby = gateway_host, standby_gateway_host
    peers = ((primary, '10.231.1.18', '10.231.1.17', 150, 'identity', 'gateway-fixture'),
             (standby, '10.231.1.17', '10.231.1.18', 100, 'standby', 'gateway-b'))

    def remote(node, command):
        return region.ssh(state, node, command, timeout=25)

    def stop(node):
        log = remote(node, shlex.join(['sudo', 'journalctl', '--no-pager', '-u', gateway_unit, '-u', vrrp_unit]))
        (report / f'desktop-gateway-{node}.log').write_bytes(log)
        remote(node, shlex.join(['sudo', 'systemctl', 'stop', gateway_unit, vrrp_unit]) + ' || true')
        remote(node, shlex.join(['podman', 'rm', '-f', '--ignore', name]))
        remote(node, shlex.join(['sudo', 'rm', '-r', '-f', '--', str(directory)]))

    def owners():
        current = []
        for node, *_ in peers:
            addresses = json.loads(remote(node, 'ip -j -4 address show dev mgmt0'))[0]['addr_info']
            if any(address['local'] == gateway_vip for address in addresses):
                current.append(node)
        return current

    if owners():
        raise RuntimeError(f'The disposable desktop gateway address {gateway_vip} is already in use.')
    server_keys = []
    for node, address, peer, priority, local_prefix, host_id in peers:
        # Both services see the original loopback TLS origins through guest SSH forwards.
        forward = forward_port(node, '-R', f'127.0.0.1:{region_port}:127.0.0.1:{region_port}',
                               '-R', f'127.0.0.1:{identity_port}:127.0.0.1:{identity_port}')
        cleanup.callback(close_process, forward)
        remote(node, 'test -x /usr/sbin/keepalived && command -v curl && podman image exists ' + shlex.quote(image))
        cleanup.callback(stop, node)
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_id)]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))]), False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(signer, hashes.SHA256()))
        server_keys.append(key.public_key())
        host_cfg = {'enrollment': {'origin': regional, 'hostId': host_id, 'managementInterface': 'mgmt0',
                                   'stateDirectory': str(directory), 'caFile': str(directory / 'ca.pem'),
                                   'tokenFile': str(directory / 'unused')}}
        gateway_cfg = gateway_configuration(f'0.0.0.0:{public_port}', directory, 'server.pem', 'server.key',
                                            web_client, pin, remote_port)
        ready = shlex.join(['/usr/bin/curl', '--noproxy', '*', '--fail', '--silent', '--output', '/dev/null',
                            '--max-time', '1', '--cacert', str(directory / 'ca.pem'), gateway + '/readyz'])
        config = f"""global_defs {{
    router_id {host_id}
    script_user root
    enable_script_security
}}
vrrp_script gateway_ready {{
    script "{directory}/bin/ready"
    interval 1
    timeout 1
    rise 1
    fall 1
    init_fail
}}
vrrp_instance DESKTOP {{
    state BACKUP
    interface mgmt0
    virtual_router_id 97
    priority {priority}
    advert_int 1
    unicast_src_ip {address}
    unicast_peer {{
        {peer}
    }}
    virtual_ipaddress {{
        {gateway_vip}/24 dev mgmt0
    }}
    track_script {{
        gateway_ready
    }}
}}
"""
        region.upload(state, node, {
            'bin/ocean-desktop-gateway': Path('bin/ocean-desktop-gateway').read_bytes(),
            'bin/ready': ('#!/bin/sh\nexec ' + ready + '\n').encode(),
            'ca.pem': ca.public_bytes(serialization.Encoding.PEM),
            'provider.pem': live_args.keycloak_ca.read_bytes(),
            'server.pem': leaf.public_bytes(serialization.Encoding.PEM),
            'server.key': key_pem(key),
            'identity.crt': (work / f'{local_prefix}.crt').read_bytes(),
            'identity.key': (work / f'{local_prefix}.key').read_bytes(),
            'host.json': json.dumps(host_cfg).encode(),
            'gateway.json': json.dumps(gateway_cfg).encode(),
            'guacamole.min.js': script.read_bytes(),
            'keepalived.conf': config.encode(),
        }, str(directory))
        remote(node, shlex.join(['sudo', 'chown', 'ocean', str(directory / 'identity.crt')]) + ' && ' +
               shlex.join(['sudo', 'chmod', '0600', str(directory / 'identity.crt')]))
        remote(node, shlex.join(['nice', '-n', '10', 'podman', 'run', '--pull=never', '--rm', '-d', '--name', name,
                                  '--publish', f'127.0.0.1:{remote_port}:4822', '--entrypoint', '/bin/sh', image,
                                  '-ec', 'exec nice -n 10 /opt/guacamole/entrypoint.sh']))
        remote(node, shlex.join(['sudo', 'systemd-run', '--collect', '--unit', gateway_unit, '--uid=ocean', '--property=Nice=10',
                                  str(directory / 'bin/ocean-desktop-gateway'), '-config', str(directory / 'gateway.json')]))
        remote(node, shlex.join(['sudo', 'systemd-run', '--collect', '--unit', vrrp_unit, '/usr/sbin/keepalived',
                                  '--dont-fork', '--log-console', '--vrrp', '--use-file', str(directory / 'keepalived.conf'),
                                  '--pid', str(directory / 'keepalived.pid'), '--vrrp_pid', str(directory / 'vrrp.pid')]))
        region.eventually(lambda: remote(node, ready), 15)

    wait(lambda: owners() == [primary], 15)
    ingress = forward_port(gateway_observer, '-L', f'127.0.0.1:{public_port}:{gateway_vip}:{public_port}')
    cleanup.callback(close_process, ingress)

    def fail_primary():
        remote(primary, shlex.join(['sudo', 'systemctl', 'kill', '--signal=SIGKILL', gateway_unit]))

    return server_keys, fail_primary, lambda: owners() == [standby]


def main():
    global state, report, script, broker_image, etcd, host_cert, issuer, gateway
    global live_args, tenant, subscription, desktop, subnet, nic
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--guacamole-js', required=True, type=Path)
    parser.add_argument('--samba-image', required=True)
    parser.add_argument('--etcd', required=True)
    parser.add_argument('--live-keycloak', action='store_true')
    parser.add_argument('--gateway-failover', action='store_true')
    parser.add_argument('--keycloak-origin')
    parser.add_argument('--keycloak-ca', type=Path)
    parser.add_argument('--keycloak-client')
    parser.add_argument('--keycloak-secret', type=Path)
    parser.add_argument('--ldap-reader', type=Path)
    parser.add_argument('--domain-sid', type=Path)
    parser.add_argument('--browser-password', type=Path)
    parser.add_argument('--native-other-password', type=Path)
    args = parser.parse_args()
    if args.gateway_failover and not args.live_keycloak:
        parser.error('Gateway failover requires the live Keycloak and regional ARM fixture.')
    if args.native_other_password and not args.live_keycloak:
        parser.error('Native admission requires the live Samba and regional ARM fixture.')
    endpoint = urls.urlsplit(args.etcd)
    if (endpoint.scheme != 'http' or endpoint.hostname != '127.0.0.1' or not endpoint.port or
            endpoint.username is not None or endpoint.path or endpoint.query or endpoint.fragment):
        parser.error('Provide a disposable loopback etcd endpoint.')
    state, script, broker_image, etcd = args.state.resolve(), args.guacamole_js.resolve(), args.samba_image, args.etcd
    live_args = args if args.live_keycloak else None
    if live_args:
        if not all((args.keycloak_origin, args.keycloak_ca, args.keycloak_client, args.keycloak_secret,
                    args.ldap_reader, args.domain_sid, args.browser_password)):
            parser.error('The live probe requires the disposable Keycloak, Samba reader and browser account files.')
        args.application, args.client_id = str(uuid.uuid4()), str(uuid.uuid4())
        tenant, subscription = str(uuid.uuid4()), str(uuid.uuid4())
        scope = f'/subscriptions/{subscription}/resourceGroups/workplace/providers/'
        desktop = scope + 'Ocean.Desktop/personalDesktops/personal'
        subnet = scope + 'Microsoft.Network/virtualNetworks/office/subnets/personal'
        nic = scope + 'Microsoft.Network/networkInterfaces/personal'
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
                            '-addext', 'basicConstraints=critical,CA:TRUE',
                            '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
                            '-out', str(cert_path), '-keyout', str(key_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ca = x509.load_pem_x509_certificate(cert_path.read_bytes())
            ca_key = serialization.load_pem_private_key(key_path.read_bytes(), None)
            now = datetime.datetime.now(datetime.timezone.utc)
            hosts = [('identity', 'gateway-fixture')]
            if args.gateway_failover:
                hosts.append(('standby', 'gateway-b'))
            for prefix, host_id in hosts:
                key = ed25519.Ed25519PrivateKey.generate()
                leaf = pem_leaf(ca, ca_key, host_id, key, now)
                cert = leaf.public_bytes(serialization.Encoding.DER)
                (work / f'{prefix}.crt').write_bytes(cert)
                (work / f'{prefix}.key').write_bytes(key.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                for extension in ('crt', 'key'):
                    (work / f'{prefix}.{extension}').chmod(0o600)
                if prefix == 'identity':
                    host_cert = cert
            if live_args:
                issuer = live_args.keycloak_origin + '/realms/' + tenant
                web_client, identity_ca = live_args.client_id, live_args.keycloak_ca
            else:
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
                web_client, identity_ca = tenant, cert_path
            gateway_port = port()
            gateway = 'https://127.0.0.1:' + str(gateway_port)
            broker, broker_processes, real_origin, real = start_real_broker(work, cleanup, ca, ca_key, cert_path, key_path, now)
            if real:
                regional = real_origin
            session_script = '/etc/X11/Xsession.d/60-ocean-desktop-cifs'
            g('test ! -e '+session_script+' && test ! -e /run/ocean-desktop-cifs')
            cleanup.callback(g, 'sudo unlink '+session_script)
            install(session_script, Path('packaging/debian/60-ocean-desktop-cifs').read_bytes(), '0644')
            settings = {'machineId': machine, 'publicKey': base64.b64encode(launch_signer.public_key().public_bytes_raw()).decode(),
                        'kerberos': broker}
            install(helper, Path('bin/ocean-desktop-guest').read_bytes(), '0755')
            install(configuration, json.dumps(settings).encode(), '0600')
            g('sudo install -d -m0700 /var/lib/ocean-desktop/replay')
            snippet = Path('packaging/debian/ocean-desktop-pam').read_bytes()
            install(stage, original.replace(b'@include common-auth', snippet + b'@include common-auth'), '0644')
            changed = True
            g('sudo systemctl start xrdp-sesman xrdp')
            pin = g('sudo openssl x509 -in /etc/xrdp/cert.pem -noout -fingerprint -sha256').decode().strip().split('=', 1)[1]
            if args.native_other_password:
                def enable_native():
                    settings['native'] = {key: value for key, value in broker.items() if key != 'service'}
                    install(configuration, json.dumps(settings).encode(), '0600')
                verify_native_rdp(cleanup, pin, enable_native)
            probe_result = prepare_user_probe(cleanup)
            if args.gateway_failover:
                server_keys, fail_primary, standby_owns_vip = start_redundant_gateways(
                    work, cleanup, ca, ca_key, now, regional, pin, web_client)
            else:
                c(shlex.join(['nice', '-n', '10', 'podman', 'run', '--pull=never', '--rm', '-d', '--name', name,
                              '--publish', f'127.0.0.1:{remote_port}:4822', '--entrypoint', '/bin/sh', image,
                              '-ec', 'exec nice -n 10 /opt/guacamole/entrypoint.sh']))
                started = True
                mapped = port()
                forward = forward_port(gateway_host, '-L', f'127.0.0.1:{mapped}:127.0.0.1:{remote_port}')
                cleanup.callback(close_process, forward)
                (work / 'host.json').write_text(json.dumps({'enrollment': {
                    'origin': regional, 'hostId': 'gateway-fixture', 'managementInterface': 'lo',
                    'stateDirectory': str(work), 'caFile': str(cert_path), 'tokenFile': str(work / 'unused')}}))
                (work / 'provider.pem').write_bytes(identity_ca.read_bytes())
                # The regional and local browser gateway share the disposable TLS CA.
                local = gateway_configuration(f'127.0.0.1:{gateway_port}', work, 'tls.pem', 'tls.key', web_client, pin, mapped)
                local['guacamoleScriptFile'] = str(script)
                config = work / 'gateway.json'
                config.write_text(json.dumps(local))
                gateway_log = cleanup.enter_context((report / 'desktop-smb-gateway.log').open('wb'))
                server = subprocess.Popen(['bin/ocean-desktop-gateway', '-config', str(config)], stdout=gateway_log, stderr=gateway_log)
                cleanup.callback(close_process, server)
                server_keys = [ca.public_key()]
            trust = ssl.create_default_context(cafile=cert_path)
            readiness_error = None
            def healthy():
                nonlocal readiness_error
                try:
                    with urlrequest.urlopen(gateway + '/readyz', context=trust, timeout=2) as reply:
                        return reply.status == 204
                except OSError as error:
                    readiness_error = error
                    return False
            try:
                wait(healthy, 15)
            except RuntimeError as error:
                raise RuntimeError(f'The shared HTTPS gateway was not ready: {readiness_error}') from error
            if real:
                server_keys.append(x509.load_pem_x509_certificate(identity_ca.read_bytes()).public_key())
            spki = ','.join(base64.b64encode(hashlib.sha256(key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
                for key in server_keys)
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
            tunnels = set()
            upgrades = []
            def command(method, params):
                nonlocal msgid
                msgid += 1
                cdp.send(json.dumps({'id': msgid, 'method': method, 'params': params}))
                while True:
                    result = json.loads(cdp.recv())
                    if result.get('id') == msgid:
                        return result.get('result', {})
                    event = result.get('method')
                    params = result.get('params', {})
                    if event == 'Network.webSocketCreated':
                        target = urls.urlsplit(params['url'])
                        if (target.scheme, target.netloc, target.path) == ('wss', urls.urlsplit(gateway).netloc, '/d/personal/tunnel'):
                            tunnels.add(params['requestId'])
                    if event == 'Network.webSocketHandshakeResponseReceived' and params['requestId'] in tunnels:
                        upgrades.append(params['response']['status'])
            def browser_state():
                expression = ('({status: document.querySelector("#status")?.textContent, canvas: document.querySelectorAll("canvas").length, '
                              'path: location.pathname, page: performance.timeOrigin, text: document.body?.innerText?.slice(0, 120)})')
                return command('Runtime.evaluate', {'expression': expression, 'returnByValue': True}).get('result', {}).get('value', {})
            before = int(g('sudo wc -l /var/log/xrdp-sesman.log').split()[0])
            command('Network.enable', {})
            command('Page.navigate', {'url': gateway + '/d/personal'})
            if real:
                finish_live_login(command, real[1])
            def drawn():
                result = browser_state()
                (report / 'desktop-smb-browser-state.json').write_text(json.dumps(result))
                return result.get('status') == 'Desktop connected' and result.get('canvas', 0) > 0
            wait(drawn, 18)
            def authenticated_guest():
                guest_log = g(f'sudo tail -n +{before + 1} /var/log/xrdp-sesman.log').decode()
                (report / 'desktop-smb-xrdp.log').write_text(guest_log)
                return 'Access permitted' in guest_log and (real is not None or renew.is_set())
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
            if args.gateway_failover:
                old_page = browser_state().get('page')
                if upgrades != [101] or browser_state().get('status') != 'Desktop connected':
                    raise RuntimeError(f'Expected one connected primary WebSocket. Observed upgrade statuses: {upgrades}.')
                openbox = shlex.join(['pgrep', '-u', user, '-x', 'openbox'])
                session_pid = g(openbox).strip()
                if len(session_pid.splitlines()) != 1:
                    raise RuntimeError('Expected exactly one active window manager for the desktop account.')
                started_at = time.monotonic()
                fail_primary()
                wait(standby_owns_vip, 18)
                vip_ms = round((time.monotonic() - started_at) * 1000)

                def reconnected():
                    visible = browser_state()
                    (report / 'desktop-gateway-reconnect-state.json').write_text(json.dumps(visible))
                    return (visible.get('page') != old_page and visible.get('path') == '/d/personal' and
                            visible.get('status') == 'Desktop connected' and visible.get('canvas', 0) > 0)

                wait(reconnected, 30)
                reconnect_ms = round((time.monotonic() - started_at) * 1000)
                if upgrades != [101, 101] or g(openbox).strip() != session_pid:
                    raise RuntimeError('The standby must reopen the same XRDP session over a second WebSocket.')
                guest_log = g(f'sudo tail -n +{before + 1} /var/log/xrdp-sesman.log').decode()
                (report / 'desktop-smb-xrdp.log').write_text(guest_log)
                (report / 'desktop-gateway-failover.tsv').write_text(
                    'case\tresult\tduration_ms\n'
                    f'vrrp-standby-sole-owner\tPASS\t{vip_ms}\n'
                    f'same-profile-browser-reconnect\tPASS\t{reconnect_ms}\n'
                    'initial-https-websocket-101\tPASS\t\n'
                    'standby-https-websocket-101\tPASS\t\n')
                print(f'Standby acquired the HTTPS address in {vip_ms} ms; the browser reopened its session in {reconnect_ms} ms.')
            if browser_state().get('status') != 'Desktop connected':
                raise RuntimeError('The browser tunnel was not active before revocation.')
            started_at = time.monotonic()
            if real:
                dc(shlex.join(['sudo', 'samba-tool', 'group', 'removemembers', real[0], 'smbwriter']))
            else:
                deny.set()
            def revoked():
                return browser_state().get('status') == 'Desktop disconnected'
            wait(revoked, 15)
            ms = round((time.monotonic() - started_at)*1000)
            if ms > 15_000:
                raise RuntimeError(f'The opened tunnel exceeded the 15-second withdrawal bound. Measured {ms} ms.')
            (report / 'desktop-smb-browser.tsv').write_text('case\tresult\tduration_ms\nchromium-oidc-to-real-xrdp\tPASS\t\nchromium-open-tunnel-revocation\tPASS\t' + str(ms) + '\n')
            (report/'desktop-smb-results.tsv').write_text('case\tresult\nkerberos-broker-and-guest\tPASS\napplication-session-to-encrypted-share\tPASS\npersonal-samba-audit\tPASS\ncache-uid-isolation\tPASS\n')
            (work/'broker.done').write_text('done')
            if real:
                real[2].set()
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
