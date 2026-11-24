# Rootless ocean development lab

Use a Debian host with access to `/dev/kvm`, a Debian generic AMD64 QCOW2 cloud image, QEMU, cloud-image-utils, VDE, and OpenSSH. The launcher runs QEMU with hardware acceleration and adjusts its niceness by +10. Node disks use QCOW2 overlays over the supplied image. The launcher keeps the image path and SHA-256 digest in the local state and checks them when the lab starts again.

## Start and inspect guests

```sh
make build
OCEAN_LAB_STATE=$(mktemp -d /tmp/ocean-lab.XXXXXX)
OCEAN_LAB_IMAGE="$HOME/.cache/ocean/images/debian-13-generic-amd64.qcow2"

./bin/ocean-lab plan -profile lab/profiles/single-farm-3.yaml
./bin/ocean-lab up -state "$OCEAN_LAB_STATE" -profile lab/profiles/single-farm-3.yaml -image "$OCEAN_LAB_IMAGE"
./bin/ocean-lab status -state "$OCEAN_LAB_STATE"
./bin/ocean-lab ssh -state "$OCEAN_LAB_STATE" farm-1-node-01 -- 'cloud-init status --wait'
```

`status` reports the QEMU process state. Use the guest's cloud-init status for boot readiness. The launcher generates an SSH key for the lab and supplies it through a private NoCloud seed. SSH forwarding is bound to the host loopback address. Use `down` to stop QEMU and the VDE switches while retaining the state and guest disks.

```sh
./bin/ocean-lab down -state "$OCEAN_LAB_STATE"
```

## Profiles and networking

The `single-farm-3` and `scale-16` profiles use the same addresses and hardware identities for the first three nodes. Run `up` with the larger profile in the same state directory to add nodes. The `geo-4x3` and `geo-4x4` profiles work the same way for four farms. Three nodes per farm carry the control-plane role and two carry the gateway role. Each farm also has separate operator and customer clients.

Every farm has its own VDE management, workload, and customer segments. The four-farm profiles add two separate VDE segments for the WAN gateway paths. The operator client attaches to management, and the customer client attaches to the customer segment. The client bootstrap interfaces provide only loopback SSH access. Ocean nodes also have bootstrap egress for package and image downloads. Guests with a management interface resolve their farm's `arm.farm-N.ocean.test` and `id.farm-N.ocean.test` names to `10.231.N.10` using data in the NoCloud seed. This address is reserved for the management virtual IP.

Copy a profile to customize node sizing. Overrides use the guest name printed by `plan`. Start a separate lab directory to adopt changes to an existing guest's declared sizing or interfaces.

```yaml
farms: 1
nodesPerFarm: 3
defaults:
  memoryMiB: 1024
  vcpus: 1
overrides:
  farm-1-node-03:
    memoryMiB: 2048
    vcpus: 2
```

The launcher checks requested memory for new guests against host `MemAvailable` and retains the memory headroom specified by `-reserve-mib`. The default is 2048 MiB. Record measured host headroom, CPU allocation, and disk use for acceptance runs. The lab provisions the guests, addresses, and network segments used by the protocol. Product readiness, quorum, join, and workload results come from the corresponding acceptance checks on a deployed ocean build.

## Regional management stack

Build the binaries and start a fresh `single-farm-3` lab as shown above. Obtain the [etcd v3.6.17 Linux AMD64 archive](https://github.com/etcd-io/etcd/releases/tag/v3.6.17). The deploy script checks its SHA-256 before installing the binaries. Run the deploy and fault checks locally on the Debian host.

```sh
python3 lab/region.py --state "$OCEAN_LAB_STATE" --etcd-archive /path/to/etcd-v3.6.17-linux-amd64.tar.gz
python3 lab/verify_region.py --state "$OCEAN_LAB_STATE"
```

The stack uses three mutually authenticated etcd voters, three HTTPS API replicas, and two gateway nodes. HAProxy checks readiness over TLS and passes the client TLS connection to a healthy replica. Keepalived transfers the management address after a gateway failure. Both gateways serve authoritative names for management and identity. The isolated operator client resolves those names through both DNS servers and verifies the management certificate.

The deploy script installs HAProxy, Keepalived, and dnsmasq inside the gateway guests. The generated lab CA keys stay in the operator's private state directory. Peer, store client, and ingress certificates use separate CAs. Lab client credentials are for the disposable deployment. Use operator-managed certificates and a dedicated production deployment when qualifying physical hosts.

Regional bootstrap creates the region record and its initial cell record in one etcd transaction. Incompatible bootstrap settings prevent a replica from starting. Provider operations use keys under `/ocean/v1/regions/<region>/operations` and cell reservations use keys under `/ocean/v1/regions/<region>/cells/<cell>/reservations`. The local fault check exercises authoritative DNS, gateway and API loss, leader replacement, and the absence of a committed mutation while quorum is unavailable. A timed-out raw etcd request has an unknown outcome after recovery. Providers must reconcile such requests using the existing operation ID. The check restores affected services and removes its own test keys. Run it on a dedicated lab because it stops services and powers off a guest.

## Replicated identity database

Start a dedicated lab with `lab/profiles/identity-ha-3.yaml`, deploy the regional management stack into it, and run the database deployment and fault check locally. This profile gives the two nodes planned for Keycloak 3 GiB of RAM each and the third node 2 GiB, with two vCPUs per server.

```sh
python3 lab/postgres.py --state "$OCEAN_LAB_STATE"
python3 lab/verify_postgres.py --state "$OCEAN_LAB_STATE"
```

The deployment uses Debian PostgreSQL 17 and Patroni. The PostgreSQL replication and application connections require verified TLS and SCRAM authentication. The cluster uses the existing etcd quorum over mTLS, with its own state prefix and client certificate. The etcd TLS listener certificate authenticates the HTTPS gateway's internal connection to etcd.

Patroni requires a watchdog before promoting a writer. The KVM control-plane guests expose an Intel 6300ESB watchdog and QEMU resets the guest on expiry. Strict synchronous replication requires one standby for a commit. The failover check writes a marker, stalls Patroni's main process, and observes the watchdog reset over QMP. It requires promotion within 45 seconds, preservation of the acknowledged marker, and replay of a new commit after the former writer rejoins as a standby. It temporarily disables the stalled service at boot to represent a member that remains down after reset. Use this check on the dedicated lab. The virtual watchdog validates guest-process failure. Production fencing also requires independent host-level controls. [Patroni watchdog behavior](https://patroni.readthedocs.io/en/latest/watchdog.html)

## Azure CLI identity compatibility

Configure the control plane with the public ocean authority, the public Keycloak origin, and an optional PEM CA for the Keycloak connection. If cloud endpoint discovery is enabled, configure distinct public ARM and Graph origins.

```json
{
  "identity": {
    "authority": "https://id.farm-1.ocean.test",
    "provider": "https://oauth.farm-1.ocean.test",
    "providerCAFile": "/path/to/provider-ca.pem",
    "exchangeSecretDirectory": "/path/to/private/realm-credentials",
    "cloud": {
      "resourceManager": "https://arm.farm-1.ocean.test",
      "microsoftGraph": "https://graph.farm-1.ocean.test"
    }
  }
}
```

With the lab CA trusted, set `AZURE_CORE_INSTANCE_DISCOVERY=false` in the CLI test environment so MSAL uses the registered ocean authority. Azure CLI 2.93.0 discovers these endpoints through `az cloud register --name ocean --endpoint-resource-manager https://arm.farm-1.ocean.test` and `az cloud set --name ocean`. Configure the realm using its tenant UUID. Use `az login --tenant <tenant-uuid> --use-device-code` for users and `az login --tenant <tenant-uuid> --service-principal` with the application ID and secret for automation.

Keycloak 26.8.2 publishes discovery under `/realms/{tenant}/.well-known/openid-configuration`. The CLI requests `/{tenant}/v2.0/.well-known/openid-configuration` and requires a display message in the Device Authorization response. The control plane supplies these two adaptations. Keycloak handles browser authentication, consent, OAuth grants, and signing.

Configure the public Azure CLI client ID `04b07795-8ddb-461a-bbee-02f9e1bf7b46` with device authorization enabled. Map the realm UUID to the ID token's `tid` claim, the user's login name to `preferred_username`, and the Keycloak subject to `sub` in access tokens. Give users the `offline_access` role, enable the corresponding scope on the public client, and set a maximum offline session lifetime.

Configure the public client's access token mapper to give its native grant the sole audience `ocean-token-exchange`. Create this confidential client in each tenant realm with standard token exchange enabled and a distinct private credential. Give it one optional scope named `<resource-origin>/.default` per resource, each mapping to the corresponding single audience. Grant service principals these same optional resource scopes. Store the exchange credentials as private `<tenant-uuid>.secret` files readable by the control-plane service. The directory and files must deny group and other access.

The CLI device flow starts with the ARM scope. The compatibility endpoint obtains a native Keycloak grant and asks Keycloak to exchange the native access token for the requested resource. On refresh it can request ARM or Graph using the same Keycloak session. The response keeps the user's native session and includes the exchanged access token. The endpoint requires the same issuer and subject and exactly one resource audience. Keycloak handles user consent, token lifetimes, and signing. [Keycloak standard token exchange](https://www.keycloak.org/securing-apps/token-exchange)

Local probes with disposable realms passed cloud discovery, end-user device login, service-principal login, and token acquisition for both audiences from each login. The probes skipped subscription discovery. Identity acceptance still requires tests for subscription discovery, audience validation at the API boundary, tenant onboarding, and identity failover.
