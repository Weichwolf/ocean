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

After starting the regional stack and the replicated database, deploy two Keycloak instances and run the sign-in fault check. The verification uses the isolated operator VM and the unmodified Microsoft Debian AMD64 package for Azure CLI 2.93.0. Use the package argument to install it if it is absent. The deploy and verification scripts check the SHA-256 of the supplied artifacts. [Keycloak 26.8.2](https://github.com/keycloak/keycloak/releases/tag/26.8.2) · [Microsoft Azure CLI packages](https://packages.microsoft.com/repos/azure-cli/pool/main/a/azure-cli/)

```sh
python3 lab/keycloak.py --state "$OCEAN_LAB_STATE" --keycloak-archive /path/to/keycloak-26.8.2.tar.gz
python3 lab/verify_identity.py --state "$OCEAN_LAB_STATE" --azure-cli-package /path/to/azure-cli_2.93.0-1~bookworm_amd64.deb
```

Both Keycloak replicas use verified TLS to PostgreSQL and connect to the current primary. The gateways forward OAuth traffic using TLS on both connections. They allow the browser and OAuth endpoints and keep the Keycloak admin and health paths private. Keycloak uses its database-backed cluster discovery with encrypted peer traffic. [Keycloak proxy configuration](https://www.keycloak.org/server/reverseproxy) · [Keycloak distributed caches](https://www.keycloak.org/server/caching)

The check creates an empty CLI cache for each sign-in, selects the assigned subscription, lists its locations, and checks both token audiences and the rejection of invalid or disabled credentials. It stops one Keycloak instance and then restores it. In a separate fault, it waits for PostgreSQL promotion and signs in before the previous database writer rejoins. The respective lab limits are 75 and 120 seconds for the full sign-in and credential checks. The run saves its observations under `evidence/identity-failover.json` in the lab state. This uses a disposable pre-provisioned tenant and subscription. The operator onboarding, directory operation, and role assignment cases exercise separate API paths.

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

ARM subscription discovery uses API version `2022-12-01`. It verifies the access token's signature, tenant issuer, expiry, and ARM audience. It reads the tenant's subscription membership from the regional quorum and returns the assigned region for the locations request. The lab seeds a subscription for the two fixture subjects after authenticating them, so the fault runs exercise the subscription API.

## Tenant onboarding

The lab deployment adds a dedicated operator realm and Automation client. The control plane requires a signed ARM access token from that realm and client for `PUT /ocean/tenants/{tenantId}?api-version=2026-11-01`. Register the cloud and sign in using the operator's application ID and secret. An operator can acquire the token without subscription discovery using `--allow-no-subscriptions --skip-subscription-discovery`.

Put `displayName`, `administratorUserPrincipalName`, and `administratorPassword` in a private JSON request file. Choose a tenant UUID before sending the first request. Retain the same UUID and request for retries.

```sh
az rest --method put \
  --url "https://arm.farm-1.ocean.test/ocean/tenants/$TENANT_ID?api-version=2026-11-01" \
  --body @tenant-request.json
```

The response contains `tenantId`, `subscriptionId`, and `administratorId`. The control plane reserves the allocation in etcd, imports and confirms the Keycloak realm and administrator, and then publishes the subscription. An identical request returns the same IDs. A conflicting request returns HTTP 409. After a transient HTTP 503, repeat the request with the original inputs. The allocation fingerprint is keyed and the password stays out of etcd.

The `identity.onboarding` configuration contains the operator tenant and client IDs, the private Keycloak admin origins, the lab admin client and its credential file, and a regional key file. Each API replica uses the same regional key to derive the exchange credential for a tenant. Keep this key with the region's recoverable credentials and provision the files with owner-only access.

Run `python3 lab/verify_onboarding.py --state "$OCEAN_LAB_STATE"` after the identity deployment and CLI installation. The test discards a successful response body, retries through `az rest`, creates a second tenant, and verifies independent administrator sign-ins and cross-tenant denials. It records the resulting IDs and assertions in `evidence/tenant-onboarding.json` under the disposable lab state.

## Tenant directory users

The initial tenant administrator uses Microsoft Graph `v1.0` with a Graph access token. The CLI workflow uses `az ad user create`, `list`, `show`, `update`, and `delete`. Lists support an exact UPN or a display-name prefix, with server paging. Object lookup accepts a UUID or a UPN. The administrator can change a user's display name, mail alias, login status, and password. The original administrator can update their profile and password and must remain enabled.

Keycloak stores the directory account and password and enforces login. Ocean declares the Graph display name and alias as managed Keycloak attributes writable by the admin API. Realm-scoped device login uses the bounded offline session policy configured at registration. [Keycloak user profiles](https://www.keycloak.org/docs/latest/server_admin/index.html#user-profile)

Run `python3 lab/verify_onboarding.py --state "$OCEAN_LAB_STATE" --directory-users` to exercise the user lifecycle with two freshly onboarded tenants. The check verifies that updates preserve the mail alias, regular users are denied directory administration, and deleted users cannot start a new login. Evidence is written to `evidence/graph-users.json`.

## Tenant applications and service principals

Use `az ad app create --display-name <name>` to register a single-tenant application, then `az ad sp create --id <app-id>` to provision its service principal. The application object ID, app ID, and service principal object ID are distinct. The app ID identifies the client during `az login --service-principal`. Access to a subscription requires a separate authorization grant.

Use `az ad app credential reset --id <app-id> --append` to add a password credential. Each password has its own identifier and validity interval. The add operation returns the secret once. Directory reads expose credential metadata. The regional store keeps a keyed verifier for each secret and uses conditional updates for concurrent credential changes. To remove a password, use `az ad app credential delete --id <app-id> --key-id <key-id>`. Removed and expired passwords are denied at the next authentication. The supported validity limit is two years, with at most 64 password credentials per app. [Graph addPassword](https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0)

Run `python3 lab/verify_onboarding.py --state "$OCEAN_LAB_STATE" --directory-users --directory-apps` to exercise these commands. The run verifies separate ARM and Graph tokens from fresh CLI caches, rejects cross-tenant reads, signs in with both secrets after append, and checks that the remaining secret works after revocation. Inspect `evidence/graph-applications.json` for the object IDs and assertions.

## ARM resource groups

Run `python3 lab/verify_arm.py --state "$OCEAN_LAB_STATE"` after deploying the control plane and installing the pinned CLI in the operator guest. The verifier runs the [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv) with a fresh CLI cache per tenant. It creates and removes the test groups and records pagination, concurrent writes, tenant isolation, and negative API responses in `evidence/arm-resource-groups.json` under the lab state.

Resource groups use ARM API version `2024-11-01`. The supported create request accepts the regional location and up to 50 string tags. Names are case-insensitive and reads preserve the casing from creation. Tag values are returned as supplied. A create at an existing name updates its tags and preserves the location. List has continuations on the configured ARM origin. Group deletion completes synchronously for empty groups and can be retried after a lost response.

`az provider show --namespace Microsoft.Resources` reports the implemented resource group type, its API version, and the available regional location. Unsupported namespaces return `InvalidResourceNamespace`.

## Scoped ARM roles

The tenant administrator can assign the built-in Reader role at an existing resource group scope. Assignees are tenant users or service principals identified by their directory object IDs. The supported CLI commands and parameters are in the [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv). Azure CLI 2.93.0 uses `2022-04-01` for role assignments and `2022-05-01-preview` for role definitions. Provider discovery for `Microsoft.Authorization` publishes these versions. [Role assignment API](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create?view=rest-authorization-2022-04-01) · [Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader)

Readers discover the parent subscription and see groups and assignments within their grants. The API consults the current grant state for each request, including requests carrying tokens issued before revocation. An assignment and its access index commit or delete together. Group deletion removes its scoped grants and assignments in the same transaction. Group mutations, role assignment mutations, and denied privileged actions persist actor, action, target, result, and time in the tenant's audit keyspace. etcd supplies the commit revision.

Run `python3 lab/verify_arm.py --state "$OCEAN_LAB_STATE" --rbac` to exercise grant creation, listing, deletion, and continued use of a token issued before revocation. It verifies cross-tenant and out-of-scope denials, rejects altered and wrong-audience tokens, and checks the audit revisions in etcd. The run writes `evidence/arm-rbac.json` under the lab state.
