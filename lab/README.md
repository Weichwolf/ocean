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

`status` reports the QEMU process state. Use the guest's cloud-init status for boot readiness. The launcher generates an SSH key for the lab and supplies it through a private NoCloud seed. SSH forwarding is bound to the host loopback address. Use `stop` with an inventoried guest name to simulate sudden loss of one guest. Use `down` to stop QEMU and the VDE switches while retaining the state and guest disks. [QEMU monitor command](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#qapidoc-89)

```sh
./bin/ocean-lab down -state "$OCEAN_LAB_STATE"
```

Use `ocean-lab shutdown -state "$OCEAN_LAB_STATE"` to stop the lab between
acceptance profiles. It waits for the guests to flush their data and power
off before stopping the switches.

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

## Samba AD domain join lab

Use a new owner-only state directory. This interoperability fixture installs
Samba AD in a Debian guest and configures another Debian guest to use its
private DNS and time service. A guest on the second farm probes isolation.
The Windows guests use the first farm's same workload switch.

```sh
make build
OCEAN_AD_STATE=$(mktemp -d /tmp/ocean-ad.XXXXXXXX)
python3 lab/verify_domain_join.py --state "$OCEAN_AD_STATE" \
  --debian-image "$HOME/.cache/ocean/images/debian-13-generic-amd64.qcow2"
```

The verifier checks the LDAP SRV record and time source, rejects invalid
credentials on the initial join, and checks machine membership, PAM sign-in,
group resolution and a Kerberos ticket after reboot. The foreign fixture
checks that LDAP, Kerberos and directory DNS are unreachable. The sanitized
result is in `evidence/debian-domain-join.json` under the state directory.
Keep the generated credentials in `identity/domain-join.secret` local to
this disposable lab.

Use official Server 2025 installation media and select Server Core. Use
licensed Windows 11 Pro media or the official Windows 11 Enterprise Evaluation
for the workstation. Keep both media files outside the repository. The launcher
needs OVMF and `genisoimage`. The Windows 11 profile also needs a host `swtpm`
executable. [Server evaluation](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025) · [Workstation evaluation](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise)

```sh
python3 lab/start_windows_domain_fixture.py --state "$OCEAN_AD_STATE" \
  --iso "$WINDOWS_SERVER_ISO" --profile server-core

python3 lab/start_windows_domain_fixture.py --state "$OCEAN_AD_STATE" \
  --iso "$WINDOWS_11_ISO" --profile windows-11
```

Run each launcher in its own terminal. Connect a VNC viewer to the private
Unix socket `<state>/<profile>/vnc`. The probe script is on the
`OCEAN_PROBE` optical volume. The launcher records the installation
media digest in `<state>/<profile>/media.json`.

An optional private `Autounattend.xml` can be attached with `--answer-file`.
Use a local account name of 20 characters or fewer and set the same name
for autologon when enabled. [Windows account name limit](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd)

After a fixture has booted from its installed disk, resume a stopped guest
with `--resume`, the same `--state` and `--profile`, and the original `--iso`.
The launcher checks the media digest and retains the disk, firmware state,
probe ISO, and serial log.

In each disposable Windows guest, set the Ethernet interface to
`10.232.1.20/24` (Server Core) or `10.232.1.21/24` (Windows 11), with
DNS at `10.232.1.11` and without a default gateway. Set the correct time
before domain join and use the fixture controller as the time source.
Run the following from the probe volume, selecting `ServerCore` or
`Windows11` as the profile. Use the disposable lab administrator
for the join. Reboot each guest before running the machine check. Sign in
as `OCEANLAB\employee` before running the identity check.

```powershell
.\verify_windows_domain_join.ps1 -Profile ServerCore -Action Join -SendToLab
Restart-Computer
# After reboot, with administrator rights
.\verify_windows_domain_join.ps1 -Profile ServerCore -Action VerifyMachine -SendToLab
# In a domain employee session
.\verify_windows_domain_join.ps1 -Profile ServerCore -Action VerifyIdentity -SendToLab
```

Export the three guest records from the launcher serial capture. Run
`python3 lab/verify_domain_join.py --state "$OCEAN_AD_STATE" --windows-profile server-core`
after the three actions. Use `windows-11` for the second guest. The
export validates the media digest, machine identity, edition, reboot and
user evidence before writing the records in each profile's state
subdirectory. The same verifier accepts the three UTF-8 JSON records
copied from the guest as `join.json`, `machine.json`, and `identity.json`.

Run the local acceptance profile after preparing the guests and collecting
their proof. The harness writes a Markdown report and TSV. Missing Windows
records produce a blocked case. To rerun the live Debian probe alone, add
`OCEAN_E2E_CASES=WORKPLACE-01` to the command.

```sh
OCEAN_E2E_PROFILE=domain-join OCEAN_E2E_DOMAIN_STATE="$OCEAN_AD_STATE" \
  OCEAN_E2E_DEBIAN_IMAGE="$HOME/.cache/ocean/images/debian-13-generic-amd64.qcow2" \
  go test -tags=e2e -count=1 -run '^TestAcceptance$' ./tests/e2e
```

Shut down the Windows guests from the guest console, then run
`bin/ocean-lab shutdown -state "$OCEAN_AD_STATE"` to stop the Debian
guests and their switches.

## KVM tenant guest runtime probe

The Server Core runtime uses Debian 13 QEMU/KVM with the `pc-q35-10.0`
machine, OVMF UEFI, an AHCI boot disk and the `e1000e` Ethernet device.
`Standard_B1ms` requests one vCPU and 2 GiB, and `Standard_B2s` requests
two vCPUs and 4 GiB. Each guest has a persistent firmware UUID, a MAC derived
from that UUID and its own writable firmware variables. The only host control
socket is a local QMP socket in a private directory. The runtime starts QEMU
with niceness 10 and carries an exclusive local writer lock in that process.
[QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html)

The reference guest was installed from Microsoft Windows Server 2025
evaluation media with SHA-256
`7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51`.
The native guest probe reported Server Standard Evaluation, Server Core,
build `26100.32230`, Microsoft Standard SATA AHCI driver `10.0.26100.7309`
and Microsoft Intel 82574L Ethernet driver `12.19.1.32`. The Debian lab used
QEMU package `1:10.0.13+ds-0+deb13u1` and OVMF `2025.02-8+deb13u1`.
Record the raw image and firmware-variable digests for each prepared fixture
because its Windows configuration changes both files.

Use a powered-off Server 2025 Core fixture installed from operator-supplied
media. Supply its disk and OVMF variables as `WINDOWS_PREPARED_QCOW2` and
`WINDOWS_PREPARED_VARS`. This example uses a fixture with static IPv4 address
`10.232.1.20/24`, BusyBox `arping`, `/dev/kvm` and `/dev/net/tun`. The test
touches the disposable copies in its state directory and runs on a private
TAP segment inside a user and network namespace.

```sh
umask 077
OCEAN_KVM_SMOKE_STATE=$(mktemp -d /tmp/ocean-kvm.XXXXXX)
export OCEAN_KVM_SMOKE_STATE
export OCEAN_KVM_SMOKE_PRIVATE_IP=10.232.1.20
qemu-img convert -f qcow2 -O raw "$WINDOWS_PREPARED_QCOW2" "$OCEAN_KVM_SMOKE_STATE/disk.raw"
install -m 0600 "$WINDOWS_PREPARED_VARS" "$OCEAN_KVM_SMOKE_STATE/OVMF_VARS.fd"
go test -mod=readonly -tags=e2e -c -o "$OCEAN_KVM_SMOKE_STATE/runtime.test" ./internal/qemu
unshare --user --map-root-user --net --pid --fork --mount-proc sh -ec '
  ip tuntap add dev oceanvmtest mode tap
  ip addr add 10.232.1.254/24 dev oceanvmtest
  ip link set oceanvmtest up
  exec "$OCEAN_KVM_SMOKE_STATE/runtime.test" -test.v -test.run "^TestKVMGuestPowerLifecycle$"
'
```

The probe checks KVM acceleration, replays the start, rejects a different
generation, and verifies that a missing QMP socket leaves the writer lock in
effect. It times the ACPI shutdown and resolves the private guest address to
the same MAC on both boots. Use a fixture whose guest power-button policy
permits ACPI shutdown. `OCEAN_KVM_SMOKE_STOP_MODE=force` exercises immediate
QEMU exit and restart, and records the selected stop mode. Capture the
installation media and prepared disk chain digests with the result. Regional
ARM operations, tenant isolation and cross-host fencing are separate
acceptance steps. [Tenant VM issue](https://github.com/Weichwolf/ocean/issues/51)

### Replicated VM backing disk

Stage the fully materialized raw OS disk and its 4 MiB OVMF variable store as
private root-owned catalog files. Record the logical disk size and SHA-256 of
both files. The backend imports sparse disks of 32–128 GiB into an exclusively
mapped RBD volume. The LUKS2-encrypted volume contains ext4 with separate OS
and UEFI state files. The worker commits the preparation receipt after both
files are durable. The runtime account can write the two backing files. The
receipt and directory stay under storage service ownership. The preparation
receipt makes exact import retries preserve the guest's subsequent writes.
[Ceph exclusive locks](https://docs.ceph.com/en/reef/rbd/rbd-exclusive-locks/)

With the storage lab running, exercise the backing store on two disposable
Debian workers. The probe uses a sparse synthetic 32 GiB disk and validates
digest and key rejection, import replay, open-file protection on detach,
encrypted snapshot contents, and the disk and UEFI writes on the second
worker after a confirmed detach.

```sh
python3 lab/verify_vm_disk.py --state "$LAB_STATE"
```

The storage probe writes `vm-disk.json` and the worker logs under the lab
state's `evidence` directory. It exercises the backing files directly. The
VM-provider acceptance exercises Windows writes and confirms the fence before
placing a failed worker's VM on another host.

### Debian KVM worker service

Install the agent package on the selected compute hosts and install
`qemu-system-x86`, `qemu-utils`, `ovmf`, `ceph-common`, `cryptsetup-bin`,
`dnsmasq-base`, `iputils-arping` and `e2fsprogs`. Give the host enrollment
account `ocean-agent` and the dedicated hypervisor account `ocean-vm` access
to `/dev/kvm`, then restart the enrollment account's user manager so it receives
its current supplementary groups. Approve each compute host with
`requireKVM: true` and configure it as a regional storage worker.

In addition to the enrollment configuration, set up
`/etc/ocean-agent/storage.json` with the worker's RBD client and mount root,
and `/etc/ocean-agent/workload-network.json` with its private fabric and
protected prefixes. In `/etc/ocean-agent/vm.json`, set `imageDirectory` to the
worker's private root-owned catalog directory. Its raw disk and OVMF variable
files are named by their pinned SHA-256 digests, followed by `.raw` and `.fd`,
respectively. `firmwareCode` defaults to the Debian 4 MiB OVMF image. Optional
`dnsServers` provides IPv4 guest DNS values. Enable `ocean-vm-agent.service`
after configuring these files and enrolling the host.

The worker opens the assigned encrypted disk, installs a leased private
firewall and starts QEMU as `ocean-vm` at niceness 10. One DHCP allocation on
the private TAP matches the assigned guest MAC and IP. The running receipt
requires a QEMU running state and a reply from that private MAC. A power-off
receipt follows QEMU exit and local disk detach. VM deletion checks the
current assignment again before removing the backing image. Missing task
authorization withdraws the local instance and preserves its backing image.
[dnsmasq configuration](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)

The `vm-ha` lab profile gives each Nested KVM compute host three vCPUs, 6 GiB
of RAM and a 32 GiB root disk to hold a private prepared image. The three
separate Ceph guests use 24 GiB dedicated data disks. Both disk capacities
are sparse allocations on the development host. To conserve memory, start
only the required compute and storage hosts with `ocean-lab up -only`.

For a private-network regression check, compile `./internal/nodeagent` with
`go test -tags=e2e -c`. On a disposable Debian worker with `curl` and the
private `work0` fabric, run `TestVMNetworkOnDebianWorker` under root with
`OCEAN_E2E_VM_TAP=1`. The test verifies routing to the TAP, observes a denied
TCP connection in the ingress drop counter, and releases the fabric MAC on
cleanup.

The packaged lifecycle probe uses a disposable `vm-ha` lab with compute host
`farm-1-node-05`, the replicated Ceph pool, and an isolated loopback etcd
endpoint. Stage the private image files as `root:root` with mode `0600` on
that host. Configure the worker storage and workload fabric before the test.
The test enrolls the real worker and uses its host certificate for assignment
and status traffic. The pinned Azure CLI uses a test bearer identity for the
ARM operations. Use a Server Core fixture configured for `10.232.1.20`.

```sh
OCEAN_E2E_VM_WORKER_STATE="$LAB_STATE" \
  OCEAN_E2E_VM_ETCD="$DISPOSABLE_ETCD_ENDPOINT" \
  OCEAN_E2E_VM_DISK_PIN="$WINDOWS_DISK_SHA256" \
  OCEAN_E2E_VM_VARS_PIN="$WINDOWS_VARS_SHA256" \
  OCEAN_E2E_VM_AZ="$(command -v az)" \
  go test -mod=readonly -tags=e2e -count=1 -timeout=20m -v \
    -run '^TestPackagedVMWorker$' ./internal/controlplane
```

For a native storage checkpoint, run `prepare_windows_vm_checkpoint.ps1`
from an elevated PowerShell session inside a disposable Server Core fixture.
Use a unique test password. The script opens an encrypted SMB share on the
private NIC for the lab client at `10.232.1.21`. The probe account can write
under `data` and read the guest identity record. Windows refreshes that
record on startup with the system UUID, Windows machine GUID, hostname,
build and boot timestamp. Keep the image and test credentials private.
[Windows Server SMB shares](https://learn.microsoft.com/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps)

For the full `vm-worker` acceptance profile, also prepare `farm-1-node-06`
with the packaged service, storage configuration and `smbclient`. The test
will start this worker after initial provisioning and use it as the private
SMB client and the eligible replacement. Place the SMB username, password
and Windows computer name in the `smbclient` authentication file as
`username`, `password` and `domain`, respectively. Restrict it to mode `0600`.
The lab storage authority must have its existing Ed25519 key pair in
`$LAB_STATE/storage-pki`. Set `OCEAN_E2E_VM_FENCE_PROFILE` to the original
profile used to start the lab so the test can reboot the retired worker.

Use the same image and CLI variables as the single-worker probe, plus the
following inputs. The acceptance harness writes Markdown and TSV reports and
captures the cold boot, restart and fenced recovery durations.

```sh
OCEAN_E2E_PROFILE=vm-worker \
  OCEAN_E2E_VM_SMB_AUTH="$PRIVATE_SMB_AUTH_FILE" \
  OCEAN_E2E_VM_FENCE_PROFILE="$ORIGINAL_LAB_PROFILE" \
  go test -mod=readonly -tags=e2e -count=1 -timeout=30m -v \
    -run '^TestAcceptance$' ./tests/e2e
```

### Regional VM store probe

The optional `region.virtualMachines` configuration registers the catalog
for the regional ARM routes. Each `images` entry specifies `tenantId`,
`subscriptionId`, `blobUri`, `sizeGiB`, `imageSha256` and `firmwareSha256`.
The HTTPS URI identifies an operator-prepared image in that subscription.
Catalog lookups use the URI as an identifier. Workers use the paired digests
to verify the files staged by the operator. The optional `diskQuotaGiB`
sets the OS disk quota for each subscription in the region and defaults to
128 GiB. CPU and RAM count against the subscription's workload placement
policy. A VM retains these reservations while it is stopped.

Creating a private network interface reserves its IPv4 address in an
undelegated subnet. VM creation attaches the interface and reserves the OS
disk, worker and quotas in one transaction. Acknowledged VM deletion frees
the disk reservation and detaches the interface. Delete the interface to
release its private address. The VM, image and NIC belong to the same
resource group and subscription.

The regional controller persists signed power-off evidence for the exact
disk writer, withdraws the old assignment and waits for a ready KVM worker
in an allowed pool if capacity is full. It replaces the writer generation
and worker reservation together, preserving the disk, key, machine ID and
private IPv4 address. Start the worker only after obtaining its current
assignment. Lease expiry updates availability without moving the writer.

Run the transaction probe against an isolated loopback etcd. Set
`OCEAN_E2E_VM_AZ` to run the instance-view request with the pinned unmodified
Azure CLI. The probe uses seeded host availability and reports, and the
optional CLI request uses fixture authentication over TLS.

```sh
OCEAN_E2E_VM_ETCD=http://127.0.0.1:12379 OCEAN_E2E_VM_AZ="$(command -v az)" \
  go test -mod=readonly -race -tags=e2e -count=1 \
  -run '^TestRegionalVirtualMachineStore$' -v ./internal/controlplane
```

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

### Managed directory request

The development profile exposes directory requests when `region.managedDirectories`
sets `cpuMillis` and `memoryMiB` per controller. Enable tenant onboarding and
workload placement in the region. Sign in as the initial tenant administrator.
Submit `dnsName`, `netbiosName`, and `subnetId` in a JSON file. Use a private
subnet in the tenant subscription. DNS names use ASCII labels, and NetBIOS
names use up to 15 ASCII characters.

```sh
directory_url="https://arm.farm-1.ocean.test/ocean/tenants/$TENANT_ID/directory?api-version=2026-11-01"
az rest --method put --url "$directory_url" --body @directory-request.json
az rest --method get --url "$directory_url"
```

HTTP 202 means the region saved the request. The response contains an opaque
`directoryId`, a polling URL in the `Location` header, and the current
provisioning state. Identical requests return the same ID, including after an
interrupted response. A different configuration for the same tenant returns
HTTP 409. Ocean holds the target subnet while the
directory exists. It reserves CPU, memory, and private IPv4 addresses for
both controllers in one transaction, using distinct live compute hosts in
permitted pools. A directory-capable host advertises its locally installed
controller image, private network reconciler, and sufficient rootless UID
and GID mappings. An incomplete
placement stays in `Creating` for a later attempt.

Poll with `az rest --method get`. The response lists allocated controllers
with their tenant-private IPv4 addresses, DNS names, and readiness. The
directory reports `Creating` and `Pending` until both assigned controllers
verify their DNS and Kerberos-authenticated LDAP service and present the same
domain SID. Ocean records the completed provisioning and established domain
SID in regional etcd. Later outages change `availability` to `Degraded` or
`Unavailable` while `provisioningState` stays `Succeeded`. Recovery of both
controllers in the same domain restores `Available`.

Each node agent reports on its current placement over host mTLS. Revocation
or reassignment invalidates its observation. Reports expire after 15
seconds without a fresh observation. This status reflects the checks from
inside the controller and the regional assignment. Client reachability has
its own network and domain sign-in probes.

Build the controller image and install the same image on the selected hosts.
Set `enrollment.directoryImage` in each node agent config to its local
`sha256:<image-id>`. Each assigned host can retrieve its controller's
initial bootstrap credential over host mTLS. The region seals that credential
in etcd with the workload key. The agent passes it to Podman through stdin and
mounts it read-only with mode 0400. Each controller uses its own
generation-specific persistent volume on restart.

Before opening its AD listeners, a controller stages its local domain SID.
The node agent confirms it against the controller's current assignment over
host mTLS. The first primary commits the SID in regional etcd. Each startup
must match that SID. A restarted primary receives its expected SID and uses
its existing volume without the bootstrap password. An empty primary volume
can only provision during initial domain creation.

The primary provisions the domain. The replica uses the bootstrap credential
to join over Kerberos, then seeds SYSVOL with its machine account. It checks
the seeded policy ACLs before listening. A persistent join checkpoint lets the
replica retry the seed if the primary goes away during the initial copy.
The replica uses the writer's private AD DNS during bootstrap. Once
initialized, both controllers use their own resolver. Kerberos calls that
target a specific controller use its assigned address directly.
Each initialization checkpoint flushes the staged database and key files to
the controller volume. The first health check also flushes the TLS material
created by the Samba daemon during startup. The node agent can recreate an
uninspectable stopped container from its volume after an unclean shutdown.
Samba DRS replicates directory records in both directions. Both controllers
retain native change notifications and poll their peers every 15 seconds to
catch up after a late join or a disconnection.

The primary is the write endpoint for Group Policy and NETLOGON files. Every
ten seconds it captures SYSVOL with its security descriptors and exposes the
finished snapshot through an encrypted SMB share. The source permits the
replica's machine account from its assigned private address. The replica
uses its own Kerberos credential and verifies the domain SID and ACLs in a
staged copy. It waits for the corresponding Group Policy directory objects
and versions to arrive through DRS before atomically switching the local
SYSVOL directory. The replica serves SYSVOL and NETLOGON read-only and
continues serving its last verified policy snapshot during a source outage.

```sh
nice -n 10 podman build -t localhost/ocean-directory:lab packaging/samba
image_id=$(podman image inspect --format '{{.Id}}' localhost/ocean-directory:lab)
OCEAN_E2E_PROFILE=managed-directory OCEAN_E2E_SAMBA_IMAGE="sha256:${image_id#sha256:}" \
  go test -tags=e2e -count=1 -run '^TestAcceptance$' ./tests/e2e
```

The probe runs both controllers on one isolated rootless Podman network. It
checks that DNS stays closed until the staged SID is authorized. It verifies
that a fresh primary volume refuses to provision after the SID is established.
It compares employee identity and SYSVOL bytes, checks that the employee cannot
write the policy, and tests each controller with its peer stopped. The client
uses AD DNS for Kerberos and SMB discovery. The probe reopens both volumes
without bootstrap credentials and requires new group memberships to converge
in either direction within 45 seconds. It revokes a membership while the
primary is stopped and requires the restarted primary to observe the change
within 45 seconds. It also updates an existing Group Policy version through
SMB and the directory, checks the new bytes and a customized per-file deny
ACE on the replica within 65 seconds, and repeats the checks after the
primary stops and the replica restarts. The harness stores the Markdown
report, TSV, and client logs under `artifacts/e2e`.

The fixture also permanently removes its stopped replica container, cleans
up its directory and DNS metadata through the surviving controller, and
joins a replacement replica on an empty volume. It checks a fresh controller
account GUID and the original domain and employee identities, membership,
policy version, and ACL. The replacement then serves clients with the primary
stopped. This recovery run uses controlled Podman stops on one host.

To enable fenced controller replacement, configure
`region.directoryFencePublicKeyFile` with the out-of-band fencing authority's
Ed25519 public key in PEM format. Configure the same key on every regional
API replica. The authority signs an attestation after observing the exact
failed host is powered off and preventing it from restarting outside Ocean.
The JSON attestation includes `action: ReplaceDirectoryReplica`,
`tenantId`, `subscriptionId`, `directoryId`, `hostId`, `placementId`,
`generation`, `observation: PoweredOff`, and an RFC 3339 `observedAt`.
Encode the original signed bytes and signature as base64 in the envelope
fields `attestation` and `signature`.

```sh
replace_url="https://arm.farm-1.ocean.test/ocean/tenants/$TENANT_ID/directory/replaceReplica?api-version=2026-11-01"
az rest --method post --url "$replace_url" --body @signed-directory-fence.json -o none
az rest --method get --url "$directory_url"
```

The initial request requires a matching fence no more than two minutes
old and an expired or removed host availability record. HTTP 202 means
Ocean recorded the signed evidence and revoked the failed host's identity.
The primary removes the retired replica's AD and DNS metadata. Its node
agent acknowledges cleanup through the current host assignment. The
regional reconciler then assigns another eligible host, preserving the
replica's private IP and transferring the capacity reservation. The
replacement rejoins the existing domain with its established SID and
the sealed directory join credential. It publishes readiness after the
data-plane probes pass. Replaying an accepted envelope preserves the
original replacement.

To replace the current writer, sign an attestation with
`action: ReplaceDirectoryPrimary` and submit it to the writer replacement
endpoint. The attestation identifies the writer's current host, placement and
generation. The survivor needs a recent health report for the established SID.

```sh
replace_url="$directory_url_base/replacePrimary?api-version=2026-11-01"
az rest --method post --url "$replace_url" --body @signed-primary-fence.json -o none
az rest --method get --url "$directory_url"
```

Ocean revokes the fenced writer and suspends delegated join and Graph tasks
while the survivor takes over. The survivor verifies its local SYSVOL against
the replicated policy versions, takes ownership of all seven FSMO roles, and
removes the failed controller's AD and DNS records before serving writable
SYSVOL. Its mTLS acknowledgement and fresh health report permit writer tasks
and placement of a new replica. DNS names and IP addresses remain tied to
the controller slots. The replacement uses the old writer's slot, a new
generation, and a separate host and volume. Directory status identifies the
controller designated for Ocean-managed writes once it has acknowledged
promotion.

AD replication is asynchronous. A valid fence establishes that the old
writer is off. The surviving domain reflects the changes that reached it.
If the local GPO data and version disagree, Ocean withholds writer promotion.
When the replica is still serving, it remains available with read-only
SYSVOL while the inconsistency is investigated.
Measure the replication gap and recovery time under the intended load before
assigning a service guarantee.

The same profile runs the `az rest` request and status commands with Azure
CLI 2.93.0 against a loopback HTTPS contract fixture and a signed fixture
token. The runtime and CLI probes are independently selectable with
`OCEAN_E2E_CASES=WORKPLACE-04` or `OCEAN_E2E_CASES=WORKPLACE-05`.
Add `WORKPLACE-06` to `OCEAN_E2E_CASES` and set
`OCEAN_E2E_DIRECTORY_ETCD` to an isolated etcd endpoint to exercise regional
fencing, promotion admission and placement with simulated host identities and
power evidence. Select `WORKPLACE-12` to exercise actual Samba and SYSVOL writer
promotion and replacement with controlled Podman stops on one host. A
replacement replica needs a valid directory join credential. The physical
fencing and client sign-in gates are tracked in [issue #50](https://github.com/Weichwolf/ocean/issues/50).

### Regional delegated machine joins

The tenant administrator can issue a join authorization with the stock Azure
CLI. Use a new lowercase UUID for the authorization and a private JSON file
with `machineName`, `expiresAt`, and `password`. Use an uppercase NetBIOS
computer name, a Unix timestamp 15 seconds to 10 minutes in the future, and a
random password of 32 to 128 printable ASCII characters.

```sh
join_url="$directory_url_base/joinAuthorizations/$AUTHORIZATION_ID"
az rest --method put --url "$join_url?api-version=2026-11-01" \
  --body @"$PRIVATE_STAGE_REQUEST" -o json
az rest --method get --url "$join_url?api-version=2026-11-01" -o json
az rest --method post --url "$join_url/close?api-version=2026-11-01" -o json
```

Set `directory_url_base` to the managed directory URL before its query string.
Wait for `Ready`, then use its `userPrincipalName` and the submitted password
to join the named computer. After the guest verifies its secure channel,
submit the close request and read the status until it is `Closed`. A
premature close returns to `Ready` once the writer rejects the operation.
Other outcomes are `Rejected` for a rejected stage and `Expired` at the
authorization deadline. Replay the same UUID, name, and deadline to read the
original authorization. The first accepted password applies for its lifetime.

The region serializes join actions per directory. The password is sealed
while the request waits on a short-lived etcd key. Only the certified writer
and its current assignment generation can read the job. The agent passes the
request to Samba on standard input. The result and audit records contain
authorization metadata. Protect the local request file and avoid debug
logging when transmitting its body.

Run `WORKPLACE-09` with the same images as `WORKPLACE-08`, plus
`OCEAN_E2E_DIRECTORY_ETCD` pointing to a disposable etcd endpoint and pinned
Azure CLI 2.93.0. The case uses a loopback TLS issuer and regional API, a real
mTLS worker, a single local Samba writer, and the Debian client fixture.

### Delegated join on the directory writer

The controller can prestage a computer and issue permissions to a temporary AD
principal for that computer. On the first successful staging operation, Ocean
sets the domain's default workstation quota to zero so a regular principal
cannot provision a different machine through the default quota. The temporary
principal receives only the object-level rights needed for the intended join.

Send `stage-join` a private JSON request on standard input. Include
`requestId` as a lowercase UUID, `machineName` as an uppercase NetBIOS
computer name, `expiresAt` as a Unix timestamp up to ten minutes in the
future, and `password` as a generated random password of 32 through 128
printable ASCII characters. Repeat an in-flight request with the same fields.
The controller prints the UPN and authorization metadata without the password.
Deliver the join password through a private channel.

```sh
nice -n 10 podman exec -i "$CONTROLLER" /usr/bin/python3 \
  /usr/local/lib/ocean-directory/controller.py stage-join <"$PRIVATE_STAGE_REQUEST"
adcli join --domain "$DOMAIN" --domain-controller "$CONTROLLER_DNS" \
  --computer-name "$MACHINE" --host-fqdn "$MACHINE_FQDN" --login-user "$JOIN_USER" \
  --stdin-password <"$PRIVATE_JOIN_PASSWORD"
adcli testjoin --domain "$DOMAIN" --domain-controller "$CONTROLLER_DNS"
nice -n 10 podman exec -i "$CONTROLLER" /usr/bin/python3 \
  /usr/local/lib/ocean-directory/controller.py close-join <"$PRIVATE_CLOSE_REQUEST"
```

Use the UPN's account name as `JOIN_USER`. Keep the temporary files
operator-only and remove them after the procedure. The close request contains
the original request ID, machine name, and expiry. Close after the client
verifies its machine credential. Closing disables the principal and removes
its ACLs. If unused, the authorization expires in AD and the writer removes
its ACLs. The credential is active until close or expiry. This procedure runs
locally on the designated writer. Validation from Windows guests is tracked
in [issue #50](https://github.com/Weichwolf/ocean/issues/50).

Run `WORKPLACE-08` with the controller image and the isolated Debian client
fixture built from `tests/e2e/testdata/workloads/domain-join-client`. Supply both
local image IDs, including their `sha256:` prefix.

```sh
client_id=$(nice -n 10 podman build --quiet \
  tests/e2e/testdata/workloads/domain-join-client)
OCEAN_E2E_PROFILE=managed-directory OCEAN_E2E_CASES=WORKPLACE-08 \
  OCEAN_E2E_SAMBA_IMAGE="sha256:${image_id#sha256:}" \
  OCEAN_E2E_ADCLI_IMAGE="sha256:${client_id#sha256:}" \
  go test -tags=e2e -count=1 -v -run '^TestAcceptance$' ./tests/e2e
```

### Standalone domain recovery

On the designated SYSVOL writer, run `backup-domain` with a current domain
Administrator password on standard input. Capture standard output as a
private file. Keep the command status and diagnostics separate from the
archive. The archive contains the native Samba database backup and the
verified policy files and ACLs. The command rejects a policy change observed
while the native backup runs.

```sh
umask 077
nice -n 10 podman exec -i "$CONTROLLER" /usr/bin/python3 \
  /usr/local/lib/ocean-directory/controller.py backup-domain \
  <"$ADMINISTRATOR_PASSWORD_FILE" >"$BACKUP_STAGING/directory.tar"
sha256sum "$BACKUP_STAGING/directory.tar"
openssl cms -encrypt -aes-256-gcm -binary -in "$BACKUP_STAGING/directory.tar" \
  -outform DER -out "$BACKUP_STAGING/directory.cms" "$BACKUP_RECIPIENT_CERT"
```

Store the encrypted archive outside both controller hosts. Keep the
decryption key separately and record an authenticated copy of the archive
SHA-256, directory ID, DNS name, NetBIOS domain name and SID. Remove plaintext
staging after encryption. The archive contains password hashes and machine
credentials. Restrict access to the backup and its decryption key.

For a full-domain disaster, permanently isolate all former **controller**
instances and their volumes from the tenant network before making a recovery
controller reachable. Decrypt the archive into private staging. With a
compatible controller image, use a dedicated, empty volume at
`/var/lib/ocean-ad`, start the one-shot container with `--network none`, and
run `restore-domain <recorded-sha256>` with the decrypted archive on standard
input. Set the original `OCEAN_AD_DIRECTORY_ID`, `OCEAN_AD_DNS_NAME`,
`OCEAN_AD_NETBIOS_NAME`, and `OCEAN_AD_EXPECTED_SID`. Set the recovery
controller's private IP in `OCEAN_AD_ADDRESS` and a distinct NetBIOS-safe
hostname in `OCEAN_AD_RECOVERY_NAME`. Use the same UID/GID mappings as the
controller runtime. Recovery removes the old controller accounts and rotates
the Kerberos ticket-granting keys. It also revokes outstanding delegated join
accounts and removes their ACLs. Clients need fresh tickets.

After the isolated restore succeeds, start the recovery controller using the
same volume and settings, with `OCEAN_AD_REQUIRE_AUTHORIZATION=1`. Confirm the
recorded SID before responding to the startup challenge. Check DNS, fresh
Kerberos authentication, the existing member's secure channel, group
membership and SYSVOL access before restoring client routing. This
operator procedure restores a standalone controller. Regional orchestration
can rebuild the pair using the same backup format.

Run the local probe using the built controller image. The probe encrypts a
backup, deletes both original controller volumes, rejects a corrupted archive
and checks continued Samba member trust from its original client state.

```sh
OCEAN_E2E_PROFILE=managed-directory OCEAN_E2E_CASES=WORKPLACE-07 \
  OCEAN_E2E_SAMBA_IMAGE="sha256:${image_id#sha256:}" \
  go test -tags=e2e -count=1 -v -run '^TestAcceptance$' ./tests/e2e
```

### Coordinated directory recovery

The site fencing authority must verify that both assigned controller hosts
are powered off and keep their old volumes isolated. Sign one attestation
with `action: RecoverDirectory`, the tenant, subscription and directory IDs,
a new lowercase UUID in `recoveryId`, the plaintext backup digest in
`backupSha256`, and `observation: PoweredOff` with an RFC 3339 `observedAt`.
Put both current assignments in `controllers` in slot order with their
`hostId`, `placementId` and `generation`. Encode the signed bytes and
Ed25519 signature in the same base64 envelope as controller replacement.

```sh
recovery_url="https://arm.farm-1.ocean.test/ocean/tenants/$TENANT_ID/directory/recoveries/$RECOVERY_ID?api-version=2026-11-01"
az rest --method put --url "$recovery_url" --body @signed-directory-recovery.json
az rest --method get --url "$recovery_url"
```

`Fenced` means both old host identities were revoked and their active
delegated authorizations were invalidated. The regional reconciler reserves
two distinct eligible hosts and keeps the tenant's IP and quota reservations.
When the operation shows `AwaitingRestore`, deliver the decrypted archive to
its `writerHostId` through the site's private operator channel. On that host,
stage the archive as a regular file owned by the agent with mode 0600 at
`<enrollment.stateDirectory>/directory-recovery/<recoveryId>.tar`. Publish it
with an atomic rename once the copy and checksum verification have completed.
Keep the encrypted original and decryption key independently available.

The agent restores into its new private volume in an offline container.
It checks the signed digest, the component digests and
the directory SID. The restore resets the built-in administrator credential
to a fresh value sealed by the region and removes old delegated grants. The
new writer requests regional startup authorization before listening.
The standby joins the restored domain once the writer reports healthy.
Both controllers get new names and generations. Clients keep their existing
DNS addresses and rediscover the new names through AD DNS.

Ocean resumes Graph and new join authorization work after both controllers
report the original SID. The status becomes `Succeeded` and the operation
can be replayed with the same signed envelope. Remove the site-staged
plaintext after successful recovery. Issue fresh join IDs for machines that
still need to join. Clients and credentials created after the backup can
require reconciliation because the restore returns the directory to the
captured state.

Use `WORKPLACE-13` to recover a new pair from encrypted media and measure
recovery on one lab host. `WORKPLACE-05` exercises the CLI contract and
`WORKPLACE-06` exercises the regional transaction with signed fixture
evidence and disposable etcd. The Windows and independent-host recovery
gates are tracked in [issue #50](https://github.com/Weichwolf/ocean/issues/50).

### Fresh directory with packaged agents

`WORKPLACE-16` provisions a new Samba AD domain through the regional ARM
API. It uses a disposable Debian KVM lab with two controller hosts and a
separate Debian client. Start only the three guests in farm 1. Build the
agent package and export the pinned local Samba image as an OCI archive.

```sh
make deb-agent
bin/ocean-lab up -state "$OCEAN_DIRECTORY_LAB" -profile lab/profiles/domain-join.yaml \
  -image "$DEBIAN_QCOW2" -only farm-1-node-01 -only farm-1-node-02 -only farm-1-node-03
python3 -B lab/prepare_managed_directory.py --state "$OCEAN_DIRECTORY_LAB" \
  --package "$AGENT_DEB" --samba-archive "$SAMBA_OCI_ARCHIVE"
OCEAN_E2E_PROFILE=managed-directory OCEAN_E2E_CASES=WORKPLACE-16 \
  OCEAN_E2E_PACKAGED_DIRECTORY_STATE="$OCEAN_DIRECTORY_LAB" \
  OCEAN_E2E_PACKAGE="$AGENT_DEB" OCEAN_E2E_DIRECTORY_ETCD="$DISPOSABLE_ETCD_URL" \
  OCEAN_E2E_SAMBA_IMAGE="sha256:${image_id#sha256:}" \
  go test -tags=e2e -count=1 -v -run '^TestAcceptance$' ./tests/e2e
```

The probe supplies a disposable HTTPS enrollment endpoint and test OAuth
issuer. It starts the installed rootless node agent and system network
service on both hosts. The stock CLI submits and replays the request and
checks the scope of access. The Debian client uses the assigned private
addresses to verify AD discovery, acquire a fresh Kerberos ticket from
each controller, and read the original SYSVOL file through SMB. The probe
powers off and restarts each controller separately. The report records the
API degradation interval and confirms the surviving data path and the
original placement on return. All three guests run on one KVM host.

### Regional recovery with existing Windows members

`WORKPLACE-14` combines the regional ARM and enrollment handlers, etcd, two
real Debian node agents, and the existing Windows Server Core and Windows 11
members. Use a disposable `domain-join` lab with only
`farm-1-node-01` and `farm-1-node-02` selected and running. Keep both original
member disks and the independent backup in private storage. Use writable
overlays and the original firmware and TPM state when reusing the members.
Their original `10.232.1.20` and `10.232.1.21` addresses must reach the lab's
isolated workload network.

Install Podman and its rootless UID mapping tools on the Debian fixtures,
load the same pinned Samba image under the `ocean` account on each, and run
`make build` locally. Before the Windows guests boot, attach
`lab/verify_windows_directory_recovery.ps1` on their `OCEAN_PROBE` media.
For resumed overlays, build the probe ISO while the guests are off.

Decrypt the backup into a private file. Put `metadata.json` beside it with
the original `identity` object from the bundle manifest, the plaintext
`archiveSha256`, and `policySha256` for
`ad.ocean.test/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI`
from the archived SYSVOL. The test submits a signed fixture fence for the
archived source slots and uses the guest workload NICs for the two restored
controller addresses. The node agents enroll over the lab-only QEMU host
gateway and use their certificates for assignments and startup authorization.

```sh
OCEAN_E2E_PROFILE=managed-directory OCEAN_E2E_CASES=WORKPLACE-14 \
  OCEAN_E2E_WINDOWS_RECOVERY_STATE="$OCEAN_RECOVERY_LAB" \
  OCEAN_E2E_WINDOWS_RECOVERY_ARCHIVE="$PRIVATE_BACKUP_TAR" \
  OCEAN_E2E_DIRECTORY_ETCD="$DISPOSABLE_ETCD_URL" \
  OCEAN_E2E_SAMBA_IMAGE="sha256:${image_id#sha256:}" \
  go test -tags=e2e -count=1 -v -run '^TestAcceptance$' ./tests/e2e
```

During the run, read `recovery-phase.json` from the lab state. Sign into
both existing members as the restored fixture administrator and run the
probe in an elevated Windows PowerShell session. The fixture writes its
temporary administrator password to the private
`recovery-fixture-admin.secret` in the lab state. Pass the recovery ID,
stage, controller, and address from the phase file. Run `-Action Machine`
in both stages. After the survivor stage's machine check, sign out and sign
in as the original fixture employee and run `-Action Employee` on both
guests. The test changes the phase after it observes both initial machine
records, powers off the recovered writer VM, and sees `Degraded` through
the regional API. Its runner collects only the records for that recovery
ID and saves the report in the acceptance evidence.

This lab exercises the Windows data path and real regional recovery on
one KVM host. Production fencing and independent physical failure domains
have separate acceptance gates.

### Regional Graph changes on Windows

`WORKPLACE-15` uses the same disposable recovery lab and independent archive.
Start the two Debian nodes and the existing Server Core member. Attach
`lab/verify_windows_directory_graph.ps1` to the member's `OCEAN_PROBE` media
before boot. Run the command above with `OCEAN_E2E_CASES=WORKPLACE-15`.

After recovery, the test signs in with the stock Azure CLI to the isolated
fixture OAuth issuer. It creates a user and security group through the regional
Graph API and checks their GUIDs and SIDs directly on the writer. The group's
test share contains a per-run value. The certified node agent applies the
directory changes.

Sign into the existing Server Core member as the temporary recovery
administrator and open elevated Windows PowerShell. Get its private password
from `recovery-fixture-admin.secret`. When `graph-phase.json` appears, invoke
the probe once for each new stage:

```powershell
$media = Get-Volume -FileSystemLabel OCEAN_PROBE
& ($media.DriveLetter + ':\verify_windows_directory_graph.ps1') `
  -RunId $runId -Stage $stage -Controller $controller -Address $address -GroupSid $groupSid
```

Use the fields from the phase file. Enter the password from
`graph-fixture-initial.secret` or `graph-fixture-rotated.secret` as indicated by
the phase's `credential` field. The probe starts a new Windows logon session,
verifies the actual group SID and requests a fresh CIFS ticket. It checks the
SMB result before membership, with membership, and after revocation. It also
checks sign-in after the CLI rotates the password and disables the user.
The acceptance case verifies the original account's disabled flag directly
in Samba and records the Windows logon error code.
Store the secret files in the private lab directory and keep them out of
test artifacts. The serial records and acceptance evidence contain only the
test identities and results.

## Tenant directory users

The initial tenant administrator uses Microsoft Graph `v1.0` with a Graph
access token. Lists support an exact UPN or a display-name prefix, with server
paging. Object lookup accepts a UUID or a UPN. The administrator can change a
user's display name, mail alias, login status, and password.

For a tenant with a managed domain, `az ad user create`, `list`, `show` and
`update` operate on Samba accounts in `OU=Ocean Workforce Users`. Use the
domain's DNS suffix in the UPN. The account name starts with an ASCII letter
and can contain up to 20 letters, digits, dots, underscores, or hyphens.
Graph uses the AD object GUID as the ID and derives `mailNickname` from the
configured mail alias at the AD domain. Built-in accounts, privileged
system accounts, and delegated join principals are outside the workforce
scope. Disable a managed account with `az ad user update --account-enabled
false`. The managed user profile rejects permanent user deletion.

The certified writer receives a sealed, short-lived operation through
the host's mTLS connection. A successful response requires the native
directory result. Requests wait for that result and return an error if
the writer is unavailable. A concurrent request for the same directory can
receive HTTP 429 and `Retry-After`. The writer's audit records contain
operation metadata. Existing Keycloak users require a separate migration.
Run `WORKPLACE-10` with the prerequisites for `WORKPLACE-09` to check the
managed profile with Azure CLI and fresh Debian Kerberos requests.

For tenants without a managed domain, Keycloak continues to store the
directory user and enforce sign-in. The `az ad user delete` command is
available in that profile. The original tenant administrator can update
their Keycloak profile and password and must remain enabled. Ocean declares
the Graph display name and alias as managed Keycloak attributes writable by
its admin API. Realm-scoped device login uses the bounded offline session
policy configured at registration. [Keycloak user profiles](https://www.keycloak.org/docs/latest/server_admin/index.html#user-profile)

Run `python3 lab/verify_onboarding.py --state "$OCEAN_LAB_STATE" --directory-users` to exercise the user lifecycle with two freshly onboarded tenants. The check verifies that updates preserve the mail alias, regular users are denied directory administration, and deleted users cannot start a new login. Evidence is written to `evidence/graph-users.json`.

## Managed security groups

`az ad group create`, `list`, and `show` manage global security groups in
`OU=Ocean Workforce Groups`. Graph uses the native AD object GUID as the ID
and the AD account name as the mail nickname. The corresponding AD group
SID can be used in ACLs. Managed groups contain direct workforce users from
the same domain.

| CLI operation | Graph v1.0 requests |
| --- | --- |
| `az ad group create` | `GET /groups` with a display-name and mail-nickname equality filter, then `POST /groups` on a miss |
| `az ad group list` | `GET /groups` with optional display-name prefix and pagination |
| `az ad group show --group <id>` | `GET /groups/<id>` |
| `az ad group member add` | `POST /groups/<id>/members/$ref` with a member object reference under the configured Graph origin |
| `az ad group member list` | `GET /groups/<id>/members` with pagination |
| `az ad group member remove` | `DELETE /groups/<id>/members/<member-id>/$ref` |

Repeated membership adds and removals preserve the same AD membership.
Use a fresh authentication session to observe new group permissions. Run
`WORKPLACE-11` to exercise the stock CLI workflow and a real Kerberos SMB
access check against a share restricted to the native group.

## Tenant applications and service principals

Use `az ad app create --display-name <name>` to register a single-tenant application, then `az ad sp create --id <app-id>` to provision its service principal. The application object ID, app ID, and service principal object ID are distinct. The app ID identifies the client during `az login --service-principal`. Access to a subscription requires a separate authorization grant.

Use `az ad app credential reset --id <app-id> --append` to add a password credential. Each password has its own identifier and validity interval. The add operation returns the secret once. Directory reads expose credential metadata. The regional store keeps a keyed verifier for each secret and uses conditional updates for concurrent credential changes. To remove a password, use `az ad app credential delete --id <app-id> --key-id <key-id>`. Removed and expired passwords are denied at the next authentication. The supported validity limit is two years, with at most 64 password credentials per app. [Graph addPassword](https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0)

Run `python3 lab/verify_onboarding.py --state "$OCEAN_LAB_STATE" --directory-users --directory-apps` to exercise these commands. The run verifies separate ARM and Graph tokens from fresh CLI caches, rejects cross-tenant reads, signs in with both secrets after append, and checks that the remaining secret works after revocation. Inspect `evidence/graph-applications.json` for the object IDs and assertions.

## ARM resource groups

Run `python3 lab/verify_arm.py --state "$OCEAN_LAB_STATE"` after deploying the control plane and installing the pinned CLI in the operator guest. The verifier runs the [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv) with a fresh CLI cache per tenant. It creates and removes the test groups and records pagination, concurrent writes, tenant isolation, and negative API responses in `evidence/arm-resource-groups.json` under the lab state.

Resource groups use ARM API version `2024-11-01`. The supported create request accepts the regional location and up to 50 string tags. Names are case-insensitive and reads preserve the casing from creation. Tag values are returned as supplied. A create at an existing name updates its tags and preserves the location. List has continuations on the configured ARM origin.

`az provider show --namespace Microsoft.Resources` reports the implemented resource group type, its API version, and the available regional location. Unsupported namespaces return `InvalidResourceNamespace`.

## Scoped ARM roles

The tenant administrator can assign the built-in Reader role at an existing resource group scope. Assignees are tenant users or service principals identified by their directory object IDs. The supported CLI commands and parameters are in the [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv). Azure CLI 2.93.0 uses `2022-04-01` for role assignments and `2022-05-01-preview` for role definitions. Provider discovery for `Microsoft.Authorization` publishes these versions. [Role assignment API](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/create?view=rest-authorization-2022-04-01) · [Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general#reader)

Readers discover the parent subscription and see groups and assignments within their grants. The API consults the current grant state for each request, including requests carrying tokens issued before revocation. An assignment and its access index commit or delete together. Group deletion removes its scoped grants and assignments in the same transaction. Group mutations, role assignment mutations, and denied privileged actions persist actor, action, target, result, and time in the tenant's audit keyspace. etcd supplies the commit revision.

Run `python3 lab/verify_arm.py --state "$OCEAN_LAB_STATE" --rbac` to exercise grant creation, listing, deletion, and continued use of a token issued before revocation. It verifies cross-tenant and out-of-scope denials, rejects altered and wrong-audience tokens, and checks the audit revisions in etcd. The run writes `evidence/arm-rbac.json` under the lab state.

## Durable ARM operations

Resource group deletion returns HTTP 202 with `Azure-AsyncOperation`, `Location`, and `Retry-After`. The response URLs use the configured ARM origin. The operation status endpoint reports `InProgress`, `Succeeded`, or `Failed`. The independent result endpoint returns HTTP 202 while waiting and HTTP 204 on success. The group reports `Deleting` while its operation is pending, and changes to its configuration return `ResourceGroupBeingDeleted`. [ARM asynchronous operations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations)

The group marker, operation record, retry reference, and pending queue entry commit together in the regional quorum. A repeated delete returns the same polling URLs until the group is recreated. A fresh group with the same name has independent state. Completion removes the group and its scoped role grants, records the audit event, and publishes the terminal outcome in one transaction. The initiating subscription administrator can poll the operation.

Every regional API replica reconciles pending operations by default. A replica configured with `region.operationController: false` serves the API while other replicas reconcile operations. Run `python3 lab/verify_operations.py --state "$OCEAN_LAB_STATE"` on the dedicated lab to exercise a controller outage, concurrent retries after a discarded response, an API process crash, and recovery on another controller. Inspect `evidence/arm-operations.json` for the operation ID, etcd revisions, and observed state transitions.

## ARM resource inventory

The subscription and resource-group inventory endpoints use `2024-11-01`. The CLI can combine exact group, type, name, and location filters. The supported expansions are `createdTime`, `changedTime`, and `provisioningState`. Pagination links contain the last visible record and keep the selected filter and expansion. Resource lookup uses the provider's API version and the case-insensitive ARM resource ID. [ARM resource listing](https://learn.microsoft.com/en-us/rest/api/resources/resources/list) · [ARM resource lookup](https://learn.microsoft.com/en-us/rest/api/resources/resources/get-by-id)

Provider implementations publish their public resource projections to the regional store. Inventory reads and the scope grants used to authorize them share an etcd revision. A resource group delete removes its inventory entries and role grants with the terminal operation state. Provider-specific controllers own data-plane cleanup and capacity release.

Run `python3 lab/verify_inventory.py --state "$OCEAN_LAB_STATE"` to exercise the selected CLI inventory commands. The lab publishes tagged test projections through the internal resource store and reads a real role assignment by its ARM ID. It checks paging, nested IDs, unsupported API requests, Reader scope, revocation, and group cleanup. The result is stored in `evidence/arm-inventory.json`. Provider acceptance runs exercise inventory against live workloads and reservations as those providers are enabled.

## ARM virtual networks and subnets

Azure CLI 2.93.0 uses `2025-07-01` for `az network vnet` and `2024-07-01` for `az network vnet subnet`. The selected commands create, show, list, and delete networks and subnets. A subnet can be declared with its virtual network or added by a separate request. The supported subnet update changes its address prefixes. [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv) · [Virtual network REST API](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/virtual-networks/create-or-update) · [Subnet resource schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2024-07-01/virtualnetworks/subnets)

Address spaces use canonical private IPv4 prefixes. A subnet prefix must fit inside the network's address space and contain at least eight addresses. Subnet address ranges within the same virtual network are disjoint. A network and its subnets share one revision so concurrent writes check those constraints against a consistent configuration. The same address range can be used in independent tenant networks.

Run `python3 lab/verify_network.py --state "$OCEAN_LAB_STATE"` from the host after deploying the control plane and the pinned CLI. It checks the ARM lifecycle with fresh tenants, competing subnet reservations, inventory, and resource group cleanup. It writes `evidence/virtual-network-arm.json`. Workload attachment, packet filtering, and egress failover are verified by their own acceptance scenarios.

The verifier also exercises security groups and named rules through `az network nsg` on API version `2022-01-01`. The supported custom rules use inbound or outbound priority, allow or deny, IPv4 or wildcard address selectors, and TCP, UDP, ICMP, or wildcard protocols. Port constraints apply to TCP and UDP. The group returns the six read-only default rules alongside custom rules when requested. [Security rules resource schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups/securityrules) · [Network security group defaults](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)

Attach or detach a security group with `az network vnet subnet update --network-security-group`. The security group must exist in the VNet's resource group and subscription. Each VNet can reference up to sixteen distinct security groups. The regional store commits the attachment, reverse link, and audit together. A group with a live subnet reference cannot be deleted through the security group endpoint. Resource group cleanup removes both sides of the association.

Add `--firewall-node farm-1-node-05` to the verifier command to run the packet tests in a disposable Debian KVM guest. The host running the verifier uses Python 3 with PyYAML. The guest needs the installed node agent, nftables, curl, Python 3, and access to the pinned BusyBox fixture. The test exports the configured Azure CLI rules from the ARM view, attaches a rootless Podman fixture to an isolated router namespace, and applies the rules through an atomic nftables transaction. It checks that rule priority controls ingress and egress, unassigned addresses and protected management prefixes are blocked, and overlapping tenant networks stay isolated. Find the results in `evidence/routed-podman-firewall.log`. [nftables manual](https://www.netfilter.org/projects/nftables/manpage.html)

## Static IPv4 and NAT gateway

Configure the same `region.publicIPv4Addresses` entries on each regional API replica. Supply up to 256 distinct IPv4 addresses approved for the region. The first startup commits the regional pool. Later startups require the same set so every replica makes decisions against one inventory. Upgrade the API replicas before enabling the pool when rolling forward from a release without public IP support.

Azure CLI 2.93.0 uses API version `2025-09-01` for regional Standard static IPv4 addresses and `2025-07-01` for Standard NAT gateways with one public address. Allocation commits with resource creation, stays fixed across retries, and returns to the pool when the resource or its resource group is deleted. A public address can have one owning association at a time. Subnets attach or detach a same-group gateway through `az network vnet subnet update --nat-gateway` on API version `2024-07-01`. A subnet attachment keeps the NAT gateway in use, and the gateway keeps its public address in use. [Public IP template schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2025-09-01/publicipaddresses) · [NAT gateway template schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2025-07-01/natgateways)

```sh
python3 lab/enrollment.py --state "$OCEAN_LAB_STATE" --node farm-1-node-03 \
  --public-ipv4 198.51.100.20 --public-ipv4 198.51.100.21
python3 lab/verify_egress.py --state "$OCEAN_LAB_STATE" --pool 198.51.100.20 198.51.100.21 \
  --gateway-node farm-1-node-05
```

Use a dedicated lab with an empty two-address pool for this verifier. The optional packet stage needs nftables and Keepalived alongside the node agent, curl, Python, and the pinned BusyBox fixture. It runs two gateway namespaces on one disposable KVM guest, with separate tenant and external links. The external HTTP observer reports the source address of a fresh TCP connection before and after the active gateway loses its uplink. The test gives the standby eight seconds to recover and records the measured time. The verifier writes `evidence/public-ip-nat-arm.json` and `evidence/fixed-egress-packet.log`. Gateway fencing, automatic workload attachment, and the Functions egress case need their deployment-level runs.

The `egress-ha` profile adds a separate external VDE segment. Two gateway guests and the source observer are attached to it. The third node hosts the pinned rootless Podman workload. Prepare both gateway guests with Debian's `nftables` and `keepalived` packages. Install the packaged ocean agent on the worker and use the same pinned fixture and host Python dependencies as the single-guest verifier.

```sh
OCEAN_EGRESS_STATE=$(mktemp -d /tmp/ocean-egress-ha.XXXXXX)
./bin/ocean-lab up -state "$OCEAN_EGRESS_STATE" -profile lab/profiles/egress-ha.yaml -image "$OCEAN_LAB_IMAGE"
# Prepare the gateway and worker packages in the new guests before the test.
python3 lab/verify_egress_hosts.py --state "$OCEAN_EGRESS_STATE" \
  --reservation "$OCEAN_LAB_STATE/evidence/public-ip-nat-arm.json"
```

The verifier installs the compiled `ocean-gateway` role command and a lab Keepalived service. Each gateway begins with a closed nftables forwarding set. The Keepalived owner activates forwarding after the external address is installed. The test checks the standby's NAT counter during a probe routed directly to it, confirms that tenant traffic cannot reach a live management-only fixture, and powers off the active KVM guest. It then checks the source address and counts attempts against the eight-second recovery budget. The original gateway reboots and rejoins as standby. This run covers sudden guest loss on a shared lab virtual switch. Network-partition fencing and Function App egress are separate acceptance scenarios. Evidence is written to `evidence/fixed-egress-hosts.json`. Use `--reset` to restart the test guests before repeating this verifier in the same disposable profile.

## Network placement and host assignment policy

A compute placement can name a subnet in its own subscription. The region reserves a private IPv4 address, tenant and host capacity, and one placement generation in the same transaction. Address selection skips the first four and last address of each IPv4 prefix. A repeated placement request returns its original address and generation. Release requires the current generation and comes after the caller has stopped the workload. Subnet address changes and deletion are blocked while the subnet has placements. Resource group deletion observes the same guard. [Azure IPv4 address allocation](https://learn.microsoft.com/en-us/azure/virtual-network/private-ip-addresses)

The enrolled host reads its network policy over the existing mTLS assignments endpoint. The assignment, owning generation, VNet address space, subnet gateway, current security rules, and optional NAT address share one regional read revision. If an assignment loses ownership of its address, the endpoint returns its assignment with `networkUnavailable` and omits its network policy.

The Debian package provides a system service, `ocean-network-agent.service`, for router-side firewall reconciliation. The operator provides a root-owned `/etc/ocean-agent/network.json` with no group or other write permissions and starts the service. Each endpoint entry names a routing namespace and veth plus the tenant, subscription, placement ID, and placement generation. The routing setup must give each workload a point-to-point link and keep forwarding disabled until the service has installed the link's policy. The service uses the enrolled host certificate to read assignments. Podman continues to run under the unprivileged `ocean-agent` account.

```json
{
  "protectedPrefixes": ["10.231.1.0/24"],
  "endpoints": [
    {
      "namespace": "tenant-router",
      "interface": "work0",
      "tenantId": "<tenant-id>",
      "subscriptionId": "<subscription-id>",
      "id": "<placement-id>",
      "generation": "<placement-generation>"
    }
  ]
}
```

The service applies policy in an atomic nftables transaction and renews an eight-second kernel deadline from valid assignments. A missing or revoked assignment replaces the endpoint's rules with a drop policy. The kernel also blocks forwarded traffic in both directions if the process stalls and the deadline expires. Operators can set `internetPrefixes` for reachable external destinations when a placement has an assigned NAT gateway. Remove an endpoint from the registry and retire its workload link before reusing that endpoint for another placement. [nftables element timeouts](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts)

Run `python3 lab/verify_network_placement.py --state "$OCEAN_LAB_STATE" --pool 198.51.100.20 198.51.100.21` in the dedicated regional lab with two enrolled compute guests and the test public IP pool. The verifier checks concurrent assignment to a /29, exhaustion without quota loss, protected deletion and prefix changes, certificate scope, network rule refresh, and release with generation checks. It also withholds policy from a fixture assignment whose ownership record has been invalidated. Results appear in `evidence/network-placement.json`.

Add `--packets` after installing the current Debian agent package on the first compute guest. The verifier attaches a pinned BusyBox fixture running in rootless Podman with nice +10. It checks real HTTP ingress after ownership is revoked and restored, after an NSG edit, after the policy process is paused and resumed, and after a replacement generation reuses the private IP address. It records the observed kernel expiry time and removes the disposable links and registry.

## Resource group network deployments

Azure CLI 2.93.0 uses `2025-04-01` for `az deployment group what-if`, `create`, and `show`. The supported template is inline and incremental, with at most eight resources. It accepts virtual networks, child subnets, regional Standard static IPv4 addresses, and Standard NAT gateways at the provider versions listed in the command matrix. Supported expressions are `parameters`, positional `format`, same-group `resourceId`, and `resourceGroup().location`. Parameters and outputs use strings. The API rejects linked templates, unsupported types and expressions, and dependency cycles. [What-if API](https://learn.microsoft.com/en-us/rest/api/resources/deployments/what-if?view=rest-resources-2025-04-01) · [Deployments API](https://learn.microsoft.com/en-us/rest/api/resources/deployments/create-or-update?view=rest-resources-2025-04-01)

Preview and validation read a single regional revision without writing resource or operation records. The resource graph, public IPv4 reservation, deployment record, and audit commit together. An incremental deployment preserves unmanaged resources. A repeated deployment preserves the assigned public address and reconciles supported changes.

Install Bicep CLI 0.49.2 and Debian's `libicu76` in the operator guest. Run `python3 lab/verify_deployment.py --state "$OCEAN_LAB_STATE"` with the empty two-address lab pool configured above. Pass `--bicep` if the compiler is installed outside `/home/ocean/.local/bin`. The verifier runs what-if on a populated group, checks for resource mutations, rejects an invalid deployment, deploys the template, verifies rollback when the pool is exhausted, and reconciles a changed subnet. Find the results in `evidence/network-deployment-arm.json`. [Network fixture](../tests/e2e/testdata/bicep/network.bicep) · [Bicep release](https://github.com/Azure/bicep/releases/tag/v0.49.2)

## Routed WireGuard gateway

The `ocean-gateway` command accepts one `wireguard` configuration for a dedicated routing namespace. Attach an underlay link with a route to the peer's IPv4 endpoint and an inside link for its approved local networks. Supply a private /31 for the tunnel, one peer public key, and a root-owned private key file with owner-only permissions. The tunnel addresses and approved local, remote, and protected networks must be disjoint. Each peer needs its own private key. [WireGuard quick start](https://www.wireguard.com/quickstart/)

```json
{
  "namespace": "tenant-vpn",
  "wireguard": {
    "tunnel": "wg0",
    "underlay": "wan0",
    "inside": "lan0",
    "localTunnel": "10.99.1.0/31",
    "peerTunnel": "10.99.1.1",
    "listenPort": 51820,
    "peerEndpoint": "198.18.24.2:51820",
    "peerPublicKey": "<WireGuard public key>",
    "privateKeyFile": "/etc/ocean-gateway/tenant-vpn.key",
    "localPrefixes": ["10.91.1.0/24"],
    "remotePrefixes": ["10.92.1.0/24"],
    "protectedPrefixes": ["10.231.1.0/24"]
  }
}
```

Use `ocean-gateway -config /etc/ocean-gateway/tenant-vpn.json -mode apply` with `iproute2`, `nftables`, and `wireguard-tools` in the gateway guest. The command blocks namespace forwarding while it reconciles the tunnel and routes. It enables only the approved prefix pairs and permits ICMP peer probes on the tunnel addresses. Use `-mode remove` to close forwarding and remove the tunnel and its routes. Keep the management interface in its own network namespace. [WireGuard network namespaces](https://www.wireguard.com/netns/)

An optional `redundancy` object gives the local inside address and the trusted neighbor's `peer` address and `peerMac`. It enables unicast VRRP traffic matching those addresses and TTL 255 on the inside interface. A routing supervisor can call `-mode probe` to check the peer tunnel using an authenticated ICMP exchange. Use a controlled inside segment for VRRP and configure each gateway with its own tunnel and peer. [Keepalived configuration synopsis](https://www.keepalived.org/manpage.html)

Run the packet check on a disposable Debian KVM guest with `wireguard-tools`, `nftables`, and `iputils-ping`. It creates and removes four isolated namespaces and uses disposable peer keys. The test exercises encrypted forwarding in both directions, blocked paths, prefix changes, failed configuration, and teardown.

```sh
vpn_test=$(mktemp /tmp/ocean-wireguard-test.XXXXXXXX)
CGO_ENABLED=0 go test -mod=readonly -tags=e2e -c -o "$vpn_test" ./internal/network
./bin/ocean-lab ssh -state "$OCEAN_LAB_STATE" farm-1-node-05 -- \
  'file=$(mktemp); trap "unlink \"$file\"" EXIT; cat > "$file"; chmod 0700 "$file"; sudo env OCEAN_E2E_WIREGUARD=1 "$file" -test.v -test.run=^TestRoutedWireGuard$' \
  < "$vpn_test"
```

Run `python3 lab/verify_wireguard_hosts.py --state "$OCEAN_LAB_STATE" --profile "$OCEAN_LAB_PROFILE"` against a disposable regional lab with the installed control plane and enrolled `farm-1-node-05` compute guest. Use the exact running profile so the verifier can restart the stopped gateway. The two gateway guests need WireGuard tools, nftables, iputils-ping, and Keepalived. The customer guest needs WireGuard tools, nftables, iputils-ping, and curl. The verifier sets up two separate peer keys and paths, starts the pinned HTTP workload under rootless Podman at nice +10, and measures route recovery after disabling a tunnel's underlay and powering off the active gateway guest. It probes management from the operator network during gateway loss and records successful and unsuccessful attempts. The customer must remain unable to reach the protected management network. Results appear in `evidence/wireguard-hosts.json`. The lab paths use separate network interfaces on a shared virtual underlay.

The `Ocean.Network/siteConnections` API uses `2026-11-01` and supports resource-group PUT, GET, and DELETE through `az rest`. A request names the tenant subnet, customer prefixes, and the two customer peer endpoints and public keys. The region validates prefix boundaries and reserves an operator slot with two enrolled hosts. Each host receives its own peer settings. Its private key stays on the gateway. The WireGuard agent renews the local eight-second forwarding lease and uses the encrypted peer probe when selecting the active tenant-side router. Creation waits for two healthy paths and one route owner. Deletion releases reservations after both hosts withdraw the tunnel.

After preparing the enrolled gateway guests using the HTTPS lab procedure, run `python3 lab/verify_wireguard_api.py --state "$OCEAN_LAB_STATE" --package bin/ocean-agent_0.1.0~dev7_amd64.deb`. The check creates and deletes the site connection through the pinned CLI. It measures recovery when the active gateway agent stops, checks the protected management path, and checks that packets stop reaching the private workload after deletion. Results appear in `evidence/wireguard-api.json`. [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv)

## Public HTTPS ingress

The `ocean-gateway -mode render-https` command renders a dedicated HAProxy configuration from a single `https` role. The bundle must contain a matching private key and a valid certificate for the configured DNS name. Place it in a root-owned, owner-only file. The backend must be a usable address in the declared private subnet.

```json
{
  "https": {
    "publicIPv4": "198.51.100.20",
    "hostname": "ingress.ocean.test",
    "certificateFile": "/etc/ocean-gateway/ingress.pem",
    "backend": "10.89.1.4:8080",
    "backendSubnet": "10.89.1.0/24"
  }
}
```

Validate the rendered configuration with `haproxy -c -f <configuration>`. Run HAProxy in a gateway namespace with a public and private link and let the routing supervisor own the listener address. HAProxy accepts the configured TLS and HTTP host, checks the private backend, and sets forwarding headers from the actual connection. [HAProxy configuration reference](https://docs.haproxy.org/3.0/configuration.html)

Run `TestPrivateHTTPSIngress` from the network test binary in a Debian KVM guest with `OCEAN_E2E_HTTPS_INGRESS=1`, HAProxy, curl, and Python installed. The test verifies certificate identity, the private backend response, replacement of client-supplied forwarding headers, rejection of other hostnames, and blocked direct access from the public client.

Use the `egress-ha` profile for the separate gateway-guest test. The gateway guests require `haproxy`, `keepalived`, `nftables`, and `dnsmasq-base`. The worker uses the Debian node-agent package and the pinned NGINX image. Run `python3 lab/verify_https_hosts.py --state "$OCEAN_EGRESS_STATE"`. The external probe uses the two DNS instances to resolve the test name and verifies TLS against the test certificate. The check powers off the active KVM gateway and measures recovery with fresh DNS and with the previous address. It records the outcome in `evidence/https-gateway-hosts.json`.

Azure CLI 2.93.0 generates a legacy template for `az network application-gateway create`. It sends the deployment to `2024-11-01` and declares the gateway resource at `2022-05-01`. The command matrix records the parameters for one public HTTPS listener and a private HTTP backend on a two-instance Standard_v2 gateway. The template fixture uses disposable certificate fields and feeds the command's actual request shape into the parser test. [ARM command matrix](../tests/e2e/testdata/arm-contract.tsv) · [Captured request shape](../tests/e2e/testdata/application-gateway-deployment.json)

Install OpenSSL on the control-plane guests for the PKCS#12 import. Run `python3 lab/verify_application_gateway_validation.py --state "$OCEAN_LAB_STATE"` with a free public address in the regional pool. It uses the unmodified CLI's `--validate` workflow to confirm the certificate password, an available public address, and a private backend address in the selected subnet. It checks failure responses and verifies that validation makes no changes to the resource group inventory. The certificate must identify one DNS hostname in its Subject Alternative Name. Results appear in `evidence/application-gateway-validation.json`.

The regional `applicationGateways` configuration defines operator slots and two enrolled gateway hosts per slot. Each API replica loads the same private 32-byte certificate encryption key. The region reserves the public address, subnet, and slot together and makes the certificate bundle available only to the assigned, leased host identities over mTLS. The HTTPS agent applies the listener and DNS roles in the operator-provided routing namespace. The local forwarding lease expires after eight seconds without renewal. ARM deployment completes after both gateways report readiness and exactly one owns the public address. Teardown releases reservations after both hosts report removal.

```sh
make deb-agent
python3 lab/prepare_application_gateway.py --state "$OCEAN_LAB_STATE" \
  --package bin/ocean-agent_0.1.0~dev7_amd64.deb
python3 lab/verify_application_gateway_lifecycle.py --state "$OCEAN_LAB_STATE"
```

Use the disposable regional identity lab with a free public address and the enrolled `farm-1-node-05` worker. The preparation command enrolls both gateway guests and attaches the slot's isolated public and backend links. The lifecycle check uses the selected Azure CLI create, show, and delete commands, verifies the certificate from the outside probe, stops the active HTTPS agent to measure failover, and checks withdrawal using the previous public address. It saves `evidence/application-gateway-lifecycle.json`.

## Debian node-agent package

Run `make deb-agent` to build the package in `bin/`. Pass `DEB_VERSION` to build a different Debian package version. Install the resulting `.deb` with `apt` inside the Debian guest so its Podman and systemd dependencies are resolved.

The package creates the `ocean-agent` system account with subordinate UID and GID ranges. It enables the unit in that account's systemd user manager on a running systemd installation. The agent checks Podman rootless mode before serving readiness at `http://127.0.0.1:8081/readyz`. The configuration file is `/etc/ocean-agent/config.json`. [Debian subordinate IDs for system accounts](https://manpages.debian.org/trixie/passwd/useradd.8.en.html)

Run `python3 lab/verify_agent_package.py --state "$OCEAN_LAB_STATE" --node farm-1-node-03 --package bin/ocean-agent_0.1.0~dev7_amd64.deb` to install the package on a disposable lab node and check the service, rootless Podman cgroups, and readiness. The Podman runtime is initialized in a separate user scope so its user namespace can outlive an agent restart. The result is written to `evidence/agent-package.json`.

## Host identity enrollment

An approved inventory entry identifies a host, its management MAC and IPv4 reservation, its cell, operator pool, profile, and allowed roles. It also sets minimum CPU and memory, an optional KVM requirement, and an expiry and SHA-256 digest for the host's bootstrap credential. Entries and their MAC, address, and credential indexes are stored in the regional quorum. Control-plane voter membership follows the regional configuration.

The node agent reads the enrollment origin and management interface from its local configuration and the credential from an owner-only file supplied during provisioning. It generates an Ed25519 private key and stores it before making the first enrollment request. The server checks the credential, the signed certificate request, the approved network identity, and the host's reported Debian and runtime capabilities. The host record and the redemption marker commit together. A retry with the same private key returns the first issued certificate, including after a discarded response. The node confirms that certificate with a mutual TLS request before reporting readiness. Host requests consult the current regional identity record, so revocation also applies to an existing client connection.

After building the control plane and installing the enrollment-enabled agent package on a disposable lab guest, run the following local checks on an unused host enrollment fixture.

```sh
python3 lab/enrollment.py --state "$OCEAN_LAB_STATE" --node farm-1-node-03
python3 lab/verify_enrollment.py --state "$OCEAN_LAB_STATE" --node farm-1-node-03
```

The check verifies capability rejection, a discarded enrollment response, reuse of the committed certificate by the packaged service, rejection of a different key with the redeemed credential, and rejection after revocation. It writes `evidence/host-enrollment.json`. The test leaves the disposable identity revoked.

## First-boot host provisioning

Start with the `identity-ha-3` lab and build the enrollment-enabled agent with `make deb-agent`. The following command admits the additional compute guest using its planned management MAC and address, then boots it with a private NoCloud seed. The new guest uses 1 GiB of RAM and one vCPU. Existing voter membership comes from the regional profile.

```sh
python3 lab/bootstrap_host.py --state "$OCEAN_LAB_STATE" --check-restarts \
  --profile lab/profiles/identity-ha-4.yaml --node farm-1-node-04 \
  --package bin/ocean-agent_0.1.0~dev7_amd64.deb
```

The installer uses the Debian repositories for package dependencies. The seed carries the local agent package, its configuration, the management CA, and the host's short-lived credential. Cloud-init installs the package, writes the protected credential, and starts the service with its enrollment configuration. The verifier observes the regional registration before connecting to the guest to check cloud-init and mTLS readiness. It records `evidence/host-first-boot-<host-id>.json`.

`--check-restarts` also restarts the agent and the guest. Both checks require the same committed host identity and a ready service after recovery.

`ocean-lab up -enrollment-file` accepts a JSON manifest with `hostId`, `origin`, `caFile`, `tokenFile`, and `packageFile`. Build the approval from the same guest inventory before booting. The lab stores the seed with owner-only permissions and reuses the existing seed and disk on a restart. An existing guest rejects a different seed. [NoCloud datasource](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html)

## Leased host capacity and reservations

An enrolled agent reports its current host capabilities every four seconds over mTLS. The coordinator checks the report against the approved inventory and publishes available capacity with a 15-second regional lease. Each host can declare its own `reserved` CPU and memory in the approval. The default reserves 100 millicores and 128 MiB. Revocation removes the availability key in the same transaction as the identity update.

Workload providers reserve CPU and memory against a subscription policy containing the allowed operator pools and quota. Reservations account for cell, host, and tenant capacity in one quorum transaction. The retry ID is unique within the subscription. A stale cleanup cannot release a newer allocation with a different generation. Hosts receive only their leased, certificate-authorized assignment list at `GET /ocean/hosts/{host-id}/placements`. Draining blocks new placements and keeps existing reservations available for orderly teardown. Lease expiry removes the host from new placement decisions. Workload controllers release old reservations as part of their fenced cleanup.

Run `python3 lab/verify_placement.py --state "$OCEAN_LAB_STATE" --small farm-1-node-05 --large farm-1-node-06` in the dedicated regional lab with two enrolled hosts and the test subscription from the identity profile. The check exercises capacity, pool policy, concurrent quotas, retry identity, drain, and expiry of a stopped agent's lease. Evidence is written to `evidence/host-placement.json`.

### Linux container groups

Enable the regional `workloads` section with an owner-only 32-byte `secretsKeyFile` and an explicit `defaultPlacement` policy. The operator supplies the same key and policy to all API replicas. A subscription-specific placement policy overrides the default. The compute worker publishes its container network readiness with its host lease. Placement reserves CPU, RAM, and an endpoint together with the resource and operation records.

Azure CLI 2.93.0 uses `Microsoft.ContainerInstance/containerGroups` API version `2024-05-01-preview`. Private create uses API version `2022-01-01` to inspect the existing subnet and apply the Container Instance delegation. The pinned commands in `tests/e2e/testdata/arm-contract.tsv` exercise a single Linux container, a TCP endpoint, public OCI images pinned by SHA-256 digest, environment variables, resource requests, and `Always`, `Never`, or `OnFailure` restart policies. CPU requests use whole millicores. Memory is rounded up to a mebibyte for cgroups and reservations. The API returns ordinary environment values and the names of secure variables. Secure values are sealed in etcd and delivered over mTLS to the assigned host. Bounded API log tails remove literal occurrences of secure values. The local Podman log file belongs to the dedicated runtime account.

The rootless Debian user service runs at nice +10. A separate system service adds per-container routing on the operator-provided public and private fabrics. Its kernel leases bound stale forwarding when the supervisor or regional API becomes unavailable. Public endpoints accept the configured TCP port. Private endpoints use the scope's subnet security policy. Active private VNet prefixes are exclusive on the shared regional fabric. Delete the container group to release capacity and its address after the worker has removed the process and network link.

After deploying an enrolled region, enable the workload provider on its healthy compute guests and run the end-to-end contract locally.

```sh
make deb-agent
python3 lab/prepare_container_groups.py --state "$LAB_STATE" \
  --package bin/ocean-agent_0.1.0~dev8_amd64.deb
python3 lab/verify_container_groups.py --state "$LAB_STATE" --observer farm-1-node-06
```

The observer uses an isolated network namespace in a separate KVM guest. The test checks HTTP and socket closure, rootless Podman, the guest process priority and cgroup limits, endpoint reuse, quota release, and redacted inventory, logs, and audit data. Its evidence is written to `evidence/container-groups.json` in the lab state directory.

### Replicated Azure Files mounts

Use `storage-ha` for the storage tests. It extends the six-node development farm with three Debian guests that each have 4 GiB of RAM, two vCPUs, and an 8 GiB data disk. The storage script selects only the dedicated `virtio-ocean-storage` devices. Ceph Reef runs one monitor and one OSD per storage guest. The `ocean` pool uses three copies, a minimum of two for I/O, and the host-level CRUSH rule.

The pinned Azure CLI account and file share commands are listed in the ARM contract matrix. A file share becomes available after the worker creates its RBD image, initializes the LUKS2 encryption header, and formats ext4. A single Azure Files volume can be mounted at `/data` in a Linux container group. The account credential authorizes the mount request within the subscription. The regional key envelope protects the separate per-volume encryption key, which is delivered over mTLS to the assigned storage worker. Podman receives the mounted directory and runs at nice +10.

The region records one durable writer generation per volume. The worker confirms an unmounted generation before ordinary deletion releases its capacity. During a management partition the current writer can continue using Ceph. A replacement receives authorization after the configured fencing authority signs an attestation for the original host, volume, and generation and the region confirms that its heartbeat lease expired. The lab fencer waits for the exact QEMU process to exit before signing. Recovery deploys a replacement container on the surviving worker. Keep the fencing private key in the environment that controls guest power.

```sh
make deb-agent
bin/ocean-lab up -state "$LAB_STATE" -profile lab/profiles/storage-ha.yaml
python3 lab/storage.py --state "$LAB_STATE"
python3 lab/verify_storage_backend.py --state "$LAB_STATE"
python3 lab/prepare_storage_provider.py --state "$LAB_STATE" \
  --package bin/ocean-agent_0.1.0~dev9_amd64.deb
python3 lab/verify_storage_mounts.py --state "$LAB_STATE"
python3 lab/verify_storage_mounts.py --state "$LAB_STATE" --fence
python3 lab/verify_storage_mounts.py --state "$LAB_STATE" --observer farm-1-node-03 \
  --restore-from-backups /path/to/etcd-v3.6.17-linux-amd64.tar.gz
```

The recovery profile quiesces the writer and releases its RBD map. It saves metadata with `etcdctl snapshot save` and exports the encrypted RBD checkpoint to a separate backup file. It starts a fresh etcd instance and ARM API in a dedicated test guest. The unchanged CLI verifies the share ID, quota, tenant scope, and account credential against the recovered metadata. With the separately held regional wrapping key, `ocean-recover` writes the authorized volume key to a new owner-only file. The recovery guest imports the encrypted image and verifies the workload's checksum. The evidence records artifact hashes and rejects recovery with a different wrapping key or a different tenant identity.

### Linux HTTP Functions

The Functions contract uses the pinned Azure CLI and one Linux B1 plan with one
worker. The supported deployment is a digest-pinned OCI image with an HTTP
trigger and Functions runtime v4. Java 21 is the acceptance fixture. Node.js,
.NET isolated and Go custom handler fixtures have independent source and pinned
base images under `tests/e2e/testdata/workloads`.

Use an enrolled regional lab with the replicated storage pool, two storage
workers, the workload network agent and the HTTPS gateway roles. Build the Debian
agent locally with `make deb-agent`. Run `python3 lab/prepare_functions.py --state DIR
--package PACKAGE` to build and stage both Java revisions through the lab's
loopback TLS registry. The setup gives each enrolled storage worker an 8 GiB
boot disk for the native Functions images. The worker preloads the pinned
storage companion image before the CLI test runs. Run `python3 lab/verify_functions.py
--state DIR` to verify the private subnet, public HTTPS, native Function keys,
image and settings changes, lifecycle operations and fixed egress through one
gateway failure. Evidence is written to `DIR/evidence/http-functions.json`.

The Functions host runs the selected OCI image in rootless Podman. A loopback
storage companion provides the blob, queue and table operations required by the
supported HTTP host. Both host storage and the native key directory live on a
dedicated encrypted Ceph-backed share. The share is retained when the app is
deleted and remains under the tenant's storage account until the tenant removes
it. The ARM compatibility profile manages this host storage through the Function
workflow. The account-level Azure Blob, Queue and Table data APIs remain outside
the profile.

Ingress opens through the selected Application Gateway and its certificate.
Provision the app, integrate the private subnet and attach the HTTPS gateway.
The Function hostname uses the operator-configured Functions domain. Use the
gateway's DNS path in the lab, or publish the gateway's address in the
operator's DNS. The initial app placement does not accept direct public HTTP.
The Functions Worker config, native master key and storage credentials are
controlled by the platform. Tenant users with resource write access can manage
app settings and Function keys. A Reader can see the app and discover functions.

Run `python3 lab/verify_function_fixtures.py --output FILE` for a local Podman check of
both Java revisions and the Node.js, .NET and Go fixtures. This check verifies
each native trigger and the valid, missing and invalid key paths. The regional
acceptance run uses the Java fixture for gateway, network and lifecycle checks.

### Regional observability

Use the regional lab with installed compute agents, replicated storage, and the
private, public, and HTTPS workload paths. Prepare the telemetry cluster and
then run the observation probes locally with the pinned Azure CLI on the
operator guest.

```sh
make deb-agent
python3 lab/prepare_telemetry.py --state "$LAB_STATE" \
  --package bin/ocean-agent_0.1.0~dev11_amd64.deb --buffer-bytes 4096
python3 lab/verify_monitor_controlplane.py --state "$LAB_STATE"
python3 lab/prepare_functions.py --state "$LAB_STATE" \
  --package bin/ocean-agent_0.1.0~dev11_amd64.deb
python3 lab/verify_insights.py --state "$LAB_STATE"
python3 lab/verify_telemetry_outage.py --state "$LAB_STATE"
```

The telemetry etcd cluster has three members with its own mTLS credentials,
peer ports, data directory, lease retention and disk budget. The lab retains
measurements for about an hour. The regional store continues to own placement,
quota reservations, audit events, observed health and fencing. Workers measure
real rootless container cgroups and write an atomic bounded queue before
sending observations with their enrolled host certificate. After the byte
budget is reached, the oldest observations are evicted and the gap includes
their count and time range per workload. The agent exposes a separate
local counter if the gap metadata itself exhausts its share of the budget.

A Function can export OTLP/HTTP JSON traces to
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`. Each relay listens on its assigned
Function's loopback interface. It exports only
HTTP status, elapsed time, a bounded route template, a dependency hostname and
exception type. Request URLs, headers, payloads and exception messages are
discarded. The sampled Functions fixture instruments successful and failing
requests, a deliberate exception and a real HTTP request to its blob service.

Container usage supports `CpuUsage` in millicores and `MemoryUsage` in bytes.
Use resource IDs with `az monitor metrics list`. The supported series intervals
are PT1M, PT5M, PT15M, PT30M and PT1H, with Average, Minimum and Maximum.
Unobserved buckets have timestamps and missing values. ACI regional usage
reads committed reservations and the configured tenant ceiling.
[ARM contract matrix](../tests/e2e/testdata/arm-contract.tsv)

Use `az rest` with the ARM audience against `POST /v1/{resource-id}/query`
for the resource-scoped log queries. The contract covers the tested
`AppRequests` projections and summary, `AppDependencies`, `AppExceptions`
and `OceanTelemetryGaps_CL`. Queries take at most a one-hour window and 8,192 observations. The request summary uses nearest-rank
latency percentiles. Both APIs apply the resource group grant within the
subscription and return a service error while telemetry quorum is unavailable.
[Insights CLI fixture](../tests/e2e/insights_cli.py)

The local probes write `evidence/monitor-controlplane.json`,
`evidence/application-insights.json` and `evidence/telemetry-outage.json`.
Run the Insights and fencing probes sequentially so each can use the lab's
public address pool. The outage probe stops all three telemetry members,
provisions a private canary and verifies out-of-band writer fencing and
replacement before restarting the telemetry cluster. It checks a 4 KiB
worker buffer across a process restart and then compares reported gaps with
worker loss and resumed usage series. The acceptance evidence records the
measured delays and the profile's numeric limits.

### Local placement and autoscaling

The `Ocean.Compute/replicaSets` API version `2026-11-01` manages stateless
private Linux container groups on the same firewall, Podman and placement
paths as individual ACI groups. Use `az rest` with the regional ARM audience.
The subnet uses the `Microsoft.ContainerInstance/containerGroups` delegation.
The tenant reads the assigned slots and their health through the replica set.
The set reconciler owns the lifecycle of its member groups.

Set `availabilityTier` to `NonRedundant` or `LocallyRedundant`. The local
tier requires two live replicas on different hosts and reserves an additional
host's capacity and address for replacement. All slots, including cold
reservations up to the maximum replica count plus the local spare, consume
tenant quota. The workload profile and reserved maximum stay fixed over the
set's lifetime. Update the policy to change the target or enable autoscaling.

The `Fixed` policy keeps its desired replica count. A `Local` policy uses
a window of fresh CPU measurements, distinct increase and decrease
thresholds, and a cooldown. Scaling stays between the configured minimum and
maximum. An unavailable telemetry store preserves the last desired count.
Host replacement uses the same reconciliation path and remains independent of
telemetry.

The Azure Application Gateway workflow accepts a pool of up to four private
IPv4 HTTP backends in one selected subnet. Use the replica set's reserved
addresses to keep the HTTPS endpoint stable as slots start and stop. Both
gateway peers probe the pool and HAProxy distributes traffic among healthy
backends. Delete the application's ingress before releasing the reserved
addresses.

Run `python3 lab/verify_replica_sets.py --state "$LAB_STATE"` against the
enrolled regional lab with four compute hosts, the redundant HTTPS gateway,
telemetry, and the package built from this revision. The probe checks fixed
and local policies, reserved tenant quota, tier validation and scoped access.
It powers off one serving KVM node, observes replacement on a reserved host,
and continues external requests using fresh and cached DNS. It measures
scale-out and scale-in under controlled HTTP load. The probe writes
`evidence/replica-sets.json` with outcomes and individual request attempts.
[CLI command matrix](../tests/e2e/testdata/arm-contract.tsv)
