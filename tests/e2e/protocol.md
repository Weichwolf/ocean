# End-to-end test protocol

The suite exercises a running ocean deployment through its external interfaces. Use the pinned, unmodified Azure CLI for supported management commands and a client outside the workload path for reachability and availability checks. Associate every result with its case ID in the [acceptance matrix](../../acceptance.tsv). The [phase-one objective](../../objective.md) defines the release scope.

## Repository layout

```text
lab/
  profiles/
    single-farm-3.yaml
    scale-16.yaml
    geo-4x3.yaml
    geo-4x4.yaml
tests/e2e/
  protocol.md
  suite_test.go
  provisioning_test.go
  identity_test.go
  workloads_test.go
  network_test.go
  resilience_test.go
  internal/harness/
  testdata/
    images.lock.yaml
    workloads/
      stateful-http/Containerfile
      functions-java/Containerfile
      functions-dotnet/Containerfile
      functions-node/Containerfile
      functions-go/Containerfile
    bicep/network.bicep
artifacts/e2e/<run-id>/
  report.md
  results.tsv
  evidence/
```

Keep workload source and runtime configuration beside each Containerfile. Keep lab topology and node sizing in `lab/profiles`. The Go harness handles CLI calls, probes, fixture deployment, scoped fault injection, and cleanup. Use the `e2e` build tag and execute uncached runs. The runner interface is `OCEAN_E2E_PROFILE=<profile> go test -tags=e2e -count=1 -json ./tests/e2e/...`.

## Lab profiles

| Profile | Purpose |
| --- | --- |
| `single-farm-3` | Smoke tests, automatic enrollment, management quorum, and local service checks |
| `scale-16` | Sixteen small nodes, mixed RAM and CPU profiles, placement, and worker drain |
| `geo-4x3` | Four independent logical farms and initial WireGuard mesh and federation setup |
| `geo-4x4` | Enroll one additional node per farm, then exercise node, tunnel, and whole-farm loss |
| `farm-pairing` | Exercise authenticated farm pairs, allowed routes and path loss over native WireGuard with four local quorums |
| `farm-routing` | Exercise BGP and BFD route failover and application traffic on both native WireGuard paths |
| `ipsec-gateway` | Check IKEv2 peer authentication, routed traffic, forwarding expiry, and cleanup in a disposable Debian KVM guest |
| `ipsec-control` | Check regional VPN reservations, assignment authorization, status freshness, and teardown against real etcd |
| `ipsec-profile` | Create and remove VPN resources with stock Azure CLI and verify the installed gateway worker against a native strongSwan peer |
| `functions-zip-foundation` | Invoke versioned packages in the native Functions host and verify sealed storage, assignment authorization, and regional slot activation and rollback |
| `functions-zip-slots` | Use stock Azure CLI and authenticated SCM against regional workers, then verify keyed responses before and after failed activation and slot promotion |
| `cost-management-foundation` | Verify a known usage ledger dataset in live mTLS etcd, including midnight splitting, retries, and retained history |
| `cost-management` | Verify native CLI cost tables and tenant scope against independently calculated totals from two live workloads |
| `domain-join` | Verify Samba AD domain join and sign-in with Debian, Windows Server 2025 Core, and Windows 11 Pro or Enterprise Evaluation |
| `managed-directory` | Exercise startup identity authorization, controller health, bidirectional AD replication, SYSVOL policy and ACL replication, outages, and the pinned Azure CLI management contract |
| `vm-worker` | Exercise stock Azure CLI VM lifecycle, tenant boundaries and quota accounting, then confirm out-of-band fencing and read a persisted Windows checkpoint on the replacement |

### Farm pairing

The `farm-pairing` profile starts two independent test underlays, eight
WireGuard gateways, and four three-voter etcd stores. It runs inside new
Linux user and network namespaces. Install WireGuard tools, dnsmasq, iproute2,
iputils, bind9-dnsutils, OpenSSL, and etcd with etcdctl. Override tool paths using
`OCEAN_E2E_WG_BINARY`, `OCEAN_E2E_DNSMASQ_BINARY`,
`OCEAN_E2E_ETCD_BINARY`, and `OCEAN_E2E_ETCDCTL_BINARY` if needed.

```sh
OCEAN_E2E_PROFILE=farm-pairing go test -tags=e2e -count=1 -v ./tests/e2e -run '^TestAcceptance$'
```

The measurement artifact records the time to all pairings and the time
to observe path lease withdrawal after loss of a WAN or a farm. The
management probe checks the surviving regional readiness endpoints.
`PROFILE-04` through `PROFILE-06` cover the KVM service and independent-site gates.

### Farm routing

Install BIRD 2 and procps in addition to the pairing tools. Set
`OCEAN_E2E_BIRD_BINARY` when its executable is outside the standard
Debian location and `OCEAN_E2E_BIRDC_BINARY` if birdc is elsewhere.

```sh
OCEAN_E2E_PROFILE=farm-routing go test -tags=e2e -count=1 -v ./tests/e2e -run '^TestAcceptance$'
```

`FED-02` runs the generated configuration on each lab gateway and its
local fabric router. The client and HTTP service have a separate
workload network. The probe checks the selected Linux next hop and
the HTTP response before and after gateway process loss, WAN loss and
recovery. It reports elapsed time and failed requests up to the first
successful probe on each expected path. A known peer also advertises an
unapproved prefix, which the receiving gateway filters. Both links of one farm are
then disconnected. Its prefixes become unreachable, and a workload
in another farm still answers.

### Other profile probes

Set `OCEAN_E2E_IPSEC_LAB_STATE` to the prepared guest state from the
[IPsec lab guide](../../lab/README.md#routed-ipsec-gateway-probe) to run
`IPSEC-01`. The artifact includes the strongSwan package versions and the
measured time to working IKE and CHILD SAs. The Azure CLI VPN lifecycle
has its own acceptance case, `PROFILE-01`.

Run `IPSEC-02` through the `ipsec-control` profile with the disposable
etcd endpoint and mTLS client files described in the
[regional IPsec lab guide](../../lab/README.md#regional-ipsec-reservations).
Its acknowledged states come from authenticated worker fixtures.

The `ipsec-profile` runner exercises `PROFILE-01` with signed CLI login,
the regional API, an enrolled Debian package, and an independently
configured native customer peer. It records command results, connection
and expiry measurements, rejected paths, and cleanup. Follow the
[IPsec profile lab setup](../../lab/README.md#ipsec-profile-acceptance-run).

The `functions-zip-foundation` runner exercises `ZIP-01` through `ZIP-03`.
It records the native runtime digest, an empty slot's HTTP 404 response,
keyed invocation of two independent packages, scoped retrieval, staging
cleanup, and regional rollback following a reported activation failure.
The regional swap probe uses authenticated worker fixtures to check that
both acknowledgments are required and endpoint bindings and sticky settings
are preserved.
[Prebuilt Functions ZIP lab](../../lab/README.md#prebuilt-functions-zip-verification)

Run `PROFILE-02` through `functions-zip-slots` against a prepared regional
lab. It records both SCM operation outcomes, measured activation and swap
times, and the responses from an independent private workload client. The CLI
command matrix includes named slot operations and the supported ARM requests
for staging function discovery and keys.
[Regional ZIP and slot acceptance](../../lab/README.md#regional-zip-and-slot-acceptance)

Run `COST-01` through `cost-management-foundation` with
`OCEAN_E2E_ETCD_ENDPOINTS` and `OCEAN_E2E_ETCD_PKI` pointing to a
disposable store. Run `PROFILE-03` through `cost-management` against the
prepared regional lab. The latter records the pinned CLI version, measured
source quantities, rate schedule, typed cost results and isolation outcomes.
[Cost Management lab guide](../../lab/README.md#cost-management)

Select `WORKPLACE-06` explicitly and set `OCEAN_E2E_DIRECTORY_ETCD` to a
disposable endpoint to verify regional replica and writer fencing,
acknowledgement, and replacement scheduling. This case uses signed fixture
power evidence. The physical-host run observes the actual power state
through the site fencing authority.

Select `WORKPLACE-07` explicitly with `OCEAN_E2E_SAMBA_IMAGE` set to
exercise encrypted backup recovery. The isolated probe deletes both original
controller volumes, brings up a fresh controller, verifies the original domain
and policy, and checks an existing Samba member's machine credentials.

Select `WORKPLACE-08` explicitly with `OCEAN_E2E_SAMBA_IMAGE` and
`OCEAN_E2E_ADCLI_IMAGE` set to exercise a scoped Debian join. The isolated
client verifies access to the named computer, denied joins for other
computers, a fresh machine keytab, and authorization closure and expiry.

Select `WORKPLACE-09` explicitly with the same images, stock Azure CLI
2.93.0, and an isolated `OCEAN_E2E_DIRECTORY_ETCD` endpoint. The test wires
the regional ARM and enrollment handlers to a real etcd store. The certified
node agent runs the staged job on a single Samba lab controller and Debian
compares the actual join result with the CLI's authorization states.

Select `WORKPLACE-10` with the same prerequisites to test the managed Graph
user profile. Azure CLI authenticates against the isolated OAuth issuer and
uses the Graph endpoint. The mTLS worker applies user operations to the Samba
workforce OU. The Debian fixture requests a fresh Kerberos ticket before and
after the user is disabled.

Select `WORKPLACE-11` with the same prerequisites to exercise managed
security groups. The pinned CLI creates and finds the native group, adds and
removes a workforce user, and verifies the actual membership. A Debian SMB
client opens a fresh Kerberos session at each step and checks its access
to a share restricted to the AD group.

Select `WORKPLACE-12` with `OCEAN_E2E_SAMBA_IMAGE` set to verify actual
Samba writer promotion on one host. The probe stops the first controller,
promotes the second, tests Kerberos, existing member trust and writable
policy, then joins a fresh read-only replica in the retired slot and verifies
the updated policy and ACL.

Select `WORKPLACE-13` with the same controller image and OpenSSL to reconstruct
a pair from its independently encrypted backup in rootless Podman. The
writer is restored on a new volume with a rotated bootstrap credential.
The standby rejoins, serves the original member alone, and supplies the
original policy and ACL. `WORKPLACE-05` covers the stock CLI recovery calls
and `WORKPLACE-06` verifies regional two-host placement, fencing and recovery
state against disposable etcd with signed fixture evidence.

Select `WORKPLACE-14` for the regional Windows recovery test. Azure CLI
submits a signed fixture fence to the real ARM handler. Two Debian KVM guests
enroll with the regional authority and their regular node agents complete the
restore from the independent archive over their authenticated assignments.
The probe powers off the recovered writer after both existing Windows guests
report machine trust and policy access. It requires fresh client records
from the surviving controller before recording success. The preparation and
interactive Windows steps are in the [lab guide](../../lab/README.md).

Select `WORKPLACE-15` with the same recovery inputs and the Server Core
member. Stock Azure CLI drives user and group changes through the regional
Graph endpoint using the `WORKPLACE-10` and `WORKPLACE-11` command profiles.
This case also creates a group without a description. Fresh Windows logon
sessions verify the native account and group SIDs, a CIFS ticket and the
contents of a group-restricted file.
Membership revocation denies the file, rotation rejects the old password,
and account disable prevents a new logon. The [Windows Graph lab
guide](../../lab/README.md#regional-graph-changes-on-windows) describes the
guest probe and evidence.

Select `WORKPLACE-16` to provision a fresh domain using the regional ARM
and enrollment handlers. Two Debian KVM hosts start the installed agents,
and the packaged network service attaches the private addresses and
enforces the subnet policy. The pinned CLI checks admission, replay and
availability. A third guest verifies real DNS, Kerberos and SMB service
with either virtual host stopped. The [lab guide](../../lab/README.md#fresh-directory-with-packaged-agents)
describes the package and image inputs.

Record the environment for each run. Production runs use qualified independent physical hosts or sites as required by the selected cases.

Select `WORKPLACE-25` for the native SMB member check. The joined Debian
guest requests personal CIFS tickets and exercises the read-write, read-only,
and denied grants with encryption required by the client. The isolated
foreign guest checks TCP reachability. The verifier checks native user
identities in the audit journal and measures the delay from group removal
to denial with a newly issued TGT from the writable controller. Prepare the
fixture with the [SMB member lab guide](../../lab/README.md#kerberos-smb-member).

Select `WORKPLACE-26` for concurrent writes and byte-range locks over
two fresh encrypted SMB connections. The member serves a LUKS2 volume
mapped from Ceph RBD. The case requires a shared eight-MiB project quota,
checks acknowledged writes across both connections and records the client
error on a write over budget. One connection holds a lock while the other
attempts to acquire the same byte before and after release.

Select `WORKPLACE-27` for the managed SMB lifecycle. The stock CLI uses
the regional handler with isolated ARM fixture principals. The Debian
member enrolls over mTLS, receives a sealed-volume assignment, and confirms
the operation after publication. Native Kerberos sessions verify the
published access and retain an acknowledged file after an ACL update.
The withdrawal check confirms that the resource, SMB listener, filesystem
mount and RBD image have been removed.

Select `WORKPLACE-28` to correlate a fresh Windows Server Core write with
a Debian read using the same Kerberos principal. Windows also verifies
reader-only and denied grants. The runner checks the supplied nonce
against the live share and the Samba audit back to each client address.

## Workload fixtures

Resolve public images as `repository@digest` using [images.lock.yaml](testdata/images.lock.yaml). The stored tags identify the upstream sources for refreshing the lock. Record the digests of the built artifacts and the platform used by the test run.

| Fixture | Test behavior |
| --- | --- |
| BusyBox musl | Run short jobs with controlled exit codes and verify logs and restart policy. |
| nginx Alpine slim | Serve HTTP through the public ingress and supply a stateless fixture for availability probes. |
| curl | Probe DNS, TLS, VPN, firewall rules, and fixed source IP from the relevant network. |
| Valkey Alpine | Run a private TCP service and verify an authorized client can write and read a known value. |
| ACI Hello World | Exercise the public-image smoke path through `az container create`. |
| `stateful-http` | Write and read a checksum on a mounted share. Emit controlled responses and errors for load, autoscaling, and telemetry tests. |
| Functions v4 with Java 21 | Run the reference keyed HTTP trigger and the VNet and fixed-egress tests. |
| Functions v4 with .NET 10 isolated | Exercise both versions of a small HTTP Function and verify image updates and app settings. |
| Functions v4 with Node.js 22 | Emit controlled successful and failing requests for Insights queries. |
| Functions v4 with a Go custom handler | Exercise the custom handler startup and HTTP request path. |

Build each Function fixture on its locked public runtime base. Generate Function Keys at run time and deploy fixtures with those keys. Run Functions runtime cases sequentially in the small profile. Reserve capacity for simultaneous replicas in availability tests.

## Network template fixture

Use Bicep CLI 0.49.2 with Azure CLI 2.93.0 for the network template run. The fixture declares a VNet, an independently managed subnet, a regional Standard static IPv4 address, and a Standard NAT gateway. `namePrefix` gives each run its own resource IDs. The subnet declares the gateway reference and disables implicit outbound access. Record the compiler version and compiled template with the deployment evidence. [Network Bicep fixture](testdata/bicep/network.bicep) · [Bicep CLI release](https://github.com/Azure/bicep/releases/tag/v0.49.2)

## Observability profile

Check CPU and memory against a controlled BusyBox load and independent cgroup
readings, with tolerances of 100 millicores and 4 MiB. Compare the Node.js
Function's Insights records against the trusted external HTTPS probe. Require
matching status codes, request and error counts, dependency outcomes and
exception types. Use a 10 ms tolerance for application duration and
percentiles and a 60-second limit for the first complete CLI result. The fixtures verify that a foreign token cannot query either
resource's telemetry.

For the telemetry outage profile, use a 4 KiB persistent buffer on each test
worker and stop all members of the independent telemetry store. Provision a
private canary and complete real writer fencing and volume recovery before
restoring the store. The recovery limit is 45 seconds and the profile allows at
most 160 evicted observations on the monitored worker. Capture worker buffer
sizes, tenant-visible gaps and measurements both before and after recovery.

## Local availability and scaling profile

Reserve four slots on separate worker hosts for the local replica fixture.
Use two initial live replicas, a maximum of three and one accounted spare.
An HTTPS Application Gateway publishes the reserved backend pool. Verify the
fixed policy with varying HTTP demand, actual KVM host power-off, replacement
on a different reserved host and fresh CLI authentication during the fault.
The external client retries requests at most four times within eight seconds.
Capture duration, individual attempts and the response's replica identity for
both DNS lookups and a previously resolved address.

Exercise local CPU scaling with a 12-second observation window, a 14-second
cooldown and bounds of two and three live replicas. Increase above 45 percent
CPU utilization and decrease below 15 percent. Require each adjustment to
reach its observed replica count within 65 seconds. Confirm that the serving
set keeps the local minimum after scaling in.

## Management availability

Probe the authorized group through the regional DNS name and verified TLS
listener throughout the gateway, API replica and consensus leader faults.
Allow up to 12 seconds per logical HTTPS read, with two-second transport
timeouts and retries. Require the existing Azure CLI cloud profile to read
and mutate state within 60 seconds of each fault. Verify the original
workload and a new write after the election, then check the former leader
has replayed the write. Ensure the signed tenant token leaves time for the
CLI's five-minute refresh window and the faults under test.

## Execution and evidence

1. Record the source revision, platform and CLI versions, API versions, selected cases, image digests, topology, resource budgets, and pass limits before running the suite. Give the run its own Azure CLI configuration directory and its own test resources.
2. Run the selected provisioning, identity, network, workload, and operations cases. Verify the observed behavior in addition to CLI responses and resource status.
3. For continuity cases, probe through the intended endpoint before, during, and after the fault. Exercise fresh and cached DNS answers where required. Record logical request results, per-attempt failures, connection resets, and latency. Capture replication and fencing evidence for single-writer recovery.
4. Collect the evidence and clean up resources owned by the run. Write a Markdown summary and a TSV with `case_id`, `status`, `duration_ms`, `evidence`, and `detail` columns. Keep relevant sanitized CLI and probe output, logs, and measurements in `evidence/`.

Submit three concurrent creates for the same container group and three for
the same Function App through the pinned CLI. Compare the returned IDs,
the ready workload state, the operation record and the reservation charge.
Run the discarded-response and controller-restart checks against the
separate ARM deletion operation.

Report each selected case as `PASS`, `FAIL`, `BLOCKED`, or `SKIP`. Phase-one approval requires a `PASS` for every `required` case in the matrix. Production and enabled compatibility profiles also require their applicable cases to pass. Store or publish run evidence as build artifacts so the release can be verified from the recorded inputs, limits, and results.

## Run the local suite

Build the agent package and prepare the lab roles with the instructions in
[the lab guide](../../lab/README.md). Run acceptance on the Debian host that
owns the KVM guests. The harness uses the operator guest's isolated Azure CLI
installation and the customer or fault-profile clients for network probes.
It rebuilds the local Go binaries before starting the selected probes.

```sh
OCEAN_E2E_PROFILE=storage-ha \
OCEAN_E2E_STATE="$LAB_STATE" \
OCEAN_E2E_CASES=CONTRACT-01,CONTRACT-02,OBS-01,OBS-03 \
go test -mod=readonly -tags=e2e -count=1 -timeout 30m -json ./tests/e2e/...
```

Use `phase-one` to select every required row. Supply the prepared regional
state in `OCEAN_E2E_STATE`, the three-node enrollment lab in
`OCEAN_E2E_SMALL_STATE` and the prepared three-voter scale base in
`OCEAN_E2E_SCALE_STATE`. Set `OCEAN_E2E_PACKAGE` to the built Debian package
and `OCEAN_E2E_ETCD_ARCHIVE` to the pinned etcd release archive used for clean
recovery. Allow enough test time for all selected probes. The regional,
small and scale profiles can also run individually. The phase-one runner
sequences the selected lab states and restores the guests that were running
when it started. The regional guests start in groups of three so each launch
checks the available host memory. After a cold start, allow up to five minutes
for the lab's readiness endpoints. Keep unrelated guests within the host budget.

Start with a fresh small enrollment state with a valid preapproved join.
The runner exercises this short-lived credential first, and host
qualification revokes its fixture certificate. Prepare the scale base with
`python3 -B lab/prepare_scale16.py --help` and the same locally pinned
Debian, etcd, Keycloak and Azure CLI inputs as the regional lab. The scale
probe boots and enrolls the remaining thirteen guests when it runs.
The scale profile serves a keyed Java Function over HTTPS and releases its
capacity after deletion. The regional workload probe exercises image
updates, lifecycle operations, and fixed egress failover.

The default artifact directory is `artifacts/e2e/<run-id>/`. Set
`OCEAN_E2E_RUN_ID` for a named run or `OCEAN_E2E_ARTIFACTS` for a different
output root. Each CLI or fault test records its command and output. A case
passes after all of its mapped probes succeed and produce their declared
fresh evidence. Missing prerequisites and unmapped profiles produce
`BLOCKED` rows. Selected failures or blocked cases make the Go test fail
and still produce `report.md` and `results.tsv`.
