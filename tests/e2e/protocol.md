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

Record the environment for each run. Production runs use qualified independent physical hosts or sites as required by the selected cases.

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
checks the available host memory. Keep unrelated guests within the host budget.

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
