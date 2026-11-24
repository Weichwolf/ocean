# End-to-end test protocol

The suite exercises a running ocean deployment through its external interfaces. Use the pinned, unmodified Azure CLI for supported management commands and a client outside the workload path for reachability and availability checks. Associate every result with its case ID in the [acceptance matrix](../../acceptance.tsv). The [phase-one objective](../../objective.md) defines the release scope.

## Planned layout

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

Keep workload source and runtime configuration beside each Containerfile. Keep lab topology and node sizing in `lab/profiles`. The Go harness handles CLI calls, probes, fixture deployment, scoped fault injection, and cleanup. Use the `e2e` build tag and execute uncached runs. The planned runner interface is `OCEAN_E2E_PROFILE=<profile> go test -tags=e2e -count=1 -json ./tests/e2e/...`.

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

## Execution and evidence

1. Record the source revision, platform and CLI versions, API versions, selected cases, image digests, topology, resource budgets, and pass limits before running the suite. Give the run its own Azure CLI configuration directory and its own test resources.
2. Run the selected provisioning, identity, network, workload, and operations cases. Verify the observed behavior in addition to CLI responses and resource status.
3. For continuity cases, probe through the intended endpoint before, during, and after the fault. Exercise fresh and cached DNS answers where required. Record logical request results, per-attempt failures, connection resets, and latency. Capture replication and fencing evidence for single-writer recovery.
4. Collect the evidence and clean up resources owned by the run. Write a Markdown summary and a TSV with `case_id`, `status`, `duration_ms`, `evidence`, and `detail` columns. Keep relevant sanitized CLI and probe output, logs, and measurements in `evidence/`.

Report each selected case as `PASS`, `FAIL`, `BLOCKED`, or `SKIP`. Phase-one approval requires a `PASS` for every `required` case in the matrix. Production and enabled compatibility profiles also require their applicable cases to pass. Store or publish run evidence as build artifacts so the release can be verified from the recorded inputs, limits, and results.
