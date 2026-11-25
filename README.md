# ocean

ocean is an open-source cloud platform on Debian for Linux containers and HTTP
Functions. Tenants can provision resources with the standard Azure CLI against
an ocean region. The first release profile has passed the end-to-end acceptance
tests in the Debian KVM lab.

See the [architecture and capabilities](ARCHITECTURE.md) for the regional
topology, workload paths, and availability profiles.

## Available in phase one

- **Identity and access.** Onboard customer tenants and subscriptions, manage
  users and service principals, sign in over OAuth, and assign scoped Azure RBAC roles.
- **Linux containers.** Run public OCI images with Podman, choose a public TCP
  endpoint or a private subnet, set CPU and memory limits and secret environment
  variables, and manage lifecycle and logs. Mount encrypted, replicated storage
  through the supported Azure Files workflow.
- **HTTP Functions.** Deploy Linux Functions v4 from an OCI image and manage
  plans, app settings, lifecycle, and function keys. Java 21 is the end-to-end
  reference workload. Node.js 22 is exercised by the Insights tests.
- **Networking.** Create IPv4 virtual networks, subnets, firewall rules,
  public IPs, HTTPS ingress with Application Gateway, and fixed egress with NAT
  Gateway. Connect on-premises networks over redundant WireGuard gateways.
  Preview and apply the supported network-only Bicep template.
- **Operations.** View inventory, health, logs and audit events, measured
  resource usage, enforced quotas, and selected Azure Monitor and Application
  Insights metrics and queries.
- **Regional resilience.** Enroll Debian hosts with per-host mTLS, place
  fixed-count or locally autoscaled replicas on separate nodes, and fail over the
  management endpoint across redundant gateways backed by three etcd voters.

See the [phase-one objective](objective.md), [acceptance matrix](acceptance.tsv),
and [end-to-end protocol](tests/e2e/protocol.md) for scope and verification.

## Azure CLI compatibility

The compatibility contract uses **unmodified Azure CLI 2.93.0**. The
[command matrix](tests/e2e/testdata/arm-contract.tsv) records the tested
commands, flag combinations, resource types, and API versions. It covers
selected Azure Resource Manager (ARM), directory, and monitoring workflows.
Ocean-specific operations such as WireGuard management use `az rest`.

### Connect and sign in

Use a reachable ocean region and a tenant and subscription provisioned by its
operator. Set `OCEAN_ARM_ENDPOINT`, `OCEAN_TENANT_ID`,
`OCEAN_SUBSCRIPTION_ID`, and `OCEAN_LOCATION` for your region. The lab uses
`https://arm.farm-1.ocean.test` and location `farm-1`. Trust your region's CA
before registering the cloud. See the [lab identity guide](lab/README.md#azure-cli-identity-compatibility).

```sh
export AZURE_CONFIG_DIR="$(mktemp -d)"
export AZURE_CORE_INSTANCE_DISCOVERY=false

az cloud register --name ocean --endpoint-resource-manager "$OCEAN_ARM_ENDPOINT"
az cloud set --name ocean
az login --tenant "$OCEAN_TENANT_ID" --use-device-code -o none
az account list --all -o json
az account set --subscription "$OCEAN_SUBSCRIPTION_ID"
az account list-locations --query '[].name' -o json
```

For automation, use this sign-in in place of the device-code sign-in. Supply
`OCEAN_CLIENT_ID` and `OCEAN_CLIENT_SECRET` from your credential store.

```sh
az login --tenant "$OCEAN_TENANT_ID" --service-principal \
  --username "$OCEAN_CLIENT_ID" --password="$OCEAN_CLIENT_SECRET" -o none
```

### Run a public Linux container

The examples share a disposable resource group. The public container requires
an available address in the region's public endpoint pool. The NGINX image is
pinned in the [fixture image lock](tests/e2e/testdata/images.lock.yaml).

```sh
OCEAN_GROUP=demo-ocean
NGINX_IMAGE=docker.io/library/nginx@sha256:836c5af5a07dbff704e8ba7971d20dd55bc96d5748a03129f02bd4ce25836e0d

az group create --name "$OCEAN_GROUP" --location "$OCEAN_LOCATION" \
  --tags ocean-fixture=readme -o json

az container create --resource-group "$OCEAN_GROUP" --name sample-web \
  --location "$OCEAN_LOCATION" --image "$NGINX_IMAGE" \
  --ip-address Public --ports 80 --protocol TCP --os-type Linux \
  --cpu 0.25 --memory 0.0625 --restart-policy Always -o json

az container show --resource-group "$OCEAN_GROUP" --name sample-web -o json
az container logs --resource-group "$OCEAN_GROUP" --name sample-web \
  --container-name sample-web
```

Use the address in `ipAddress.ip` from `az container show` to reach NGINX over HTTP.

### Create a private network

Choose regional address prefixes available to your subscription.

```sh
az network vnet create --resource-group "$OCEAN_GROUP" --name app-net \
  --location "$OCEAN_LOCATION" --address-prefixes 10.91.0.0/16 \
  --subnet-name workloads --subnet-prefixes 10.91.1.0/24 -o json
```

### Deploy a Linux HTTP Function

Set `OCEAN_FUNCTION_APP` and `OCEAN_STORAGE_ACCOUNT` to available names and
`OCEAN_FUNCTION_IMAGE` to a digest-pinned Java 21 Functions v4 image available to
the region's workers. The [Functions lab guide](lab/README.md#linux-http-functions)
covers building and staging the reference image, integrating a private subnet,
and publishing the app through HTTPS ingress.

```sh
az storage account create --resource-group "$OCEAN_GROUP" \
  --name "$OCEAN_STORAGE_ACCOUNT" --location "$OCEAN_LOCATION" \
  --kind StorageV2 --sku Standard_LRS --https-only true \
  --public-network-access Disabled --allow-blob-public-access false \
  --min-tls-version TLS1_2 -o json

az functionapp plan create --resource-group "$OCEAN_GROUP" --name functions \
  --location "$OCEAN_LOCATION" --is-linux --sku B1 --number-of-workers 1 -o json

az functionapp create --resource-group "$OCEAN_GROUP" --name "$OCEAN_FUNCTION_APP" \
  --plan functions --storage-account "$OCEAN_STORAGE_ACCOUNT" \
  --image "$OCEAN_FUNCTION_IMAGE" --functions-version 4 --runtime java \
  --runtime-version 21 --os-type Linux --https-only true \
  --configure-networking-later true --disable-app-insights true -o json

az functionapp function list --resource-group "$OCEAN_GROUP" \
  --name "$OCEAN_FUNCTION_APP" -o json
```

## Develop locally

Use the Go version pinned in `go.mod`. Run `make check` for formatting, `go vet`,
race-enabled unit tests, compilation of the `e2e` suite, and static analysis.
Run `make lint` for the pinned Staticcheck and errcheck passes alone. Both
analyze application code and `e2e` sources. Go downloads the tools on first use.
Handle returned errors and check type assertions. Use explicit error discards
for intentional best-effort operations such as closing a read-only response body.
Run `make build` to build the binaries in `bin/`.

For a local process check, run `./bin/ocean-control-plane` and
`./bin/ocean-agent` in separate terminals. The agent requires rootless Podman.
The default loopback readiness endpoints return HTTP 204 after startup.

```sh
curl --fail --silent --output /dev/null http://127.0.0.1:8080/readyz
curl --fail --silent --output /dev/null http://127.0.0.1:8081/readyz
```

Both services accept a JSON configuration file through `-config`. A listener
outside loopback requires TLS. See the [KVM lab guide](lab/README.md) for
topology profiles, regional TLS and etcd configuration, and the full suite.
