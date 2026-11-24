# ocean

See the [phase-one objective](objective.md), [acceptance matrix](acceptance.tsv), and [end-to-end protocol](tests/e2e/protocol.md) for the platform scope and release gates.

## Build and check

Use the Go version in `go.mod`. An older Go installation with automatic toolchain selection can fetch that version. Run `make check` for formatting, vet, and unit tests with the race detector. Run `make build` to build the service binaries in `bin/`. The build uses the pinned compiler, removes local paths and VCS metadata, and disables cgo.

## Run locally

Run the commands in separate terminals. The node agent runs as a regular user with working rootless Podman and checks `podman info` before serving requests.

```sh
./bin/ocean-control-plane
./bin/ocean-agent
```

```sh
curl --fail --silent --output /dev/null http://127.0.0.1:8080/readyz
curl --fail --silent --output /dev/null http://127.0.0.1:8081/readyz
```

`GET /livez` returns HTTP 204 while the server is running. `GET /readyz` returns HTTP 204 after startup and HTTP 503 during shutdown. Logs are JSON on standard error. Use Ctrl-C or send SIGTERM for graceful shutdown.

## Listener configuration

Both services accept `-config` with a JSON file. Settings omitted from the file use the service defaults. The listener address is a literal IP address and port. A port of zero selects an available port, which appears in the startup log. The default log level is `INFO`.

```json
{
  "listenAddress": "127.0.0.1:8080",
  "logLevel": "INFO"
}
```

For an HTTPS listener, set `tls.certificateFile` and `tls.keyFile` to PEM file paths. A non-loopback listener requires TLS. The service validates configuration and loads its key pair before it binds the listener.

## Development lab

See the [rootless KVM lab guide](lab/README.md) for the `ocean-lab` launcher and the topology profiles used in the [end-to-end protocol](tests/e2e/protocol.md).
