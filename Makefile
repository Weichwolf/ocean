.PHONY: build check lint vuln fuzz deb-agent

DEB_VERSION ?= 0.1.0~dev12
export DEB_VERSION

STATICCHECK_VERSION := v0.8.2
ERRCHECK_VERSION := v1.30.0
GOVULNCHECK_VERSION := v1.10.0
ERRORLINT_VERSION := v1.9.1
X_TOOLS_VERSION := v0.53.0
FUZZ_TIME ?= 10s
FUZZ_WORKERS ?= 2

GO_BUILD = CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false

build:
	mkdir -p bin
	$(GO_BUILD) -o bin/ ./cmd/...

check:
	formatter=$$(go env GOROOT)/bin/gofmt && files=$$("$$formatter" -l cmd internal tests) && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }
	go mod tidy -diff
	go mod verify
	out=$$(mktemp -d) && trap 'rm -rf -- "$$out"' 0 && $(GO_BUILD) -o "$$out/" ./cmd/...
	go vet -mod=readonly ./...
	go vet -mod=readonly -tags=e2e ./...
	go test -mod=readonly -race -shuffle=on -count=1 ./...
	go test -mod=readonly -tags=e2e -run '^$$' ./...
	$(MAKE) lint
	$(MAKE) vuln

lint:
	toolchain=$$(go env GOVERSION) && GOTOOLCHAIN="$$toolchain" go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags=e2e ./...
	toolchain=$$(go env GOVERSION) && GOTOOLCHAIN="$$toolchain" go run github.com/kisielk/errcheck@$(ERRCHECK_VERSION) -mod=readonly -asserts -tags=e2e ./...
	toolchain=$$(go env GOVERSION) && original_flags="$$GOFLAGS" && \
	for tags in '' e2e; do \
		export GOTOOLCHAIN="$$toolchain" GOFLAGS="$$original_flags -mod=readonly -tags=$$tags"; \
		go run codeberg.org/polyfloyd/go-errorlint@$(ERRORLINT_VERSION) -errorf ./... && \
		go run golang.org/x/tools/go/analysis/passes/nilness/cmd/nilness@$(X_TOOLS_VERSION) ./... || exit 1; \
	done

vuln:
	toolchain=$$(go env GOVERSION) && CGO_ENABLED=0 GOTOOLCHAIN="$$toolchain" GOFLAGS="$${GOFLAGS} -mod=readonly" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./cmd/...

fuzz:
	go test -mod=readonly -run '^$$' -fuzz '^FuzzLoadServerConfig$$' -fuzztime="$(FUZZ_TIME)" -parallel="$(FUZZ_WORKERS)" ./internal/config

deb-agent: build
	sh packaging/debian/build-agent.sh "$$DEB_VERSION" bin/ocean-agent bin/ocean-network-agent bin/ocean-telemetry-relay bin
