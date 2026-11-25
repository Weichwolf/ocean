.PHONY: build check lint deb-agent

DEB_VERSION ?= 0.1.0~dev12
export DEB_VERSION

STATICCHECK_VERSION := v0.8.2
ERRCHECK_VERSION := v1.30.0

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o bin/ ./cmd/...

check:
	formatter=$$(go env GOROOT)/bin/gofmt && files=$$("$$formatter" -l cmd internal tests/e2e) && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }
	go vet -mod=readonly ./...
	go vet -mod=readonly -tags=e2e ./...
	go test -mod=readonly -race -count=1 ./...
	go test -mod=readonly -tags=e2e -run '^$$' ./...
	$(MAKE) lint

lint:
	toolchain=$$(go env GOVERSION) && GOTOOLCHAIN="$$toolchain" go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags=e2e ./...
	toolchain=$$(go env GOVERSION) && GOTOOLCHAIN="$$toolchain" go run github.com/kisielk/errcheck@$(ERRCHECK_VERSION) -mod=readonly -asserts -tags=e2e ./...

deb-agent: build
	sh packaging/debian/build-agent.sh "$$DEB_VERSION" bin/ocean-agent bin/ocean-network-agent bin/ocean-telemetry-relay bin
