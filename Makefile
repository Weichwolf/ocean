.PHONY: build check lint security vuln fuzz deb-agent

DEB_VERSION ?= 0.1.0~dev12
export DEB_VERSION

STATICCHECK_VERSION := v0.8.2
ERRCHECK_VERSION := v1.30.0
GOVULNCHECK_VERSION := v1.10.0
ERRORLINT_VERSION := v1.9.1
X_TOOLS_VERSION := v0.53.0
GOSEC_VERSION := v2.30.0
GOSEC_RULES := G106,G108,G109,G110,G111,G112,G113,G114,G116,G119,G120,G121,G122,G123,G124,G125,G201,G202,G203,G303,G305,G306,G307,G401,G402,G403,G404,G405,G406,G408,G505,G602,G710
FUZZ_TIME ?= 10s
FUZZ_WORKERS ?= 2

GO_BUILD = CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false

build:
	mkdir -p bin
	$(GO_BUILD) -o bin/ ./cmd/...

check:
	formatter=$$(go env GOROOT)/bin/gofmt && files=$$("$$formatter" -l cmd internal tests tools/lint) && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }
	go mod tidy -diff
	go mod verify
	go -C tools/lint mod tidy -diff
	go -C tools/lint mod verify
	go -C tools/lint test -mod=readonly ./...
	out=$$(mktemp -d) && trap 'rm -rf -- "$$out"' 0 && $(GO_BUILD) -o "$$out/" ./cmd/...
	go vet -mod=readonly ./...
	go vet -mod=readonly -tags=e2e ./...
	go test -mod=readonly -race -shuffle=on -count=1 ./...
	go test -mod=readonly -tags=e2e -count=1 -run '^TestAcceptanceMatrix$$' ./...
	$(MAKE) lint
	$(MAKE) security
	$(MAKE) vuln

lint:
	set -e; toolchain=$$(go env GOVERSION); export GOTOOLCHAIN="$$toolchain"; original_flags="$$GOFLAGS"; \
	out=$$(mktemp -d); trap 'rm -rf -- "$$out"' 0; \
	GOWORK=off go -C tools/lint build -mod=readonly -o "$$out/discardederrors" .; \
	for tags in '' e2e; do \
		export GOFLAGS="$$original_flags -mod=readonly -tags=$$tags"; \
		go vet -vettool="$$out/discardederrors" ./...; \
		go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags=$$tags ./...; \
		go run github.com/kisielk/errcheck@$(ERRCHECK_VERSION) -mod=readonly -asserts -tags=$$tags ./...; \
		go run codeberg.org/polyfloyd/go-errorlint@$(ERRORLINT_VERSION) -errorf ./...; \
		go run golang.org/x/tools/go/analysis/passes/nilness/cmd/nilness@$(X_TOOLS_VERSION) ./...; \
		GOWORK=off go tool -modfile=tools/lint/go.mod bodyclose ./...; \
	done

security:
	toolchain=$$(go env GOVERSION) && CGO_ENABLED=0 GOSEC_AI_PROVIDER= GOTOOLCHAIN="$$toolchain" GOFLAGS="$${GOFLAGS} -mod=readonly" \
		go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -terse -include=$(GOSEC_RULES) ./cmd/... ./internal/...

vuln:
	toolchain=$$(go env GOVERSION) && CGO_ENABLED=0 GOTOOLCHAIN="$$toolchain" GOFLAGS="$${GOFLAGS} -mod=readonly" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./cmd/...

fuzz:
	go test -mod=readonly -run '^$$' -fuzz '^FuzzLoadServerConfig$$' -fuzztime="$(FUZZ_TIME)" -parallel="$(FUZZ_WORKERS)" ./internal/config

deb-agent: build
	sh packaging/debian/build-agent.sh "$$DEB_VERSION" bin/ocean-agent bin/ocean-network-agent bin/ocean-telemetry-relay bin
