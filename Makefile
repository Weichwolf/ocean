.PHONY: build check deb-agent

DEB_VERSION ?= 0.1.0~dev12
export DEB_VERSION

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o bin/ ./cmd/...

check:
	formatter=$$(go env GOROOT)/bin/gofmt && files=$$("$$formatter" -l cmd internal) && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }
	go vet -mod=readonly ./...
	go test -mod=readonly -race -count=1 ./...

deb-agent: build
	sh packaging/debian/build-agent.sh "$$DEB_VERSION" bin/ocean-agent bin/ocean-network-agent bin/ocean-telemetry-relay bin
