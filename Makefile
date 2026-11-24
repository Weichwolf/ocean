.PHONY: build check

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o bin/ ./cmd/...

check:
	formatter=$$(go env GOROOT)/bin/gofmt && files=$$("$$formatter" -l cmd internal) && test -z "$$files" || { printf '%s\n' "$$files"; exit 1; }
	go vet -mod=readonly ./...
	go test -mod=readonly -race -count=1 ./...
