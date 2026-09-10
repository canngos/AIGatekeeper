MODULE   := github.com/canngos/aigatekeeper
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
BIN      := bin/aigatekeeper

.PHONY: all build build-noui ui test test-ui lint fmt docker clean

all: build

## build: build the web UI, then the static Go binary with the UI embedded
build: ui
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/aigatekeeper

## build-noui: build the Go binary without rebuilding the web UI
build-noui:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/aigatekeeper

## ui: install web dependencies and build the SPA into web/dist
ui:
	cd web && npm ci && npm run build

## test: run Go tests with the race detector
test:
	go test ./... -race -count=1

## test-docker: run Go tests inside a Linux container (for hosts where local
## binaries cannot execute, e.g. Windows with Smart App Control, or no cgo)
test-docker:
	docker run --rm -v "$(CURDIR):/src" -v aigk-gomod:/go/pkg/mod -v aigk-gocache:/root/.cache/go-build -w /src golang:1.27 go test ./... -race -count=1

## test-ui: run frontend tests
test-ui:
	cd web && npm run test -- --run

## lint: vet Go code and type-check the frontend
lint:
	go vet ./...
	cd web && npm run lint && npm run typecheck

fmt:
	gofmt -l -w .

## docker: build the container image
docker:
	docker build -f deploy/Dockerfile -t aigatekeeper:$(VERSION) .

clean:
	rm -rf bin web/dist/assets web/dist/index.html
