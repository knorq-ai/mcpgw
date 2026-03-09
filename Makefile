VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/knorq-ai/mcpgw/cmd.Version=$(VERSION)"

.PHONY: build build-go frontend test vet clean demo-build demo demo-clean

frontend:
	cd web && npm ci && npm run build

build: frontend
	go build $(LDFLAGS) -o mcpgw .

build-go:
	go build $(LDFLAGS) -o mcpgw .

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

clean:
	rm -f mcpgw cover.out

demo-build: build-go
	go build -o demo/server/demo-server ./demo/server

demo: demo-build
	@bash demo/run.sh

demo-clean:
	rm -f demo/server/demo-server demo/audit.jsonl
