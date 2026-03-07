VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X github.com/yuyamorita/mcpgw/cmd.Version=$(VERSION)"

.PHONY: build test vet clean

build:
	go build $(LDFLAGS) -o mcpgw .

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

clean:
	rm -f mcpgw cover.out
