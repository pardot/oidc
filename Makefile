.PHONY: all build test lint proto

export PATH := $(shell pwd)/bin:$(PATH)

all: proto build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 run ./...

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh

proto: proto/core/v1/storage.pb.go

proto/core/v1/storage.pb.go: proto/core/v1/storage.proto
	protoc -I proto/core/v1 --go_out=proto/core/v1 storage.proto
