.PHONY: all build test lint proto

gopath=$(shell go env GOPATH)

all: proto build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 run ./...

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh

proto: proto/core/v1beta1/storage.pb.go

proto/core/v1beta1/storage.pb.go: proto/core/v1beta1/storage.proto
	protoc -I proto/core/v1beta1 --go_out=proto/core/v1beta1 storage.proto
