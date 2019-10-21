.PHONY: all build test lint proto

gopath=$(shell go env GOPATH)

all: proto build test lint

build:
	go build ./...

test:
	go test -v ./...

lint: $(gopath)/bin/gobin
	$(gopath)/bin/gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./...

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)

proto: proto/deci/corestate/v1beta1/storage.pb.go

proto/deci/corestate/v1beta1/storage.pb.go: proto/deci/corestate/v1beta1/storage.proto
	protoc -I proto/deci/corestate/v1beta1 --go_out=proto/deci/corestate/v1beta1 storage.proto
