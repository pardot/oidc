.PHONY = all build test proto gobin

gopath=$(shell go env GOPATH)

all: proto build test lint

build:
	go build ./oidcserver/... ./signer/...

test:
	go test ./oidcserver/... ./signer/...

lint: $(gopath)/bin/gobin
	gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./oidcserver/... ./signer/...

proto: internal/serializedpb/deciserialized.pb.go proto/deci/storage/v1beta1/storage.pb.go

internal/serializedpb/deciserialized.pb.go: proto/deciserialized.proto
	protoc -I proto --go_out=internal/serializedpb deciserialized.proto

proto/deci/storage/v1beta1/storage.pb.go: proto/deci/storage/v1beta1/storage.proto
	protoc -I proto/deci/storage/v1beta1 --go_out=proto/deci/storage/v1beta1 storage.proto

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)