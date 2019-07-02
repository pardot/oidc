.PHONY = all build test proto gobin

gopath=$(shell go env GOPATH)

all: build test lint

build:
	go build ./oidcserver/... ./signer/...

test:
	go test ./oidcserver/... ./signer/...

lint: $(gopath)/bin/gobin
	gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./oidcserver/... ./signer/...

proto: internal/serializedpb/deciserialized.pb.go

internal/serializedpb/deciserialized.pb.go: proto/deciserialized.proto
	protoc -I proto --go_out=internal/serializedpb deciserialized.proto

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)