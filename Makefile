.PHONY: all build test proto gobin packr

gopath=$(shell go env GOPATH)

all: proto packr build test lint

build:
	go build ./oidcserver/... ./signer/...

test:
	go test ./oidcserver/... ./signer/...

lint: $(gopath)/bin/gobin
	$(gopath)/bin/gobin -m -run github.com/golangci/golangci-lint/cmd/golangci-lint run ./oidcserver/... ./signer/...

packr: oidcserver/oidcserver-packr.go

oidcserver/oidcserver-packr.go: $(gopath)/bin/gobin oidcserver/web
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2 clean
	cd oidcserver && gobin -m -run github.com/gobuffalo/packr/v2/packr2

proto: proto/deci/storage/v1beta1/storage.pb.go

proto/deci/storage/v1beta1/storage.pb.go: proto/deci/storage/v1beta1/storage.proto
	protoc -I proto/deci/storage/v1beta1 --go_out=proto/deci/storage/v1beta1 storage.proto

$(gopath)/bin/gobin:
	(cd /tmp && GO111MODULE=on go get -u github.com/myitcv/gobin@latest)
