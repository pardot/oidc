.PHONY = all build test proto

all: build test

build:
	go build ./...

test:
	go test ./...

proto: internal/serializedpb/deciserialized.pb.go

internal/serializedpb/deciserialized.pb.go: proto/deciserialized.proto
	protoc -I proto --go_out=internal/serializedpb deciserialized.proto
