package core

import (
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
)

func TestTokens(t *testing.T) {
	sessID := mustGenerateID()

	utok, stok, err := newToken(sessID, tsAdd(ptypes.TimestampNow(), 1*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// get what we send to the user
	utokstr, err := marshalToken(utok)
	if err != nil {
		t.Fatal(err)
	}

	// parse it back, maje sure they compare
	gotTok, err := unmarshalToken(utokstr)
	if err != nil {
		t.Fatal(err)
	}

	eq, err := tokensMatch(gotTok, stok)
	if err != nil {
		t.Fatal(err)
	}
	if !eq {
		t.Error("want: tokens to be equal, got not equal")
	}

	utok2, _, err := newToken(sessID, tsAdd(ptypes.TimestampNow(), 1*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	eq, err = tokensMatch(utok2, stok)
	if err != nil {
		t.Fatal(err)
	}
	if eq {
		t.Error("want: tokens to not be equal, got equal")
	}
}

func TestUnmarshalToken(t *testing.T) {
	encodedURLToken := "ChZXb2ozLXFJS0xEbzg5aDlaYXNaTmF3EjAezFlLpPCa5dMEOTNT0rpUnQUQrFZnKxV4AMvV2UzI7HXlLSSem-PVW-68oJDOA08"
	encodedStdToken := "ChZXb2ozLXFJS0xEbzg5aDlaYXNaTmF3EjAezFlLpPCa5dMEOTNT0rpUnQUQrFZnKxV4AMvV2UzI7HXlLSSem+PVW+68oJDOA08"

	urlToken, err := unmarshalToken(encodedURLToken)
	if err != nil {
		t.Fatal(err)
	}

	stdToken, err := unmarshalToken(encodedStdToken)
	if err != nil {
		t.Fatal(err)
	}

	if !proto.Equal(urlToken, stdToken) {
		t.Error("want: url encoded and std encoded tokens to be equal, got not equal")
	}
}
