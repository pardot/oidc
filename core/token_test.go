package core

import (
	"testing"
	"time"

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
