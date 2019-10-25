package core

import "testing"

func TestTokens(t *testing.T) {
	tok, err := newToken()
	if err != nil {
		t.Fatal(err)
	}

	// convert the token to their respective client and database representations
	tokStr := tok.String()
	pbTok, err := tok.ToPB()
	if err != nil {
		t.Fatal(err)
	}

	// parse them back from their representations, and make sure they compare
	cliTok, err := parseToken(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	stoTok := tokenFromPB(pbTok)

	eq, err := cliTok.Equal(stoTok)
	if err != nil {
		t.Fatal(err)
	}
	if !eq {
		t.Error("want: tokens to be equal, got not equal")
	}

	eq, err = stoTok.Equal(cliTok)
	if err != nil {
		t.Fatal(err)
	}
	if !eq {
		t.Error("want: tokens to be equal, got not equal")
	}

	tok2, err := newToken()
	if err != nil {
		t.Fatal(err)
	}

	eq, err = tok2.Equal(tok)
	if err != nil {
		t.Fatal(err)
	}
	if eq {
		t.Error("want: tokens to not be equal, got equal")
	}

	eq, err = tok.Equal(tok2)
	if err != nil {
		t.Fatal(err)
	}
	if eq {
		t.Error("want: tokens to not be equal, got equal")
	}
}
