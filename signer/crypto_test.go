package signer

import (
	"testing"

	"crypto/rsa"

	"crypto/rand"

	"context"
)

func TestCryptoSigner(t *testing.T) {
	ctx := context.Background()

	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	kid := "somekey"

	s, err := NewFromCrypto(key, kid)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	jwt := []byte(`{"sub": "sub ject"}`)

	signed, err := s.Sign(ctx, jwt)
	if err != nil {
		t.Fatalf("error signing: %v", err)
	}

	pl, err := s.VerifySignature(ctx, string(signed))
	if err != nil {
		t.Fatalf("error verifying signed jwt: %v", err)
	}

	if string(pl) != string(jwt) {
		t.Fatalf("want: %s, got: %s", string(jwt), string(pl))
	}
}
