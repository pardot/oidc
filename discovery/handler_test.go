package discovery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
)

type mockKeysource struct {
	keys []jose.JSONWebKey
}

func (m *mockKeysource) GetPublicKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	return m.keys, nil
}

func TestHandler(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	ks := &mockKeysource{
		keys: []jose.JSONWebKey{
			{
				Key:       key.Public(),
				KeyID:     "testkey",
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}

	h := NewHandler(&ProviderMetadata{}, WithKeysource(ks, 1*time.Nanosecond))
	ts := httptest.NewServer(h)

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to get discovery info: %v", err)
	}
	gotpm := &ProviderMetadata{}
	err = json.NewDecoder(res.Body).Decode(gotpm)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("failed decoding metadata response: %v", err)
	}

	if gotpm.JWKSURI != "/.well-known/openid-configuration/jwks.json" {
		t.Errorf("want jwks URI %s, got %s", " /.well-known/openid-configuration/jwks.json", gotpm.JWKSURI)
	}

	res, err = http.Get(ts.URL + "/keys.json")
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}
	gotks := &jose.JSONWebKeySet{}
	err = json.NewDecoder(res.Body).Decode(gotks)
	_ = res.Body.Close()
	if err != nil {
		t.Fatalf("failed decoding keys response: %v", err)
	}

}
