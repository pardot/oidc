package discovery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
)

type mockKeysource struct {
	keys []jose.JSONWebKey
}

func (m *mockKeysource) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{Keys: m.keys}, nil
}

func TestDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	m := http.NewServeMux()
	ts := httptest.NewServer(m)

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

	kh := NewKeysHandler(ks, 1*time.Nanosecond)
	m.Handle("/jwks.json", kh)

	pm := &ProviderMetadata{
		Issuer:                ts.URL,
		JWKSURI:               ts.URL + "/jwks.json",
		AuthorizationEndpoint: "/auth",
		TokenEndpoint:         "/token",
	}

	ch, err := NewConfigurationHandler(pm, WithCoreDefaults())
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}
	m.Handle(oidcwk, ch)

	cli, err := NewClient(ctx, ts.URL)
	if err != nil {
		t.Fatalf("failed to create discovery client: %v", err)
	}

	_, err = cli.GetKey(ctx, "testkey")
	if err != nil {
		t.Errorf("wanted no error getting testkey, got: %v", err)
	}

	_, err = cli.GetKey(ctx, "badkey")
	if err == nil {
		t.Errorf("wanted error getting non-existent key, but got none")
	}
}
